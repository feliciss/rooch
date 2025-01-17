// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

use super::messages::{
    AnnotatedStatesMessage, ExecuteViewFunctionMessage, GetAnnotatedEventsByEventHandleMessage,
    GetAnnotatedStatesByStateMessage, GetEventsByEventHandleMessage, ResolveMessage, StatesMessage,
    ValidateTransactionMessage,
};
use crate::actor::messages::{
    GetEventsByEventIDsMessage, GetTxExecutionInfosByHashMessage, ListAnnotatedStatesMessage,
    ListStatesMessage,
};
use anyhow::Result;
use async_trait::async_trait;
use coerce::actor::{context::ActorContext, message::Handler, Actor};
use itertools::Itertools;
use move_binary_format::errors::{Location, PartialVMError, VMResult};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::ModuleId;
use move_core_types::resolver::ModuleResolver;
use move_core_types::value::MoveValue;
use move_core_types::vm_status::{StatusCode, VMStatus};
use move_resource_viewer::MoveValueAnnotator;
use moveos::gas::table::{initial_cost_schedule, MoveOSGasMeter};
use moveos::moveos::{GasPaymentAccount, MoveOS};
use moveos::vm::vm_status_explainer::explain_vm_status;
use moveos_store::transaction_store::TransactionStore;
use moveos_types::function_return_value::AnnotatedFunctionResult;
use moveos_types::function_return_value::AnnotatedFunctionReturnValue;
use moveos_types::module_binding::MoveFunctionCaller;
use moveos_types::move_types::FunctionId;
use moveos_types::moveos_std::event::EventHandle;
use moveos_types::moveos_std::event::{AnnotatedEvent, Event};
use moveos_types::moveos_std::tx_context::TxContext;
use moveos_types::state::{AnnotatedState, State};
use moveos_types::state_resolver::{AnnotatedStateReader, StateReader};
use moveos_types::transaction::VerifiedMoveAction;
use moveos_types::transaction::VerifiedMoveOSTransaction;
use moveos_types::transaction::{FunctionCall, MoveAction};
use moveos_types::transaction::{MoveOSTransaction, TransactionExecutionInfo};
use moveos_verifier::metadata::load_module_metadata;
use parking_lot::RwLock;
use rooch_store::RoochStore;
use rooch_types::address::MultiChainAddress;
use rooch_types::framework::address_mapping::AddressMapping;
use rooch_types::framework::auth_validator::AuthValidatorCaller;
use rooch_types::framework::auth_validator::TxValidateResult;
use rooch_types::framework::transaction_validator::TransactionValidator;
use rooch_types::transaction::AbstractTransaction;
use rooch_types::transaction::AuthenticatorInfo;
use std::ops::Deref;
use std::sync::Arc;

pub struct ReaderExecutorActor {
    moveos: Arc<RwLock<MoveOS>>,
    rooch_store: RoochStore,
}

type ValidateAuthenticatorResult = Result<
    (
        TxValidateResult,
        Option<MultiChainAddress>,
        Vec<FunctionCall>,
        Vec<FunctionCall>,
    ),
    VMStatus,
>;

impl ReaderExecutorActor {
    pub fn new(moveos: Arc<RwLock<MoveOS>>, rooch_store: RoochStore) -> Result<Self> {
        Ok(Self {
            moveos,
            rooch_store,
        })
    }

    pub fn resolve_or_generate(
        &self,
        multi_chain_address_sender: MultiChainAddress,
    ) -> Result<AccountAddress> {
        let moveos = self.moveos.read();
        let resolved_sender = {
            let address_mapping = moveos.as_module_binding::<AddressMapping>();
            address_mapping.resolve_or_generate(multi_chain_address_sender)?
        };

        Ok(resolved_sender)
    }

    pub fn validate<T: AbstractTransaction>(&self, tx: T) -> Result<VerifiedMoveOSTransaction> {
        let multi_chain_address_sender = tx.sender();

        let resolved_sender = self.resolve_or_generate(multi_chain_address_sender.clone())?;
        let authenticator = tx.authenticator_info()?;

        let mut moveos_tx = tx.construct_moveos_transaction(resolved_sender)?;

        let vm_result = self.validate_authenticator(&moveos_tx.ctx, authenticator)?;

        let can_pay_gas = self.validate_gas_function(&moveos_tx)?;

        let mut pay_by_module_account = false;
        let mut gas_payment_account = moveos_tx.ctx.sender;

        if let Some(pay_gas) = can_pay_gas {
            if pay_gas {
                let account_balance = self.get_account_balance(&moveos_tx)?;
                let module_account = {
                    match &moveos_tx.action {
                        MoveAction::Function(call) => Some(*call.function_id.module_id.address()),
                        _ => None,
                    }
                };

                let gas_payment_address = {
                    if account_balance >= moveos_tx.ctx.max_gas_amount as u128 {
                        pay_by_module_account = true;
                        module_account.unwrap()
                    } else {
                        moveos_tx.ctx.sender
                    }
                };

                gas_payment_account = gas_payment_address;
            }
        }

        moveos_tx
            .ctx
            .add(GasPaymentAccount {
                account: gas_payment_account,
                pay_gas_by_module_account: pay_by_module_account,
            })
            .expect("adding GasPaymentAccount to tx context failed.");

        let moveos = self.moveos.read();
        match vm_result {
            Ok((
                tx_validate_result,
                multi_chain_address,
                pre_execute_functions,
                post_execute_functions,
            )) => {
                // Add the original multichain address to the context
                moveos_tx
                    .ctx
                    .add(multi_chain_address.unwrap_or(multi_chain_address_sender))
                    .expect("add sender to context failed");

                // Add the tx_validate_result to the context
                moveos_tx
                    .ctx
                    .add(tx_validate_result)
                    .expect("add tx_validate_result failed");

                moveos_tx.append_pre_execute_functions(pre_execute_functions);
                moveos_tx.append_post_execute_functions(post_execute_functions);
                Ok(moveos.verify(moveos_tx)?)
            }
            Err(e) => {
                let status_view = explain_vm_status(moveos.moveos_resolver(), e.clone())?;
                log::warn!(
                    "transaction validate vm error, tx_hash: {}, error:{:?}",
                    moveos_tx.ctx.tx_hash(),
                    status_view,
                );
                //TODO how to return the vm status to rpc client.
                Err(e.into())
            }
        }
    }

    pub fn validate_authenticator(
        &self,
        ctx: &TxContext,
        authenticator: AuthenticatorInfo,
    ) -> Result<ValidateAuthenticatorResult> {
        let moveos = self.moveos.read();
        let tx_validator = moveos.as_module_binding::<TransactionValidator>();
        let tx_validate_function_result = tx_validator
            .validate(ctx, authenticator.clone())?
            .into_result();

        let vm_result = match tx_validate_function_result {
            Ok(tx_validate_result) => {
                let auth_validator_option = tx_validate_result.auth_validator();
                match auth_validator_option {
                    Some(auth_validator) => {
                        let auth_validator_caller =
                            AuthValidatorCaller::new(moveos.deref(), auth_validator);
                        let auth_validator_function_result = auth_validator_caller
                            .validate(ctx, authenticator.authenticator.payload)?
                            .into_result();
                        match auth_validator_function_result {
                            Ok(multi_chain_address) => {
                                // pre_execute_function: AuthValidator
                                let pre_execute_functions =
                                    vec![auth_validator_caller.pre_execute_function_call()];
                                // post_execute_function: AuthValidator
                                let post_execute_functions =
                                    vec![auth_validator_caller.post_execute_function_call()];
                                Ok((
                                    tx_validate_result,
                                    multi_chain_address,
                                    pre_execute_functions,
                                    post_execute_functions,
                                ))
                            }
                            Err(vm_status) => Err(vm_status),
                        }
                    }
                    None => {
                        let pre_execute_functions = vec![];
                        let post_execute_functions = vec![];
                        Ok((
                            tx_validate_result,
                            None,
                            pre_execute_functions,
                            post_execute_functions,
                        ))
                    }
                }
            }
            Err(vm_status) => Err(vm_status),
        };
        Ok(vm_result)
    }

    pub fn validate_gas_function(&self, tx: &MoveOSTransaction) -> VMResult<Option<bool>> {
        let MoveOSTransaction { ctx, .. } = tx;

        let cost_table = initial_cost_schedule();
        let mut gas_meter = MoveOSGasMeter::new(cost_table, ctx.max_gas_amount);
        gas_meter.set_metering(false);

        let moveos = self.moveos.read();
        let verified_moveos_action = moveos.verify(tx.clone())?;
        let verified_action = verified_moveos_action.action;

        match verified_action {
            VerifiedMoveAction::Function { call } => {
                let module_id = &call.function_id.module_id;
                let loaded_module_bytes_result = moveos.moveos_resolver().get_module(module_id);
                let loaded_module_bytes = match loaded_module_bytes_result {
                    Ok(loaded_module_bytes_opt) => match loaded_module_bytes_opt {
                        None => {
                            return Err(PartialVMError::new(StatusCode::RESOURCE_DOES_NOT_EXIST)
                                .with_message(
                                    "The name of the gas_validate_function does not exist."
                                        .to_string(),
                                )
                                .finish(Location::Module(module_id.clone())));
                        }
                        Some(module_bytes) => module_bytes,
                    },
                    Err(error) => {
                        return Err(PartialVMError::new(StatusCode::RESOURCE_DOES_NOT_EXIST)
                            .with_message(format!(
                                "Load module data from module_id {:} was failed {:}.",
                                module_id.clone(),
                                error
                            ))
                            .finish(Location::Module(module_id.clone())));
                    }
                };

                let module_metadata = load_module_metadata(module_id, Ok(loaded_module_bytes))?;
                let gas_free_function_info = {
                    match module_metadata {
                        None => None,
                        Some(runtime_metadata) => Some(runtime_metadata.gas_free_function_map),
                    }
                };

                let called_function_name = call.function_id.function_name.to_string();
                match gas_free_function_info {
                    None => Ok(None),
                    Some(gas_func_info) => {
                        let full_called_function = format!(
                            "0x{}::{}::{}",
                            call.function_id.module_id.address().to_hex(),
                            call.function_id.module_id.name(),
                            called_function_name
                        );
                        let gas_func_info_opt = gas_func_info.get(&full_called_function);

                        if let Some(gas_func_info) = gas_func_info_opt {
                            let gas_validate_func_name = gas_func_info.gas_validate.clone();

                            let split_function = gas_validate_func_name.split("::").collect_vec();
                            if split_function.len() != 3 {
                                return Err(PartialVMError::new(StatusCode::VM_EXTENSION_ERROR)
                                    .with_message(
                                        "The name of the gas_validate_function is incorrect."
                                            .to_string(),
                                    )
                                    .finish(Location::Module(call.clone().function_id.module_id)));
                            }
                            let real_gas_validate_func_name =
                                split_function.get(2).unwrap().to_string();

                            let gas_validate_func_call = FunctionCall::new(
                                FunctionId::new(
                                    call.function_id.module_id.clone(),
                                    Identifier::new(real_gas_validate_func_name).unwrap(),
                                ),
                                vec![],
                                vec![],
                            );

                            let function_execution_result = self
                                .moveos
                                .read()
                                .execute_view_function(gas_validate_func_call);

                            return if function_execution_result.vm_status == VMStatus::Executed {
                                let return_value = function_execution_result.return_values.unwrap();
                                if !return_value.is_empty() {
                                    let first_return_value = return_value.get(0).unwrap();
                                    Ok(Some(
                                        bcs::from_bytes::<bool>(first_return_value.value.as_slice())
                                            .expect(
                                                "the return value of gas validate function should be bool",
                                            ),
                                    ))
                                } else {
                                    return Err(PartialVMError::new(
                                        StatusCode::VM_EXTENSION_ERROR,
                                    )
                                    .with_message(
                                        "the return value of gas_validate_function is empty."
                                            .to_string(),
                                    )
                                    .finish(Location::Module(call.clone().function_id.module_id)));
                                }
                            } else {
                                Ok(None)
                            };
                        };

                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
    }

    pub fn get_account_balance(&self, tx: &MoveOSTransaction) -> VMResult<u128> {
        let MoveOSTransaction { ctx, .. } = tx;

        let cost_table = initial_cost_schedule();
        let mut gas_meter = MoveOSGasMeter::new(cost_table, ctx.max_gas_amount);
        gas_meter.set_metering(false);

        let moveos = self.moveos.read();
        let verified_moveos_action = moveos.verify(tx.clone())?;
        let verified_action = verified_moveos_action.action;

        match verified_action {
            VerifiedMoveAction::Function { call } => {
                let module_address = call.function_id.module_id.address();

                let gas_coin_module_id = ModuleId::new(
                    AccountAddress::from_hex_literal("0x3").unwrap(),
                    Identifier::from(IdentStr::new("gas_coin").unwrap()),
                );
                let gas_balance_func_call = FunctionCall::new(
                    FunctionId::new(gas_coin_module_id, Identifier::new("balance").unwrap()),
                    vec![],
                    vec![MoveValue::Address(*module_address)
                        .simple_serialize()
                        .unwrap()],
                );

                let function_execution_result = self
                    .moveos
                    .read()
                    .execute_view_function(gas_balance_func_call);

                if function_execution_result.vm_status == VMStatus::Executed {
                    let return_value = function_execution_result.return_values.unwrap();
                    let first_return_value = return_value.get(0).unwrap();

                    let balance = bcs::from_bytes::<move_core_types::u256::U256>(
                        first_return_value.value.as_slice(),
                    )
                    .expect("the return value of gas validate function should be u128");

                    Ok(balance.unchecked_as_u128())
                } else {
                    Ok(0)
                }
            }
            _ => Ok(0),
        }
    }

    pub fn get_rooch_store(&self) -> RoochStore {
        self.rooch_store.clone()
    }

    pub fn moveos(&self) -> Arc<RwLock<MoveOS>> {
        self.moveos.clone()
    }
}

impl Actor for ReaderExecutorActor {}

#[async_trait]
impl<T> Handler<ValidateTransactionMessage<T>> for ReaderExecutorActor
where
    T: 'static + AbstractTransaction + Send + Sync,
{
    async fn handle(
        &mut self,
        msg: ValidateTransactionMessage<T>,
        _ctx: &mut ActorContext,
    ) -> Result<VerifiedMoveOSTransaction> {
        self.validate(msg.tx)
    }
}

#[async_trait]
impl Handler<ExecuteViewFunctionMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: ExecuteViewFunctionMessage,
        _ctx: &mut ActorContext,
    ) -> Result<AnnotatedFunctionResult, anyhow::Error> {
        let moveos = self.moveos.read();
        let resoler = moveos.moveos_resolver();

        let function_result = moveos.execute_view_function(msg.call);
        Ok(AnnotatedFunctionResult {
            vm_status: function_result.vm_status,
            return_values: match function_result.return_values {
                Some(values) => Some(
                    values
                        .into_iter()
                        .map(|v| {
                            let decoded_value = resoler.view_value(&v.type_tag, &v.value)?;
                            Ok(AnnotatedFunctionReturnValue {
                                value: v,
                                decoded_value,
                            })
                        })
                        .collect::<Result<Vec<AnnotatedFunctionReturnValue>, anyhow::Error>>()?,
                ),
                None => None,
            },
        })
    }
}

#[async_trait]
impl Handler<ResolveMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: ResolveMessage,
        _ctx: &mut ActorContext,
    ) -> Result<AccountAddress, anyhow::Error> {
        self.resolve_or_generate(msg.address)
    }
}

#[async_trait]
impl Handler<StatesMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: StatesMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<Option<State>>, anyhow::Error> {
        let moveos = self.moveos.read();
        let statedb = moveos.moveos_resolver();
        statedb.get_states(msg.access_path)
    }
}

#[async_trait]
impl Handler<AnnotatedStatesMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: AnnotatedStatesMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<Option<AnnotatedState>>, anyhow::Error> {
        let moveos = self.moveos.read();
        let statedb = moveos.moveos_resolver();
        statedb.get_annotated_states(msg.access_path)
    }
}

#[async_trait]
impl Handler<ListStatesMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: ListStatesMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<(Vec<u8>, State)>, anyhow::Error> {
        let moveos = self.moveos.read();
        let statedb = moveos.moveos_resolver();
        statedb.list_states(msg.access_path, msg.cursor, msg.limit)
    }
}

#[async_trait]
impl Handler<ListAnnotatedStatesMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: ListAnnotatedStatesMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<(Vec<u8>, AnnotatedState)>, anyhow::Error> {
        let moveos = self.moveos.read();
        let statedb = moveos.moveos_resolver();
        statedb.list_annotated_states(msg.access_path, msg.cursor, msg.limit)
    }
}

#[async_trait]
impl Handler<GetAnnotatedEventsByEventHandleMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: GetAnnotatedEventsByEventHandleMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<AnnotatedEvent>> {
        let GetAnnotatedEventsByEventHandleMessage {
            event_handle_type,
            cursor,
            limit,
        } = msg;
        let moveos = self.moveos.read();
        let event_store = moveos.event_store();
        let resolver = moveos.moveos_resolver();

        let event_handle_id = EventHandle::derive_event_handle_id(&event_handle_type);
        let events = event_store.get_events_by_event_handle_id(&event_handle_id, cursor, limit)?;

        events
            .into_iter()
            .map(|event| {
                let event_move_value = MoveValueAnnotator::new(resolver)
                    .view_resource(&event_handle_type, event.event_data())?;
                Ok(AnnotatedEvent::new(event, event_move_value))
            })
            .collect::<Result<Vec<_>>>()
    }
}

#[async_trait]
impl Handler<GetEventsByEventHandleMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: GetEventsByEventHandleMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<Event>> {
        let GetEventsByEventHandleMessage {
            event_handle_type,
            cursor,
            limit,
        } = msg;
        let moveos = self.moveos.read();
        let event_store = moveos.event_store();

        let event_handle_id = EventHandle::derive_event_handle_id(&event_handle_type);
        event_store.get_events_by_event_handle_id(&event_handle_id, cursor, limit)
    }
}

#[async_trait]
impl Handler<GetEventsByEventIDsMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: GetEventsByEventIDsMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<Option<AnnotatedEvent>>> {
        let GetEventsByEventIDsMessage { event_ids } = msg;
        let moveos = self.moveos.read();
        let event_store = moveos.event_store();
        let resolver = moveos.moveos_resolver();

        event_store
            .multi_get_events(event_ids)?
            .into_iter()
            .map(|v| match v {
                Some(event) => {
                    let event_move_value = MoveValueAnnotator::new(resolver)
                        .view_resource(event.event_type(), event.event_data())?;
                    Ok(Some(AnnotatedEvent::new(event, event_move_value)))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<_>>>()
    }
}

#[async_trait]
impl Handler<GetTxExecutionInfosByHashMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: GetTxExecutionInfosByHashMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<Option<TransactionExecutionInfo>>> {
        let GetTxExecutionInfosByHashMessage { tx_hashes } = msg;
        self.moveos
            .read()
            .transaction_store()
            .multi_get_tx_execution_infos(tx_hashes)
    }
}

#[async_trait]
impl Handler<GetAnnotatedStatesByStateMessage> for ReaderExecutorActor {
    async fn handle(
        &mut self,
        msg: GetAnnotatedStatesByStateMessage,
        _ctx: &mut ActorContext,
    ) -> Result<Vec<AnnotatedState>> {
        let GetAnnotatedStatesByStateMessage { states } = msg;
        let moveos = self.moveos.read();
        let resolver = moveos.moveos_resolver();

        states
            .into_iter()
            .map(|state| {
                let annotate_state = MoveValueAnnotator::new(resolver)
                    .view_value(&state.value_type, &state.value)?;
                Ok(AnnotatedState::new(state, annotate_state))
            })
            .collect::<Result<Vec<_>>>()
    }
}
