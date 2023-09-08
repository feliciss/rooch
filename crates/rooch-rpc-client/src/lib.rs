// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use ethers::types::{H160, U256};
use jsonrpsee::{
    core::RpcResult,
    http_client::{HttpClient, HttpClientBuilder},
};
use moveos_types::{
    access_path::AccessPath,
    function_return_value::FunctionResult,
    h256::H256,
    module_binding::MoveFunctionCaller,
    state::{MoveStructType, State},
    transaction::FunctionCall,
    tx_context::TxContext,
};
use rooch_rpc_api::api::eth_api::EthAPIClient;
use rooch_rpc_api::api::rooch_api::RoochAPIClient;
use rooch_rpc_api::{
    api::eth_api::TransactionType,
    jsonrpc_types::{
        bytes::Bytes,
        eth::{
            ethereum_types::block::{Block, BlockNumber},
            CallRequest, EthFeeHistory, Transaction, TransactionReceipt,
        },
        AccessPathView, AnnotatedFunctionResultView, AnnotatedStateView, EventPageView,
        ExecuteTransactionResponseView, H160View, H256View, ListAnnotatedStatesPageView,
        ListStatesPageView, StateView, StrView, StructTagView, TransactionView, U256View,
    },
};
use rooch_types::{
    account::Account,
    address::{EthereumAddress, RoochAddress},
    transaction::{
        ethereum::{EthereumTransaction, EthereumTransactionData},
        rooch::RoochTransaction,
    },
};
use std::sync::Arc;
use std::time::Duration;
use tonic::async_trait;

pub mod client_config;
pub mod wallet_context;

pub struct ClientBuilder {
    request_timeout: Duration,
    max_concurrent_requests: usize,
    ws_url: Option<String>,
}

impl ClientBuilder {
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub fn max_concurrent_requests(mut self, max_concurrent_requests: usize) -> Self {
        self.max_concurrent_requests = max_concurrent_requests;
        self
    }

    pub fn ws_url(mut self, url: impl AsRef<str>) -> Self {
        self.ws_url = Some(url.as_ref().to_string());
        self
    }

    pub async fn build(self, http: impl AsRef<str>) -> Result<Client> {
        // TODO: add verison info

        let http_client = HttpClientBuilder::default()
            .max_request_body_size(2 << 30)
            .max_concurrent_requests(self.max_concurrent_requests)
            .request_timeout(self.request_timeout)
            .build(http)?;

        Ok(Client {
            rpc: Arc::new(RpcClient {
                http: http_client.clone(),
            }),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            max_concurrent_requests: 256,
            ws_url: None,
        }
    }
}

pub(crate) struct RpcClient {
    http: HttpClient,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC client. Http: {:?}", self.http)
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    rpc: Arc<RpcClient>,
}

// TODO: call args are uniformly defined in jsonrpc types?
// example execute_view_function get_events_by_event_handle
impl Client {
    pub async fn execute_tx(&self, tx: RoochTransaction) -> Result<ExecuteTransactionResponseView> {
        let tx_payload = bcs::to_bytes(&tx)?;
        self.rpc
            .http
            .execute_raw_transaction(tx_payload.into())
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn execute_view_function(
        &self,
        function_call: FunctionCall,
    ) -> Result<AnnotatedFunctionResultView> {
        self.rpc
            .http
            .execute_view_function(function_call.into())
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn get_states(&self, access_path: AccessPath) -> Result<Vec<Option<StateView>>> {
        Ok(self.rpc.http.get_states(access_path.into()).await?)
    }

    pub async fn get_annotated_states(
        &self,
        access_path: AccessPath,
    ) -> Result<Vec<Option<AnnotatedStateView>>> {
        Ok(self
            .rpc
            .http
            .get_annotated_states(access_path.into())
            .await?)
    }

    pub async fn get_transaction_by_hash(&self, hash: H256) -> Result<Option<TransactionView>> {
        Ok(self.rpc.http.get_transaction_by_hash(hash.into()).await?)
    }

    pub async fn get_transaction_by_index(
        &self,
        start: u64,
        limit: u64,
    ) -> Result<Vec<TransactionView>> {
        let s = self.rpc.http.get_transaction_by_index(start, limit).await?;
        Ok(s)
    }

    pub async fn get_sequence_number(&self, sender: RoochAddress) -> Result<u64> {
        Ok(self
            .get_states(AccessPath::resource(sender.into(), Account::struct_tag()))
            .await?
            .pop()
            .flatten()
            .map(|state_view| {
                let state = State::from(state_view);
                state.as_move_state::<Account>()
            })
            .transpose()?
            .map_or(0, |account| account.sequence_number))
    }

    pub async fn get_events_by_event_handle(
        &self,
        event_handle_type: StructTagView,
        cursor: Option<u64>,
        limit: Option<u64>,
    ) -> Result<EventPageView> {
        let s = self
            .rpc
            .http
            .get_events_by_event_handle(event_handle_type, cursor, limit)
            .await?;
        Ok(s)
    }

    pub async fn list_states(
        &self,
        access_path: AccessPathView,
        cursor: Option<StrView<Vec<u8>>>,
        limit: Option<usize>,
    ) -> Result<ListStatesPageView> {
        Ok(self
            .rpc
            .http
            .list_states(access_path, cursor, limit)
            .await?)
    }

    pub async fn list_annotated_states(
        &self,
        access_path: AccessPathView,
        cursor: Option<StrView<Vec<u8>>>,
        limit: Option<usize>,
    ) -> Result<ListAnnotatedStatesPageView> {
        Ok(self
            .rpc
            .http
            .list_annotated_states(access_path, cursor, limit)
            .await?)
    }

    pub async fn net_version(&self) -> Result<String> {
        Ok(self.rpc.http.net_version().await?)
    }

    pub async fn get_chain_id(&self) -> Result<String> {
        Ok(self.rpc.http.get_chain_id().await?)
    }

    pub async fn get_block_number(&self) -> Result<String> {
        Ok(self.rpc.http.get_block_number().await?)
    }

    pub async fn get_block_by_number(
        &self,
        num: BlockNumber,
        include_txs: bool,
    ) -> Result<Block<TransactionType>> {
        Ok(self.rpc.http.get_block_by_number(num, include_txs).await?)
    }

    pub async fn get_balance(&self, address: H160, num: Option<BlockNumber>) -> Result<U256> {
        let response = self.rpc.http.get_balance(address.into(), num).await?;
        Result::Ok(response.into())
    }

    pub async fn estimate_gas(
        &self,
        request: CallRequest,
        num: Option<BlockNumber>,
    ) -> Result<U256> {
        let response = self.rpc.http.estimate_gas(request, num).await?;
        Result::Ok(response.into())
    }

    pub async fn fee_history(
        &self,
        block_count: U256,
        newest_block: BlockNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<EthFeeHistory> {
        Ok(self
            .rpc
            .http
            .fee_history(block_count.into(), newest_block, reward_percentiles)
            .await?)
    }

    pub async fn gas_price(&self) -> Result<U256> {
        let response = self.rpc.http.gas_price().await?;
        Result::Ok(response.into())
    }

    pub async fn transaction_count(&self, address: H160, num: Option<BlockNumber>) -> Result<U256> {
        let response = self.rpc.http.transaction_count(address.into(), num).await?;
        Result::Ok(response.into())
    }

    pub async fn send_raw_transaction(&self, bytes: Bytes) -> Result<H256> {
        let response = EthAPIClient::send_raw_transaction(&self.rpc.http, bytes).await?;
        Result::Ok(response.into())
    }

    pub async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        Ok(self.rpc.http.transaction_receipt(hash.into()).await?)
    }

    pub async fn transaction_by_hash_and_index(
        &self,
        hash: H256,
        index: u64,
    ) -> Result<Option<Transaction>> {
        Ok(self
            .rpc
            .http
            .transaction_by_hash_and_index(hash.into(), index)
            .await?)
    }

    pub async fn block_by_hash(
        &self,
        hash: H256,
        include_txs: bool,
    ) -> Result<Block<TransactionType>> {
        Ok(self
            .rpc
            .http
            .block_by_hash(hash.into(), include_txs)
            .await?)
    }
}

impl MoveFunctionCaller for Client {
    fn call_function(
        &self,
        _ctx: &TxContext,
        function_call: FunctionCall,
    ) -> Result<FunctionResult> {
        let function_result =
            futures::executor::block_on(self.execute_view_function(function_call))?;
        function_result.try_into()
    }
}
