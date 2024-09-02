// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

use crate::addresses::ROOCH_FRAMEWORK_ADDRESS;
use move_core_types::{
    account_address::AccountAddress, ident_str, identifier::IdentStr, u256::U256,
};
use moveos_types::state::MoveStructType;

pub const MODULE_NAME: &IdentStr = ident_str!("gas_coin");
pub const DECIMALS: u8 = 18;

#[derive(Debug, Clone)]
pub struct RGas;

impl MoveStructType for RGas {
    const ADDRESS: AccountAddress = ROOCH_FRAMEWORK_ADDRESS;
    const MODULE_NAME: &'static IdentStr = MODULE_NAME;
    const STRUCT_NAME: &'static IdentStr = ident_str!("RGas");
}

impl RGas {
    pub fn scaling<I: Into<U256>>(value: I) -> U256 {
        U256::from(10u64.pow(DECIMALS as u32)) * value.into()
    }
}
