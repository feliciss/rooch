// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

use super::{authenticator::Authenticator, AbstractTransaction, AuthenticatorInfo};
use crate::{address::EthereumAddress, error::RoochError};
use anyhow::Result;
use ethers::{
    types::Address,
    utils::rlp::{Decodable, Rlp},
};
use fastcrypto::{
    hash::Keccak256,
    secp256k1::recoverable::Secp256k1RecoverableSignature,
    traits::{RecoverableSignature, ToFromBytes},
};
use move_core_types::account_address::AccountAddress;
use moveos_types::{
    h256::H256,
    transaction::{MoveAction, MoveOSTransaction},
    tx_context::TxContext,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthereumTransaction(pub ethers::core::types::Transaction);

impl EthereumTransaction {
    //This function is just a demo, we should define the Ethereum calldata's MoveAction standard
    pub fn decode_calldata_to_action(&self) -> Result<MoveAction> {
        //Maybe we should use RLP to encode the MoveAction
        bcs::from_bytes(&self.0.input)
            .map_err(|e| anyhow::anyhow!("decode calldata to action failed: {}", e))
    }

    // Calculate the "recovery byte": The recovery ID (v) contains information about the network and the signature type.
    fn normalize_recovery_id(v: u64) -> u8 {
        match v {
            0 => 0,
            1 => 1,
            27 => 0,
            28 => 1,
            v if v >= 35 => ((v - 1) % 2) as _,
            _ => 4,
        }
    }

    pub fn into_signature(&self) -> Result<Secp256k1RecoverableSignature, RoochError> {
        let r = self.0.r;
        let s = self.0.s;
        let v = self.0.v.as_u64();

        let recovery_id = Self::normalize_recovery_id(v);

        // Convert `U256` values `r` and `s` to arrays of `u8`
        let mut r_bytes = [0u8; 32];
        r.to_big_endian(&mut r_bytes);
        let mut s_bytes = [0u8; 32];
        s.to_big_endian(&mut s_bytes);

        // Create a new array to store the 65-byte "rsv" signature
        let mut rsv_signature = [0u8; 65];
        rsv_signature[..32].copy_from_slice(&r_bytes);
        rsv_signature[32..64].copy_from_slice(&s_bytes);
        rsv_signature[64] = recovery_id;

        // Create the recoverable signature from the rsv signature
        let recoverable_signature: Secp256k1RecoverableSignature =
            <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&rsv_signature)
                .expect("Invalid signature");

        Ok(recoverable_signature)
    }

    pub fn into_address(&self) -> Result<Address, RoochError> {
        // Prepare the signed message (RLP encoding of the transaction)
        let message = self.tx_hash().to_fixed_bytes();
        let recoverable_signature = self.into_signature()?;
        // Recover with Keccak256 hash to a public key
        let public_key = recoverable_signature
            .recover_with_hash::<Keccak256>(&message)
            .expect("Failed to recover public key");
        let uncompressed_public_key_bytes = public_key.pubkey.serialize_uncompressed();
        // Ignore the first byte and take the last 64-bytes of the uncompressed pubkey
        let uncompressed_64 = uncompressed_public_key_bytes[1..].to_vec();
        // create a SHA3-256 object
        let mut hasher = Sha3_256::new();
        // write input message
        hasher.update(&uncompressed_64);
        // read hash digest
        let result = hasher.finalize();
        // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey
        let address_bytes = result[12..32].to_vec();
        let address = Address::from_slice(&address_bytes);

        Ok(address)
    }
}

impl AbstractTransaction for EthereumTransaction {
    fn transaction_type(&self) -> super::TransactionType {
        super::TransactionType::Ethereum
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let rlp = Rlp::new(bytes);
        let mut tx = ethers::core::types::Transaction::decode(&rlp)?;
        tx.recover_from_mut()?;
        Ok(Self(tx))
    }

    fn encode(&self) -> Vec<u8> {
        self.0.rlp().to_vec()
    }

    fn tx_hash(&self) -> H256 {
        self.0.hash()
    }

    fn authenticator_info(&self) -> Result<AuthenticatorInfo> {
        let chain_id = self.0.chain_id.ok_or(RoochError::InvalidChainID)?.as_u64();
        let authenticator = Authenticator::ethereum(self.into_signature()?);
        Ok(AuthenticatorInfo::new(chain_id, authenticator))
    }

    fn construct_moveos_transaction(
        self,
        resolved_sender: AccountAddress,
    ) -> Result<MoveOSTransaction> {
        let action = self.decode_calldata_to_action()?;
        let sequence_number = self.0.nonce.as_u64();
        let gas = self.0.gas.as_u64();
        let tx_ctx = TxContext::new(resolved_sender, sequence_number, gas, self.tx_hash());
        Ok(MoveOSTransaction::new(tx_ctx, action))
    }

    fn sender(&self) -> crate::address::MultiChainAddress {
        EthereumAddress(self.0.from).into()
    }
}
