// Copyright (c) RoochNetwork
// SPDX-License-Identifier: Apache-2.0

/// This module implements the session auth validator.
module rooch_framework::session_validator {

    use std::vector;
    use std::option;
    use moveos_std::tx_context;
    use moveos_std::hash;
    use rooch_framework::ed25519;
    use rooch_framework::auth_validator;
    use rooch_framework::session_key;

    friend rooch_framework::transaction_validator;

    /// there defines auth validator id for each auth validator
    const SESSION_VALIDATOR_ID: u64 = 0;

    const SIGNATURE_SCHEME_ED25519: u8 = 0;


    struct SessionValidator has store, drop {}

    public fun auth_validator_id(): u64 {
        SESSION_VALIDATOR_ID
    }

    /// Validate the authenticator payload, return public key and signature
    fun validate_authenticator_payload(authenticator_payload: &vector<u8>): (vector<u8>, vector<u8>) {
        let scheme = vector::borrow(authenticator_payload, 0);
        assert!(*scheme == SIGNATURE_SCHEME_ED25519, auth_validator::error_validate_invalid_authenticator());

        let sign = vector::empty<u8>();
        let i = 1;
        let signature_position = ed25519::signature_length() + 1;
        while (i < signature_position) {
            let value = vector::borrow(authenticator_payload, i);
            vector::push_back(&mut sign, *value);
            i = i + 1;
        };

        let public_key = vector::empty<u8>();
        let i = 1 + ed25519::signature_length();
        let public_key_position = 1 + ed25519::signature_length() + ed25519::public_key_length();
        while (i < public_key_position) {
            let value = vector::borrow(authenticator_payload, i);
            vector::push_back(&mut public_key, *value);
            i = i + 1;
        };
        (sign, public_key)
    }

    /// Get the authentication key of the given public key.
    fun public_key_to_authentication_key(signature_scheme: u8, public_key: vector<u8>): vector<u8> {
        let bytes = vector::singleton(signature_scheme);
        vector::append(&mut bytes, public_key);
        hash::blake2b256(&bytes)
    }


    // validate the signature of the authenticator payload and return auth key
    fun validate_signature(authenticator_payload: &vector<u8>, tx_hash: &vector<u8>) : vector<u8> {
        let (signature, public_key) = validate_authenticator_payload(authenticator_payload);
        assert!(
            ed25519::verify(
                &signature,
                &public_key,
                tx_hash
            ),
            auth_validator::error_validate_invalid_authenticator()
        );
        public_key_to_authentication_key(SIGNATURE_SCHEME_ED25519, public_key)
    }

    public(friend) fun validate(authenticator_payload: vector<u8>) :vector<u8> {
        
        let sender_addr = tx_context::sender();
        assert!(session_key::has_session_key(sender_addr), auth_validator::error_validate_invalid_account_auth_key());
        
        let tx_hash = tx_context::tx_hash();
        let auth_key = validate_signature(&authenticator_payload, &tx_hash);

        let session_key_option = session_key::get_session_key(sender_addr, auth_key);
        assert!(option::is_some(&session_key_option), auth_validator::error_validate_invalid_account_auth_key());
        
        let session_key = option::extract(&mut session_key_option);
        assert!(!session_key::is_expired(&session_key), auth_validator::error_validate_session_is_expired());
        
        assert!(session_key::in_session_scope(&session_key), auth_validator::error_validate_function_call_beyond_session_scope());
        auth_key
    }

    #[test]
    fun test_validate_signature_success() {
        let tx_hash = x"14563b3603703b02c89f15dbaa67f8f0e939c46c152d6700e515459d48fbec31";
        let authenticator_payload = x"0004746573741b68747470733a3a2f2f746573742e726f6f63682e6e6574776f726b204ad70a371cff3b7b5c9fc08d7c33f2081d3663d7e37a6461917a106078fe5304010000000000000000000000000000000000000000000000000000000000000003012a012a000000000000000000000000000000006400000000000000";

        validate_signature(&authenticator_payload, &tx_hash);
    }

    // #[test]
    // fun test_validate_signature_fail() {
    //     let tx_hash = x"5415b18de0b880bb2af5dfe1ee27fd19ae8a0c99b5328e8b4b44f4c86cc7176a";
    //     let authenticator_payload = x"007e5b0c1da7d2bed7c2497b7c7c46b1a485883029a3bb1479493688ad347bcafa2bd82c6fd9bb2515f9e0c697f621ac0a28fb9f8c0e565d5b6d4e20bf18ce86621a18426974636f696e205369676e6564204d6573736167653a0ae2a201526f6f6368205472616e73616374696f6e3a0a57656c636f6d6520746f20726f6f63685f746573740a596f752077696c6c20617574686f72697a652073657373696f6e3a0a53636f70653a0a3078663962313065366337363066316361646365393563363634623361336561643363393835626265396436336264353161396266313736303738356432366131623a3a2a3a3a2a0a54696d654f75743a313030300a21031a446b6ac064acb14687764871dad6c08186a788248d585b3cce69231b48d1382a62633171333234356e706d3430346874667a76756c783676347736356d61717a7536617474716c336677";

    //     validate_signature(&authenticator_payload, &tx_hash);
    // }
}
