// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use secp256k1::{Secp256k1, Message, SecretKey};
use ripemd::Ripemd160;
use sha2::{Sha256, Digest};
use std::sync::Once;
use tsarcore_native::txcodec::{
    txid_from_compact,
    wtxid_from_compact, 
    serialize_tx_compact,
    sighash_bip143_compact,
    validate_tx_p2wpkh_compact
};

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

fn hash160_bytes(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn create_opts<'py>(py: Python<'py>) -> Bound<'py, PyDict> {
    let opts = PyDict::new(py);
    opts.set_item("coinbase_maturity", 100).unwrap();
    opts.set_item("max_sigops_per_tx", 20000).unwrap();
    opts.set_item("max_tx_vsize", 100000).unwrap();
    opts.set_item("min_tx_vsize", 60).unwrap();
    opts.set_item("max_tx_weight", 400000).unwrap();
    opts.set_item("min_tx_weight", 240).unwrap();
    opts.set_item("max_tx_inputs", 1000).unwrap();
    opts.set_item("max_tx_outputs", 1000).unwrap();
    opts.set_item("enforce_low_s", true).unwrap();
    opts
}

fn to_tuple<'py>(py: Python<'py>, list: &Bound<'py, PyList>) -> Bound<'py, PyTuple> {
    let builtins = py.import("builtins").unwrap();
    builtins.call_method1("tuple", (list,)).unwrap().cast_into::<PyTuple>().unwrap()
}

#[test]
fn test_txcodec_basic() {
    init_python();
    Python::attach(|py| {
        let prev_txid = PyBytes::new(py, &[0u8; 32]);
        let script_sig = PyBytes::new(py, &[]);
        let witness = PyList::empty(py);
        witness.append(PyBytes::new(py, &[1, 2, 3])).unwrap();
        
        let tx_input_list = PyList::empty(py);
        tx_input_list.append(prev_txid).unwrap();
        tx_input_list.append(0u32).unwrap();
        tx_input_list.append(0xffffffffu32).unwrap();
        tx_input_list.append(script_sig).unwrap();
        tx_input_list.append(witness).unwrap();
        let tx_input = to_tuple(py, &tx_input_list);
        
        let inputs = PyList::empty(py);
        inputs.append(tx_input).unwrap();
        
        let spk = PyBytes::new(py, &[0x00, 0x14, 1, 2, 3]);
        let tx_output_list = PyList::empty(py);
        tx_output_list.append(50000u64).unwrap();
        tx_output_list.append(spk).unwrap();
        let tx_output = to_tuple(py, &tx_output_list);

        let outputs = PyList::empty(py);
        outputs.append(tx_output).unwrap();
        
        let tx_list = PyList::empty(py);
        tx_list.append(1i32).unwrap();
        tx_list.append(0u32).unwrap();
        tx_list.append(inputs).unwrap();
        tx_list.append(outputs).unwrap();
        tx_list.append(py.None()).unwrap();
        tx_list.append(false).unwrap();
        let tx = to_tuple(py, &tx_list);

        // Test serialize_tx_compact
        let raw_with_wit = serialize_tx_compact(py, tx.clone(), true).unwrap();
        assert!(raw_with_wit.as_bytes().len() > 0);
        
        let raw_no_wit = serialize_tx_compact(py, tx.clone(), false).unwrap();
        assert!(raw_with_wit.as_bytes().len() > raw_no_wit.as_bytes().len());

        // Test txid and wtxid
        let txid = txid_from_compact(py, tx.clone()).unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
        
        let wtxid = wtxid_from_compact(py, tx.clone()).unwrap();
        assert_eq!(wtxid.as_bytes().len(), 32);
        assert_ne!(txid.as_bytes(), wtxid.as_bytes()); // They should differ since witness is present
    });
}

#[test]
fn test_txcodec_validate_p2wpkh_success() {
    init_python();
    Python::attach(|py| {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0xcd; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_bytes = pk.serialize();
        
        let pubkey_hash = hash160_bytes(&pk_bytes);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&pubkey_hash);

        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xaa;
        let txid_py = PyBytes::new(py, &prev_txid);
        let spk_py = PyBytes::new(py, &spk);

        // Build utxo items
        let utxo_list = PyList::empty(py);
        utxo_list.append(txid_py.clone()).unwrap();
        utxo_list.append(0u32).unwrap();
        utxo_list.append(100000u64).unwrap();
        utxo_list.append(spk_py.clone()).unwrap();
        utxo_list.append(false).unwrap();
        utxo_list.append(100i64).unwrap();
        let utxo_items = PyList::empty(py);
        utxo_items.append(to_tuple(py, &utxo_list)).unwrap();

        // Empty TX for sighash
        let script_sig = PyBytes::new(py, &[]);
        let witness_empty = PyList::empty(py);
        let tx_input_empty_list = PyList::empty(py);
        tx_input_empty_list.append(txid_py.clone()).unwrap();
        tx_input_empty_list.append(0u32).unwrap();
        tx_input_empty_list.append(0xffffffffu32).unwrap();
        tx_input_empty_list.append(script_sig.clone()).unwrap();
        tx_input_empty_list.append(witness_empty).unwrap();
        let tx_input_empty = to_tuple(py, &tx_input_empty_list);
        let inputs_empty = PyList::empty(py);
        inputs_empty.append(tx_input_empty).unwrap();
        
        let tx_output_list = PyList::empty(py);
        tx_output_list.append(90000u64).unwrap();
        tx_output_list.append(spk_py.clone()).unwrap();
        let tx_output = to_tuple(py, &tx_output_list);
        let outputs = PyList::empty(py);
        outputs.append(tx_output).unwrap();

        let tx_empty_list = PyList::empty(py);
        tx_empty_list.append(1i32).unwrap();
        tx_empty_list.append(0u32).unwrap();
        tx_empty_list.append(inputs_empty).unwrap();
        tx_empty_list.append(outputs.clone()).unwrap();
        tx_empty_list.append(py.None()).unwrap();
        tx_empty_list.append(false).unwrap();
        let tx_empty = to_tuple(py, &tx_empty_list);

        // Sighash script code
        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.extend_from_slice(&pubkey_hash);
        script_code.extend_from_slice(&[0x88, 0xac]);

        let sighash = sighash_bip143_compact(py, tx_empty.clone(), 0, &script_code, 100000, 1).unwrap();
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(sighash.as_bytes());
        let msg = Message::from_digest(digest_arr);
        let sig = secp.sign_ecdsa(msg, &sk);
        let mut sig_der = sig.serialize_der().to_vec();
        sig_der.push(1); // SIGHASH_ALL
        
        let sig_py = PyBytes::new(py, &sig_der);
        let pk_py = PyBytes::new(py, &pk_bytes);
        let witness = PyList::empty(py);
        witness.append(sig_py).unwrap();
        witness.append(pk_py).unwrap();
        
        let tx_input_list = PyList::empty(py);
        tx_input_list.append(txid_py.clone()).unwrap();
        tx_input_list.append(0u32).unwrap();
        tx_input_list.append(0xffffffffu32).unwrap();
        tx_input_list.append(script_sig.clone()).unwrap();
        tx_input_list.append(witness).unwrap();
        let tx_input = to_tuple(py, &tx_input_list);
        
        let inputs = PyList::empty(py);
        inputs.append(tx_input).unwrap();
        
        let tx_list = PyList::empty(py);
        tx_list.append(1i32).unwrap();
        tx_list.append(0u32).unwrap();
        tx_list.append(inputs).unwrap();
        tx_list.append(outputs).unwrap();
        tx_list.append(py.None()).unwrap();
        tx_list.append(false).unwrap();
        let tx = to_tuple(py, &tx_list);

        let opts = create_opts(py);
        let (valid, err_msg, fee) = validate_tx_p2wpkh_compact(py, tx, utxo_items, 200, opts.into_any()).unwrap();
        
        assert!(valid, "Tx invalid: {:?}", err_msg);
        assert_eq!(fee.unwrap(), 10000);
    });
}

#[test]
fn test_txcodec_validate_errors() {
    init_python();
    Python::attach(|py| {
        let utxo_items = PyList::empty(py);
        let tx_input_list = PyList::empty(py);
        tx_input_list.append(PyBytes::new(py, &[0u8; 32])).unwrap();
        tx_input_list.append(0u32).unwrap();
        tx_input_list.append(0u32).unwrap();
        tx_input_list.append(PyBytes::new(py, &[])).unwrap();
        tx_input_list.append(PyList::empty(py)).unwrap();
        
        let tx_input = to_tuple(py, &tx_input_list);
        let inputs = PyList::empty(py);
        inputs.append(tx_input.clone()).unwrap();
        
        let tx_output_list = PyList::empty(py);
        tx_output_list.append(10u64).unwrap();
        tx_output_list.append(PyBytes::new(py, &[0x00])).unwrap();
        let tx_output = to_tuple(py, &tx_output_list);
        let outputs = PyList::empty(py);
        outputs.append(tx_output).unwrap();
        
        let tx_list = PyList::empty(py);
        tx_list.append(1i32).unwrap();
        tx_list.append(0u32).unwrap();
        tx_list.append(inputs).unwrap();
        tx_list.append(outputs.clone()).unwrap();
        tx_list.append(py.None()).unwrap();
        tx_list.append(false).unwrap();
        let tx = to_tuple(py, &tx_list);
        let opts = create_opts(py);
        
        // 1. Missing prevout
        let (valid, err, _) = validate_tx_p2wpkh_compact(py, tx.clone(), utxo_items.clone(), 100, opts.clone().into_any()).unwrap();
        assert!(!valid);
        assert_eq!(err.unwrap(), "prevout_missing");

    });
}

#[test]
fn test_txcodec_validate_duplicate_prevout() {
    init_python();
    Python::attach(|py| {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0xcd; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_bytes = pk.serialize();
        
        let pubkey_hash = hash160_bytes(&pk_bytes);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&pubkey_hash);

        let mut prev_txid = [0u8; 32];
        prev_txid[0] = 0xaa;
        let txid_py = PyBytes::new(py, &prev_txid);
        let spk_py = PyBytes::new(py, &spk);

        // Build utxo items
        let utxo_list = PyList::empty(py);
        utxo_list.append(txid_py.clone()).unwrap();
        utxo_list.append(0u32).unwrap();
        utxo_list.append(100000u64).unwrap();
        utxo_list.append(spk_py.clone()).unwrap();
        utxo_list.append(false).unwrap();
        utxo_list.append(100i64).unwrap();
        let utxo_items = PyList::empty(py);
        utxo_items.append(to_tuple(py, &utxo_list)).unwrap();

        let script_sig = PyBytes::new(py, &[]);
        let tx_output_list = PyList::empty(py);
        tx_output_list.append(90000u64).unwrap();
        tx_output_list.append(spk_py.clone()).unwrap();
        let tx_output = to_tuple(py, &tx_output_list);
        let outputs = PyList::empty(py);
        outputs.append(tx_output).unwrap();

        // Sighash script code (for valid first input)
        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.extend_from_slice(&pubkey_hash);
        script_code.extend_from_slice(&[0x88, 0xac]);

        let witness_empty = PyList::empty(py);
        let tx_input_empty_list = PyList::empty(py);
        tx_input_empty_list.append(txid_py.clone()).unwrap();
        tx_input_empty_list.append(0u32).unwrap();
        tx_input_empty_list.append(0xffffffffu32).unwrap();
        tx_input_empty_list.append(script_sig.clone()).unwrap();
        tx_input_empty_list.append(witness_empty).unwrap();
        let tx_input_empty = to_tuple(py, &tx_input_empty_list);
        
        // We need an empty tx with TWO identical inputs to compute sighash for input 0
        let inputs_empty = PyList::empty(py);
        inputs_empty.append(tx_input_empty.clone()).unwrap();
        inputs_empty.append(tx_input_empty.clone()).unwrap();
        
        let tx_empty_list = PyList::empty(py);
        tx_empty_list.append(1i32).unwrap();
        tx_empty_list.append(0u32).unwrap();
        tx_empty_list.append(inputs_empty).unwrap();
        tx_empty_list.append(outputs.clone()).unwrap();
        tx_empty_list.append(py.None()).unwrap();
        tx_empty_list.append(false).unwrap();
        let tx_empty = to_tuple(py, &tx_empty_list);

        let sighash = sighash_bip143_compact(py, tx_empty.clone(), 0, &script_code, 100000, 1).unwrap();
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(sighash.as_bytes());
        let msg = Message::from_digest(digest_arr);
        let sig = secp.sign_ecdsa(msg, &sk);
        let mut sig_der = sig.serialize_der().to_vec();
        sig_der.push(1); // SIGHASH_ALL
        
        let sig_py = PyBytes::new(py, &sig_der);
        let pk_py = PyBytes::new(py, &pk_bytes);
        let witness = PyList::empty(py);
        witness.append(sig_py).unwrap();
        witness.append(pk_py).unwrap();
        
        let tx_input_list = PyList::empty(py);
        tx_input_list.append(txid_py.clone()).unwrap();
        tx_input_list.append(0u32).unwrap();
        tx_input_list.append(0xffffffffu32).unwrap();
        tx_input_list.append(script_sig.clone()).unwrap();
        tx_input_list.append(witness).unwrap();
        let tx_input = to_tuple(py, &tx_input_list);
        
        let inputs = PyList::empty(py);
        inputs.append(tx_input.clone()).unwrap();
        inputs.append(tx_input.clone()).unwrap(); // DUPLICATE
        
        let tx_list = PyList::empty(py);
        tx_list.append(1i32).unwrap();
        tx_list.append(0u32).unwrap();
        tx_list.append(inputs).unwrap();
        tx_list.append(outputs).unwrap();
        tx_list.append(py.None()).unwrap();
        tx_list.append(false).unwrap();
        let tx = to_tuple(py, &tx_list);

        let opts = create_opts(py);
        let (valid, err_msg, _) = validate_tx_p2wpkh_compact(py, tx, utxo_items, 200, opts.into_any()).unwrap();
        
        assert!(!valid);
        assert_eq!(err_msg.unwrap(), "duplicate_prevout_in_tx");
    });
}

