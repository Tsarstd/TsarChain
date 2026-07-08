// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md

use std::sync::Once;
use pyo3::prelude::*;
use sha2::{Sha256, Digest};
use pyo3::types::{PyDict, PyList, PyBytes, PyAny};

use tsarcore_native::validation::{
    validate_block_txs_native,
    validate_block_txs_compact
};

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

fn create_opts<'py>(py: Python<'py>) -> Bound<'py, PyDict> {
    let opts = PyDict::new(py);
    opts.set_item("coinbase_maturity", 100).unwrap();
    opts.set_item("max_sigops_per_tx", 20000).unwrap();
    opts.set_item("max_sigops_per_block", 80000).unwrap();
    opts.set_item("max_tx_vsize", 100000).unwrap();
    opts.set_item("min_tx_vsize", 10).unwrap();
    opts.set_item("max_tx_weight", 400000).unwrap();
    opts.set_item("min_tx_weight", 40).unwrap();
    opts.set_item("max_tx_inputs", 1000).unwrap();
    opts.set_item("max_tx_outputs", 1000).unwrap();
    opts.set_item("enforce_low_s", true).unwrap();
    opts
}

// Generate valid P2WSH witness and script pubkey (Graffiti payout covenant)
fn generate_p2wsh_covenant() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let art_digest = vec![0xaa; 32];
    let mut redeem_script = Vec::new();
    redeem_script.push(0x20); // Push 32 bytes
    redeem_script.extend_from_slice(&art_digest);
    redeem_script.push(0x87); // OP_EQUAL

    let hash32 = Sha256::digest(&redeem_script);
    
    let mut script_pubkey = Vec::new();
    script_pubkey.push(0x00); // OP_0
    script_pubkey.push(0x20); // Push 32 bytes
    script_pubkey.extend_from_slice(&hash32);

    (art_digest, redeem_script, script_pubkey)
}

fn create_valid_tx_dict<'py>(py: Python<'py>, is_coinbase: bool, txid_hex: &str) -> Bound<'py, PyDict> {
    let tx = PyDict::new(py);
    tx.set_item("version", 1).unwrap();
    tx.set_item("locktime", 0).unwrap();
    tx.set_item("txid", txid_hex).unwrap();
    tx.set_item("is_coinbase", is_coinbase).unwrap();

    let inputs = PyList::empty(py);
    let inp = PyDict::new(py);
    let prev_txid = hex::encode(vec![0xbb; 32]);
    inp.set_item("txid", prev_txid.clone()).unwrap();
    inp.set_item("vout", 0).unwrap();
    inp.set_item("sequence", 0xffffffffu32).unwrap();
    
    if !is_coinbase {
        let (art_digest, redeem_script, _) = generate_p2wsh_covenant();
        let witness = PyList::empty(py);
        witness.append(PyBytes::new(py, &art_digest)).unwrap();
        witness.append(PyBytes::new(py, &redeem_script)).unwrap();
        inp.set_item("witness", witness).unwrap();
    } else {
        inp.set_item("witness", PyList::empty(py)).unwrap();
    }
    inputs.append(inp).unwrap();
    tx.set_item("inputs", inputs).unwrap();

    let outputs = PyList::empty(py);
    let out = PyDict::new(py);
    out.set_item("amount", 5000000000u64).unwrap();
    let (_, _, script_pubkey) = generate_p2wsh_covenant();
    out.set_item("script_pubkey", hex::encode(&script_pubkey)).unwrap();
    outputs.append(out).unwrap();
    tx.set_item("outputs", outputs).unwrap();

    tx
}

fn create_utxo_map<'py>(py: Python<'py>) -> Bound<'py, PyDict> {
    let utxo = PyDict::new(py);
    let prev_txid = hex::encode(vec![0xbb; 32]);
    let key = format!("{}:0", prev_txid);
    
    let entry = PyDict::new(py);
    entry.set_item("amount", 5000000000u64 + 1000).unwrap(); // +1000 for fee
    let (_, _, script_pubkey) = generate_p2wsh_covenant();
    entry.set_item("script_pubkey", hex::encode(&script_pubkey)).unwrap();
    entry.set_item("is_coinbase", false).unwrap();
    entry.set_item("block_height", 100).unwrap();
    
    utxo.set_item(key, entry).unwrap();
    utxo
}

#[test]
fn test_validate_block_txs_native_success() {
    init_python();
    Python::attach(|py| {
        let block = PyDict::new(py);
        let txs = PyList::empty(py);
        
        let tx1 = create_valid_tx_dict(py, true, &hex::encode(vec![0x11; 32]));
        let tx2 = create_valid_tx_dict(py, false, &hex::encode(vec![0x22; 32]));
        
        txs.append(tx1).unwrap();
        txs.append(tx2).unwrap();
        block.set_item("transactions", txs).unwrap();

        let utxo = create_utxo_map(py);
        let opts = create_opts(py);

        let (success, err, fees) = validate_block_txs_native(&block, &utxo, 200, &opts).unwrap();
        assert!(success, "Validation failed: {:?}", err);
        assert!(err.is_none());
        assert_eq!(fees.unwrap().len(), 1); // Only non-coinbase tx has fee output
    });
}

#[test]
fn test_validate_block_txs_native_errors() {
    init_python();
    Python::attach(|py| {
        let block = PyDict::new(py);
        let utxo = create_utxo_map(py);
        let opts = create_opts(py);

        // 1. Empty block
        block.set_item("transactions", PyList::empty(py)).unwrap();
        let (success, err, _) = validate_block_txs_native(&block, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "empty_block_transactions");

        // 2. Missing coinbase
        let txs = PyList::empty(py);
        txs.append(create_valid_tx_dict(py, false, &hex::encode(vec![0x33; 32]))).unwrap();
        block.set_item("transactions", txs).unwrap();
        let (success, err, _) = validate_block_txs_native(&block, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "missing_coinbase");
        
        // 3. Duplicate coinbase
        let txs = PyList::empty(py);
        txs.append(create_valid_tx_dict(py, true, &hex::encode(vec![0x11; 32]))).unwrap();
        txs.append(create_valid_tx_dict(py, true, &hex::encode(vec![0x22; 32]))).unwrap();
        block.set_item("transactions", txs).unwrap();
        let (success, err, _) = validate_block_txs_native(&block, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "duplicate_coinbase");
        
        // 4. Vsize exceeds limit
        let small_opts = create_opts(py);
        small_opts.set_item("max_tx_vsize", 10).unwrap(); // very small
        let txs = PyList::empty(py);
        txs.append(create_valid_tx_dict(py, true, &hex::encode(vec![0x11; 32]))).unwrap();
        txs.append(create_valid_tx_dict(py, false, &hex::encode(vec![0x22; 32]))).unwrap();
        block.set_item("transactions", txs).unwrap();
        let (success, err, _) = validate_block_txs_native(&block, &utxo, 200, &small_opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "tx_vsize_exceeds_limit");
    });
}

#[test]
fn test_validate_block_txs_native_extra_errors() {
    init_python();
    Python::attach(|py| {
        let block = PyDict::new(py);
        let utxo = create_utxo_map(py);
        let opts = create_opts(py);

        // 1. P2WPKH signature failure (covers P2WPKH parsing, sighash, and verify_signature)
        let txs = PyList::empty(py);
        let tx1 = create_valid_tx_dict(py, true, &hex::encode(vec![0x11; 32]));
        let tx2 = PyDict::new(py);
        tx2.set_item("version", 1).unwrap();
        tx2.set_item("locktime", 0).unwrap();
        tx2.set_item("txid", hex::encode(vec![0x44; 32])).unwrap();
        tx2.set_item("is_coinbase", false).unwrap();
        
        let inputs = PyList::empty(py);
        let inp = PyDict::new(py);
        let prev_txid = hex::encode(vec![0xcc; 32]);
        inp.set_item("txid", prev_txid.clone()).unwrap();
        inp.set_item("vout", 0).unwrap();
        inp.set_item("sequence", 0xffffffffu32).unwrap();
        
        // Construct P2WPKH witness
        let mut pubkey = vec![0x02];
        pubkey.extend_from_slice(&vec![0x55; 32]);
        let h = sha2::Sha256::digest(&pubkey);
        let ripe = ripemd::Ripemd160::digest(&h);
        
        let mut sig_full = vec![0x30, 0x05, 0x02, 0x01, 0x01]; // Dummy DER
        sig_full.push(0x01); // SIGHASH_ALL
        
        let witness = PyList::empty(py);
        witness.append(PyBytes::new(py, &sig_full)).unwrap();
        witness.append(PyBytes::new(py, &pubkey)).unwrap();
        inp.set_item("witness", witness).unwrap();
        inputs.append(inp).unwrap();
        tx2.set_item("inputs", inputs).unwrap();

        let outputs = PyList::empty(py);
        let out = PyDict::new(py);
        out.set_item("amount", 1000u64).unwrap();
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&ripe);
        out.set_item("script_pubkey", hex::encode(&spk)).unwrap();
        outputs.append(out).unwrap();
        tx2.set_item("outputs", outputs).unwrap();
        txs.append(tx1).unwrap();
        txs.append(tx2).unwrap();
        block.set_item("transactions", txs).unwrap();
        
        // Add UTXO for P2WPKH
        let entry = PyDict::new(py);
        entry.set_item("amount", 5000u64).unwrap();
        entry.set_item("script_pubkey", hex::encode(&spk)).unwrap();
        entry.set_item("is_coinbase", false).unwrap();
        entry.set_item("block_height", 100).unwrap();
        utxo.set_item(format!("{}:0", prev_txid), entry).unwrap();

        let (success, err, _) = validate_block_txs_native(&block, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert!(err.unwrap().contains("sig_verify_failed"));
    });
}

// ----------------- COMPACT TX TESTS -----------------

fn create_valid_compact_tx<'py>(py: Python<'py>, is_coinbase: bool, txid_bytes: &[u8]) -> Bound<'py, PyAny> {
    // tuple: (version, locktime, inputs, outputs, txid, is_coinbase)
    let version: i32 = 1;
    let locktime: u32 = 0;
    
    let inputs = PyList::empty(py);
    
    let prev_txid = vec![0xbb; 32];
    let inp = PyList::empty(py);
    if !is_coinbase {
        let (art_digest, redeem_script, _) = generate_p2wsh_covenant();
        let witness = PyList::empty(py);
        witness.append(PyBytes::new(py, &art_digest)).unwrap();
        witness.append(PyBytes::new(py, &redeem_script)).unwrap();
        
        inp.append(PyBytes::new(py, &prev_txid)).unwrap();
        inp.append(0u32).unwrap();
        inp.append(0xffffffffu32).unwrap();
        inp.append(PyBytes::new(py, &[])).unwrap();
        inp.append(witness).unwrap();
    } else {
        inp.append(PyBytes::new(py, &prev_txid)).unwrap();
        inp.append(0u32).unwrap();
        inp.append(0xffffffffu32).unwrap();
        inp.append(PyBytes::new(py, &[])).unwrap();
        inp.append(PyList::empty(py)).unwrap();
    }
    
    let builtins = py.import("builtins").unwrap();
    let inp_tuple = builtins.call_method1("tuple", (inp,)).unwrap();
    inputs.append(inp_tuple).unwrap();

    let outputs = PyList::empty(py);
    let (_, _, script_pubkey) = generate_p2wsh_covenant();
    let out = PyList::empty(py);
    out.append(5000000000u64).unwrap();
    out.append(PyBytes::new(py, &script_pubkey)).unwrap();
    
    let out_tuple = builtins.call_method1("tuple", (out,)).unwrap();
    outputs.append(out_tuple).unwrap();

    let tx_list = PyList::empty(py);
    tx_list.append(version).unwrap();
    tx_list.append(locktime).unwrap();
    tx_list.append(inputs).unwrap();
    tx_list.append(outputs).unwrap();
    tx_list.append(PyBytes::new(py, txid_bytes)).unwrap();
    tx_list.append(is_coinbase).unwrap();
    
    builtins.call_method1("tuple", (tx_list,)).unwrap()
}

fn create_compact_utxo<'py>(py: Python<'py>) -> Bound<'py, PyList> {
    let utxo = PyList::empty(py);
    let prev_txid = vec![0xbb; 32];
    let (_, _, script_pubkey) = generate_p2wsh_covenant();
    
    let entry = PyList::empty(py);
    entry.append(PyBytes::new(py, &prev_txid)).unwrap();
    entry.append(0u32).unwrap();
    entry.append(5000000000u64 + 1000).unwrap();
    entry.append(PyBytes::new(py, &script_pubkey)).unwrap();
    entry.append(false).unwrap();
    entry.append(100i64).unwrap();
    
    let builtins = py.import("builtins").unwrap();
    let entry_tuple = builtins.call_method1("tuple", (entry,)).unwrap();
    utxo.append(entry_tuple).unwrap();
    utxo
}

#[test]
fn test_validate_block_txs_compact_success() {
    init_python();
    Python::attach(|py| {
        let block_txs = PyList::empty(py);
        
        let tx1 = create_valid_compact_tx(py, true, &vec![0x11; 32]);
        let tx2 = create_valid_compact_tx(py, false, &vec![0x22; 32]);
        
        block_txs.append(tx1).unwrap();
        block_txs.append(tx2).unwrap();

        let utxo = create_compact_utxo(py);
        let opts = create_opts(py);

        let (success, err, fees) = validate_block_txs_compact(&block_txs, &utxo, 200, &opts).unwrap();
        assert!(success, "Validation failed: {:?}", err);
        assert!(err.is_none());
        assert_eq!(fees.unwrap().len(), 1);
    });
}

#[test]
fn test_validate_block_txs_compact_errors() {
    init_python();
    Python::attach(|py| {
        let utxo = create_compact_utxo(py);
        let opts = create_opts(py);

        // 1. Empty block
        let block_txs = PyList::empty(py);
        let (success, err, _) = validate_block_txs_compact(&block_txs, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "empty_block_transactions");

        // 2. Missing coinbase
        let block_txs = PyList::empty(py);
        block_txs.append(create_valid_compact_tx(py, false, &vec![0x33; 32])).unwrap();
        let (success, err, _) = validate_block_txs_compact(&block_txs, &utxo, 200, &opts).unwrap();
        assert!(!success);
        assert_eq!(err.unwrap(), "missing_coinbase");
    });
}
