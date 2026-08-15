// SPDX-License-Identifier: MIT

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use std::sync::Once;
use tsarcore_native::{
    count_sigops, hash160, hash256, merkle_root, randomx_pow_hash, secp_sign_der_low_s,
    secp_verify_der_low_s, secp_verify_der_low_s_many, sighash_bip143,
};
use secp256k1::{Secp256k1, SecretKey};

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

#[test]
fn test_lib_hashing() {
    init_python();
    Python::attach(|py| {
        // test hash256
        let data = b"hello world";
        let h256 = hash256(py, data).unwrap();
        assert_eq!(h256.as_bytes().len(), 32);

        // test hash160
        let h160 = hash160(py, data).unwrap();
        assert_eq!(h160.as_bytes().len(), 20);
    });
}

#[test]
fn test_lib_randomx() {
    init_python();
    Python::attach(|py| {
        let header = PyBytes::new(py, b"block_header");
        let key = PyBytes::new(py, b"key_seed");
        
        // Fast test without full_mem to save time
        let hash_result = randomx_pow_hash(
            py, 
            header.clone(), 
            key.clone(), 
            false, // full_mem
            false, // large_pages
            true,  // jit
            false, // hard_aes
            false, // secure_jit
            1      // max_cache_entries
        );
        assert!(hash_result.is_ok());
        assert_eq!(hash_result.unwrap().as_bytes().len(), 32);

        // Test with custom max_cache_entries
        let hash_result2 = randomx_pow_hash(
            py, 
            header.clone(), 
            key.clone(), 
            false, 
            false,  // large_pages
            true,  
            false, 
            false, 
            2      // max_cache_entries
        );
        assert!(hash_result2.is_ok());

        // Test cache eviction (max_entries = 1, use 2 keys)
        let header2 = PyBytes::new(py, b"hdr2");
        let key2 = PyBytes::new(py, b"key2");
        let _ = randomx_pow_hash(py, header.clone(), key.clone(), false, false, false, false, false, 1);
        let _ = randomx_pow_hash(py, header2, key2, false, false, false, false, false, 1);

        // Error cases
        let empty_header = PyBytes::new(py, b"");
        let res_err = randomx_pow_hash(py, empty_header, key.clone(), false, false, false, false, false, 1);
        assert!(res_err.is_err());
        
        let empty_key = PyBytes::new(py, b"");
        let res_err2 = randomx_pow_hash(py, header.clone(), empty_key, false, false, false, false, false, 1);
        assert!(res_err2.is_err());
    });
}

#[test]
fn test_lib_sigops() {
    // Empty script
    let ops = count_sigops(b"").unwrap();
    assert_eq!(ops, 0);

    // Basic script with 1 CHECKSIG (0xac)
    let ops2 = count_sigops(&[0xac]).unwrap();
    assert_eq!(ops2, 1);

    // Basic script with CHECKMULTISIG (0xae) without any prior pushed numbers
    let ops3 = count_sigops(&[0xae]).unwrap();
    assert_eq!(ops3, 20); // defaults to 20 if no small_int found

    // Script with OP_2 CHECKMULTISIG (OP_2 is 0x52)
    let ops4 = count_sigops(&[0x52, 0xae]).unwrap();
    assert_eq!(ops4, 2); 

    // Negative/edge cases for parsing ops (OOB)
    // OP_PUSHDATA1 missing bytes
    let _ = count_sigops(&[0x4c]);
    let _ = count_sigops(&[0x4c, 0x05]); // missing 5 bytes
    // OP_PUSHDATA2 missing bytes
    let _ = count_sigops(&[0x4d, 0x05]);
    let _ = count_sigops(&[0x4d, 0x05, 0x00, 0x00]);
    // OP_PUSHDATA4 missing bytes
    let _ = count_sigops(&[0x4e, 0x05, 0x00, 0x00]);
    let _ = count_sigops(&[0x4e, 0x05, 0x00, 0x00, 0x00, 0x00]);
    
    // Unknown small int
    let _ = count_sigops(&[0x05, 0xae]); // 0x05 is OP_5? No OP_5 is 0x55
}

#[test]
fn test_lib_ecdsa() {
    init_python();
    Python::attach(|py| {
        // Generate key pair
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0xcd; 32]).expect("32 bytes, within curve order");
        let pk = sk.public_key(&secp);
        
        // Digest
        let digest32 = [0xaa; 32];
        let sk_hex = hex::encode(sk.secret_bytes());

        // Sign
        let der_sig_py = secp_sign_der_low_s(py, &sk_hex, &digest32).unwrap();
        let der_sig = der_sig_py.as_bytes();

        // Verify single
        let is_valid = secp_verify_der_low_s(&pk.serialize(), &digest32, der_sig).unwrap();
        assert!(is_valid);
        
        let is_valid_uncompressed = secp_verify_der_low_s(&pk.serialize_uncompressed(), &digest32, der_sig).unwrap();
        assert!(is_valid_uncompressed);

        // Verify many
        let item1 = PyTuple::new(py, &[
            PyBytes::new(py, &pk.serialize()).into_any(),
            PyBytes::new(py, &digest32).into_any(),
            der_sig_py.clone().into_any()
        ]).unwrap();
        
        let triples = PyList::new(py, vec![item1.clone(), item1.clone()]).unwrap();
        
        let results = secp_verify_der_low_s_many(py, triples.into_any(), true, false).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.get_item(0).unwrap().extract::<bool>().unwrap());
        
        let results_par = secp_verify_der_low_s_many(py, PyList::new(py, vec![item1]).unwrap().into_any(), true, true).unwrap();
        assert_eq!(results_par.len(), 1);
        assert!(results_par.get_item(0).unwrap().extract::<bool>().unwrap());

        // --- Negative Cases ---
        
        // secp_sign_der_low_s invalid digest size
        assert!(secp_sign_der_low_s(py, &sk_hex, &[0; 31]).is_err());
        // secp_sign_der_low_s invalid hex
        assert!(secp_sign_der_low_s(py, "zz", &digest32).is_err());
        
        // secp_verify_der_low_s invalid digest size
        assert!(secp_verify_der_low_s(&pk.serialize(), &[0; 31], der_sig).is_err());
        // secp_verify_der_low_s invalid pubkey
        assert_eq!(secp_verify_der_low_s(&[0; 33], &digest32, der_sig).unwrap(), false);
        // secp_verify_der_low_s invalid sig
        assert_eq!(secp_verify_der_low_s(&pk.serialize(), &digest32, &[0; 70]).unwrap(), false);
        
        // secp_verify_der_low_s_many invalid shape
        let bad_item = PyTuple::new(py, &[
            PyBytes::new(py, &pk.serialize()).into_any()
        ]).unwrap(); // Only 1 element
        assert!(secp_verify_der_low_s_many(py, PyList::new(py, vec![bad_item]).unwrap().into_any(), true, false).is_err());
        
        // secp_verify_der_low_s_many invalid digest len
        let bad_digest_item = PyTuple::new(py, &[
            PyBytes::new(py, &pk.serialize()).into_any(),
            PyBytes::new(py, &[0; 10]).into_any(),
            der_sig_py.clone().into_any()
        ]).unwrap();
        assert!(secp_verify_der_low_s_many(py, PyList::new(py, vec![bad_digest_item]).unwrap().into_any(), true, false).is_err());
    });
}

#[test]
fn test_lib_merkle_root() {
    init_python();
    Python::attach(|py| {
        let empty_list = PyList::empty(py);
        let root0 = merkle_root(py, empty_list.into_any()).unwrap();
        assert_eq!(root0.as_bytes(), &[0u8; 32]);

        let txids = PyList::empty(py);
        txids.append(PyBytes::new(py, &[0x11; 32])).unwrap();
        let root1 = merkle_root(py, txids.clone().into_any()).unwrap();
        assert_eq!(root1.as_bytes(), &[0x11; 32]);
        
        txids.append(PyBytes::new(py, &[0x22; 32])).unwrap();
        let root2 = merkle_root(py, txids.into_any()).unwrap();
        assert_ne!(root2.as_bytes(), &[0u8; 32]);
    });
}

#[test]
fn test_lib_sighash() {
    init_python();
    Python::attach(|py| {
        // Create a minimal tx view bytes for bip143
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&1i32.to_le_bytes()); // version = 1
        // marker
        tx_bytes.extend_from_slice(&[0x00, 0x01]);
        
        // 1 input
        tx_bytes.push(1); // varint 1
        tx_bytes.extend_from_slice(&[0x55; 32]); // prev txid
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // vout
        tx_bytes.push(0); // script len 0
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // seq

        // 2 outputs
        tx_bytes.push(2); // varint 2
        // Output 1: 0 script len
        tx_bytes.extend_from_slice(&1000u64.to_le_bytes()); // value
        tx_bytes.push(0); // script len 0
        // Output 2: large script len (e.g. 253 to trigger 0xfd branch)
        tx_bytes.extend_from_slice(&500u64.to_le_bytes()); // value
        tx_bytes.push(0xfd); // 0xfd
        tx_bytes.extend_from_slice(&253u16.to_le_bytes()); // length 253
        tx_bytes.extend_from_slice(&vec![0x01; 253]); // script

        // 1 witness stack (length 1, size 2) to trigger segwit branch
        tx_bytes.push(1); // n_stack = 1
        tx_bytes.push(2); // size = 2
        tx_bytes.extend_from_slice(&[0xaa, 0xbb]); // witness item

        // locktime
        tx_bytes.extend_from_slice(&0u32.to_le_bytes());

        let res = sighash_bip143(py, &tx_bytes, 0, b"script", 1000, 0x01).unwrap();
        assert_eq!(res.as_bytes().len(), 32);
        
        // Invalid input index
        let err = sighash_bip143(py, &tx_bytes, 99, b"script", 1000, 0x01);
        assert!(err.is_err());

        // Invalid sighash type
        let err2 = sighash_bip143(py, &tx_bytes, 0, b"script", 1000, 0x02);
        assert!(err2.is_err());

        // Invalid tx bytes parsing (trigger OOB)
        let err3 = sighash_bip143(py, &tx_bytes[0..5], 0, b"script", 1000, 0x01);
        assert!(err3.is_err());
    });
}

#[test]
fn test_lib_pymodule_init() {
    init_python();
    Python::attach(|py| {
        let m = pyo3::types::PyModule::new(py, "tsarcore_native").unwrap();
        let res = tsarcore_native::tsarcore_native(py, &m);
        assert!(res.is_ok());
    });
}