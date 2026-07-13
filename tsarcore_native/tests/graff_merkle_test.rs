// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md


use std::sync::Once;
use std::io::Write;
use pyo3::prelude::*;
use tempfile::NamedTempFile;
use pyo3::types::{PyDict, PyList};

use tsarcore_native::graff_merkle::{
    graff_merkle_verify,
    graff_merkle_root_for_file,
    graff_merkle_path_for_file,
};

static INIT: Once = Once::new();
fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

fn create_dummy_file(content: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file
}

#[test]
fn test_graff_merkle_basic_file() {
    init_python();
    Python::attach(|py| {
        // Create a 10-byte file
        let content = b"0123456789";
        let temp_file = create_dummy_file(content);
        let path = temp_file.path().to_str().unwrap();

        // 1. Get root and count for chunk size 2
        // chunk 2 -> 5 chunks -> 5 leaves -> odd number of leaves (will duplicate last for root)
        let (root_bytes, count) = graff_merkle_root_for_file(py, path, 2).unwrap();
        assert_eq!(count, 5);
        let root_hex = hex::encode(root_bytes.as_bytes());

        // 2. Get path for index 2
        let path_list = graff_merkle_path_for_file(py, path, 2, 2).unwrap();
        
        // Compute leaf hash for chunk index 2 ("45")
        use sha2::{Sha256, Digest};
        let leaf_hash = Sha256::digest(b"45");
        let leaf_hex = hex::encode(leaf_hash);

        // 3. Verify
        let is_valid = graff_merkle_verify(&root_hex, &leaf_hex, path_list.into_any()).unwrap();
        assert!(is_valid);
    });
}



#[test]
fn test_graff_merkle_errors() {
    init_python();
    Python::attach(|py| {
        let content = b"testdata";
        let temp_file = create_dummy_file(content);
        let file_path = temp_file.path().to_str().unwrap();

        // 1. Chunk size 0
        let res = graff_merkle_root_for_file(py, file_path, 0);
        assert!(res.is_err(), "chunk size 0 should fail");

        // 2. Empty leaves / empty file
        let empty_file = create_dummy_file(b"");
        let res3 = graff_merkle_root_for_file(py, empty_file.path().to_str().unwrap(), 2);
        assert!(res3.is_err(), "empty file should fail");

        // 4. File not found
        let res6 = graff_merkle_root_for_file(py, "/non/existent/path/123xyz", 4);
        assert!(res6.is_err());
        let res7 = graff_merkle_path_for_file(py, "/non/existent/path/123xyz", 4, 0);
        assert!(res7.is_err());
    });
}

#[test]
fn test_graff_merkle_verify_errors() {
    init_python();
    Python::attach(|py| {
        let valid_hex32 = "0000000000000000000000000000000000000000000000000000000000000000";
        let invalid_hex32 = "000000000000000000000000000000000000000000000000000000000000000"; // 63 chars (not 64)
        
        let empty_list = PyList::empty(py);

        // Bad root hex
        assert!(!graff_merkle_verify(invalid_hex32, valid_hex32, empty_list.clone().into_any()).unwrap());
        
        // Bad leaf hex
        assert!(!graff_merkle_verify(valid_hex32, invalid_hex32, empty_list.clone().into_any()).unwrap());

        // Bad path iter (not iterable)
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, py.None().into_bound(py)).unwrap());

        // List with non-dict item
        let list_with_int = PyList::empty(py);
        list_with_int.append(42).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_with_int.into_any()).unwrap());

        // Dict missing side
        let dict1 = PyDict::new(py);
        dict1.set_item("hash", valid_hex32).unwrap();
        let list_no_side = PyList::empty(py);
        list_no_side.append(dict1).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_no_side.into_any()).unwrap());

        // Dict missing hash
        let dict2 = PyDict::new(py);
        dict2.set_item("side", "L").unwrap();
        let list_no_hash = PyList::empty(py);
        list_no_hash.append(dict2).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_no_hash.into_any()).unwrap());

        // Dict with invalid side type (e.g. integer)
        let dict3 = PyDict::new(py);
        dict3.set_item("side", 42).unwrap();
        dict3.set_item("hash", valid_hex32).unwrap();
        let list_bad_side_type = PyList::empty(py);
        list_bad_side_type.append(dict3).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_bad_side_type.into_any()).unwrap());

        // Dict with invalid hash type (e.g. integer)
        let dict4 = PyDict::new(py);
        dict4.set_item("side", "L").unwrap();
        dict4.set_item("hash", 42).unwrap();
        let list_bad_hash_type = PyList::empty(py);
        list_bad_hash_type.append(dict4).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_bad_hash_type.into_any()).unwrap());

        // Dict with invalid hash hex (wrong length)
        let dict5 = PyDict::new(py);
        dict5.set_item("side", "L").unwrap();
        dict5.set_item("hash", invalid_hex32).unwrap();
        let list_bad_hash_hex = PyList::empty(py);
        list_bad_hash_hex.append(dict5).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_bad_hash_hex.into_any()).unwrap());

        // Dict with invalid side value (not L or R)
        let dict6 = PyDict::new(py);
        dict6.set_item("side", "X").unwrap();
        dict6.set_item("hash", valid_hex32).unwrap();
        let list_bad_side_val = PyList::empty(py);
        list_bad_side_val.append(dict6).unwrap();
        assert!(!graff_merkle_verify(valid_hex32, valid_hex32, list_bad_side_val.into_any()).unwrap());

        // Valid execution but mismatch
        let dict7 = PyDict::new(py);
        dict7.set_item("side", "L").unwrap();
        dict7.set_item("hash", valid_hex32).unwrap();
        let list_mismatch = PyList::empty(py);
        list_mismatch.append(dict7).unwrap();
        let mismatch_root = "1111111111111111111111111111111111111111111111111111111111111111";
        assert!(!graff_merkle_verify(mismatch_root, valid_hex32, list_mismatch.into_any()).unwrap());
    });
}
