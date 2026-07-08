// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md

use std::sync::Once;
use pyo3::prelude::*;
use tempfile::tempdir;
use tsarcore_native::storage::{json_read_file, json_write_file, open_storage};

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

#[test]
fn test_json_file_helpers() {
    init_python();
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.json");
    let file_str = file_path.to_str().unwrap();

    // Read non-existent
    let content = json_read_file(file_str).unwrap();
    assert_eq!(content, None);

    // Write pretty
    let json_data = r#"{"hello":"world"}"#;
    json_write_file(file_str, json_data, true).unwrap();
    
    // Read exists
    let content = json_read_file(file_str).unwrap().unwrap();
    assert!(content.contains("\"hello\": \"world\""));

    // Write not pretty
    json_write_file(file_str, json_data, false).unwrap();
    let content2 = json_read_file(file_str).unwrap().unwrap();
    assert_eq!(content2, json_data);
}

#[test]
fn test_json_backend() {
    init_python();
    let dir = tempdir().unwrap();
    let path_str = dir.path().to_str().unwrap();

    Python::attach(|py| {
        let storage = open_storage("json", path_str, None, None, true).unwrap();
        assert_eq!(storage.backend(), "json");

        let db = "testdb";
        let key = b"my_key";
        let val = b"my_val";

        // put_bytes & get_bytes
        storage.put_bytes(db, key, val).unwrap();
        let fetched = storage.get_bytes(py, db, key).unwrap().unwrap();
        assert_eq!(fetched.as_bytes(), val);

        // put_json & get_json
        let json_key = b"my_json";
        let json_text = r#"{"foo": "bar"}"#;
        storage.put_json(db, json_key, json_text).unwrap();
        let fetched_json = storage.get_json(py, db, json_key).unwrap().unwrap();
        let dict = fetched_json.extract::<pyo3::Bound<pyo3::types::PyDict>>(py).unwrap();
        assert_eq!(dict.get_item("foo").unwrap().unwrap().extract::<String>().unwrap(), "bar");

        // delete
        let deleted = storage.delete(db, key).unwrap();
        assert!(deleted);
        let fetched2 = storage.get_bytes(py, db, key).unwrap();
        assert!(fetched2.is_none());

        // put_batch
        let mut batch = Vec::new();
        batch.push((b"k1".to_vec(), Some(b"v1".to_vec())));
        batch.push((b"k2".to_vec(), Some(b"v2".to_vec())));
        batch.push((b"k3".to_vec(), None)); // delete non-existent
        storage.put_batch(db, batch).unwrap();

        // iter_prefix
        let py_list = storage.iter_prefix(py, db, b"k").unwrap();
        assert_eq!(py_list.len(), 2);
        
        let py_list_chunk = storage.iter_prefix_chunk(py, db, b"k", 1, None).unwrap();
        assert_eq!(py_list_chunk.len(), 1);

        // clear_db
        storage.clear_db(db).unwrap();
        let py_list_empty = storage.iter_prefix(py, db, b"k").unwrap();
        assert_eq!(py_list_empty.len(), 0);
        
        // Unsupported operations
        let copy_res = storage.copy("dest", false);
        assert!(copy_res.is_err());
        
        let apply_res = storage.apply_utxo_ops(vec![]);
        assert!(apply_res.is_err());
    });
}

#[test]
fn test_lmdb_backend() {
    init_python();
    let dir = tempdir().unwrap();
    let path_str = dir.path().to_str().unwrap();

    Python::attach(|py| {
        // Init LMDB with small max size to test growth later
        let storage = open_storage("lmdb", path_str, Some(1024 * 1024), Some(4 * 1024 * 1024), false).unwrap();
        assert_eq!(storage.backend(), "lmdb");

        let db = "testdb_lmdb";
        let key = b"my_key";
        let val = b"my_val";

        // put_bytes & get_bytes
        storage.put_bytes(db, key, val).unwrap();
        let fetched = storage.get_bytes(py, db, key).unwrap().unwrap();
        assert_eq!(fetched.as_bytes(), val);

        // put_json & get_json
        let json_key = b"my_json";
        let json_text = r#"{"foo": "bar"}"#;
        storage.put_json(db, json_key, json_text).unwrap();
        let fetched_json = storage.get_json(py, db, json_key).unwrap().unwrap();
        let dict = fetched_json.extract::<pyo3::Bound<pyo3::types::PyDict>>(py).unwrap();
        assert_eq!(dict.get_item("foo").unwrap().unwrap().extract::<String>().unwrap(), "bar");

        // delete
        let deleted = storage.delete(db, key).unwrap();
        assert!(deleted);
        let fetched2 = storage.get_bytes(py, db, key).unwrap();
        assert!(fetched2.is_none());

        // put_batch
        let mut batch = Vec::new();
        batch.push((b"k1".to_vec(), Some(b"v1".to_vec())));
        batch.push((b"k2".to_vec(), Some(b"v2".to_vec())));
        batch.push((b"k1".to_vec(), None)); // delete just created
        storage.put_batch(db, batch).unwrap();

        let fetched_k1 = storage.get_bytes(py, db, b"k1").unwrap();
        assert!(fetched_k1.is_none());
        
        let fetched_k2 = storage.get_bytes(py, db, b"k2").unwrap().unwrap();
        assert_eq!(fetched_k2.as_bytes(), b"v2");

        // iter_prefix
        storage.put_bytes(db, b"pre_1", b"1").unwrap();
        storage.put_bytes(db, b"pre_2", b"2").unwrap();
        storage.put_bytes(db, b"pre_3", b"3").unwrap();
        let py_list = storage.iter_prefix(py, db, b"pre_").unwrap();
        assert_eq!(py_list.len(), 3);
        
        let py_list_chunk = storage.iter_prefix_chunk(py, db, b"pre_", 2, Some(b"pre_1")).unwrap();
        assert_eq!(py_list_chunk.len(), 2);

        // apply_utxo_ops
        let ops = vec![
            ("utxo1".to_string(), Some(100), Some(vec![0x00]), Some(false), Some(1)),
            ("utxo2".to_string(), None, None, None, None), // deletion
        ];
        let (put_c, del_c) = storage.apply_utxo_ops(ops).unwrap();
        assert_eq!(put_c, 1);
        assert_eq!(del_c, 1);

        // clear_db
        storage.clear_db(db).unwrap();
        let py_list_empty = storage.iter_prefix(py, db, b"pre_").unwrap();
        assert_eq!(py_list_empty.len(), 0);

        // copy env
        let dest_dir = tempdir().unwrap();
        let dest_str = dest_dir.path().to_str().unwrap();
        storage.copy(dest_str, true).unwrap();
        assert!(dest_dir.path().join("data.mdb").exists());
    });
}

#[test]
fn test_lmdb_map_full_growth() {
    init_python();
    let dir = tempdir().unwrap();
    let path_str = dir.path().to_str().unwrap();

    Python::attach(|_py| {
        // Init LMDB with VERY small max size so it hits MapFull instantly on big inserts
        let init_size = 1024 * 1024; // 1MB
        let max_size = 4 * 1024 * 1024; // 4MB
        let storage = open_storage("lmdb", path_str, Some(init_size), Some(max_size), false).unwrap();
        
        // Put a massive chunk of bytes to trigger map full & growth
        let db = "grow_db";
        let large_val = vec![0u8; 800 * 1024]; // 800 KB
        
        storage.put_bytes(db, b"huge1", &large_val).unwrap();
        // This second one should definitely push it past 1MB and trigger grow_to_max
        storage.put_bytes(db, b"huge2", &large_val).unwrap();
        
        // Similarly for put_batch
        let mut batch = Vec::new();
        batch.push((b"huge3".to_vec(), Some(large_val.clone())));
        batch.push((b"huge4".to_vec(), Some(large_val.clone())));
        storage.put_batch(db, batch).unwrap();
    });
}
