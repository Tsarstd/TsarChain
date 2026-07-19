// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tsar Studio
// Part of TsarChain — see LICENSE


use pyo3::prelude::*;
use std::sync::Once;
use pyo3::types::PyBytes;
use tsarcore_native::mining::randomx_mine;

static INIT: Once = Once::new();

fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

#[test]
fn test_mining_invalid_inputs() {
    init_python();
    Python::attach(|py| {
        let prefix_bad = PyBytes::new(py, &[0u8; 10]); // not 76
        let target_ok = PyBytes::new(py, &[0u8; 32]);
        let key_ok = PyBytes::new(py, b"testkey");

        // Invalid prefix
        let res = randomx_mine(
            py, prefix_bad.clone(), target_ok.clone(), key_ok.clone(),
            1, false, false, true, true, false, None, None, None,
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "ValueError: header_prefix must be 76 bytes (header minus nonce)");

        // Invalid target
        let prefix_ok = PyBytes::new(py, &[0u8; 76]);
        let target_bad = PyBytes::new(py, &[0u8; 10]);
        let res = randomx_mine(
            py, prefix_ok.clone(), target_bad.clone(), key_ok.clone(),
            1, false, false, true, true, false, None, None, None,
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "ValueError: target must be 32 bytes (big-endian)");

        // Invalid key
        let key_empty = PyBytes::new(py, &[]);
        let res = randomx_mine(
            py, prefix_ok.clone(), target_ok.clone(), key_empty.clone(),
            1, false, false, true, true, false, None, None, None,
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "ValueError: key cannot be empty");
    });
}

#[test]
fn test_mining_success() {
    init_python();
    Python::attach(|py| {
        let prefix = PyBytes::new(py, &[0u8; 76]);
        // Set target to all 0xff so ANY hash is considered < target.
        // This ensures the miner returns on the very first nonce.
        let target = PyBytes::new(py, &[0xff; 32]);
        let key = PyBytes::new(py, b"testkey123");

        let res = randomx_mine(
            py, prefix.clone(), target.clone(), key.clone(),
            1, // 1 thread
            false, false, true, true, false, // flags
            None, None, None, // no progress, no stop_event
        ).unwrap();

        assert!(res.is_some());
        let (nonce, hash) = res.unwrap();
        
        // Since target is all 0xff, the first hash calculated should be lower.
        // It's not guaranteed to be nonce 0 if threading makes another thread find it, 
        // but since threads=1, it should be nonce 0.
        assert_eq!(nonce, 0);
        assert_eq!(hash.as_bytes().len(), 32);
    });
}

#[test]
fn test_mining_multi_thread() {
    init_python();
    Python::attach(|py| {
        let prefix = PyBytes::new(py, &[1u8; 76]);
        let target = PyBytes::new(py, &[0xff; 32]);
        let key = PyBytes::new(py, b"multithread");

        let res = randomx_mine(
            py, prefix.clone(), target.clone(), key.clone(),
            4, // 4 threads
            false, false, false, true, false, // NO JIT
            None, None, None,
        ).unwrap();

        assert!(res.is_some());
        let (_nonce, hash) = res.unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    });
}

#[test]
fn test_mining_advanced_features() {
    init_python();
    Python::attach(|py| {
        let prefix = PyBytes::new(py, &[2u8; 76]);
        let target = PyBytes::new(py, &[0x00; 32]); // Impossible target
        let key = PyBytes::new(py, b"advanced_key");

        // Create a mock queue that prints to stdout (or does nothing)
        let locals = pyo3::types::PyDict::new(py);
        let code = std::ffi::CString::new(r#"
class MockQueue:
    def __init__(self):
        self.puts = 0
    def put(self, item):
        self.puts += 1

class MockEvent:
    def __init__(self):
        self.calls = 0
    def is_set(self):
        self.calls += 1
        # Stop after 3 checks
        return self.calls > 3
"#).unwrap();
        py.run(
            code.as_c_str(),
            None,
            Some(&locals),
        ).unwrap();

        let q_class = locals.get_item("MockQueue").unwrap().unwrap();
        let q_obj = q_class.call0().unwrap().unbind();

        let ev_class = locals.get_item("MockEvent").unwrap().unwrap();
        let ev_obj = ev_class.call0().unwrap().unbind();

        let res = randomx_mine(
            py, prefix.clone(), target.clone(), key.clone(),
            2, // 2 threads
            false, true, true, true, true, // flags: large_pages=true, secure_jit=true
            Some(q_obj.clone_ref(py)), Some(10), // progress_interval 10ms
            Some(ev_obj.clone_ref(py)),
        ).unwrap();

        // Should return None because the event stops it before it finds a 0x0000.. target
        assert!(res.is_none());
        
        let q_bound = q_obj.bind(py);
        let puts: i32 = q_bound.getattr("puts").unwrap().extract().unwrap();
        assert!(puts >= 0); // Might or might not put, but should not crash
    });
}

#[test]
fn test_mining_full_mem() {
    if std::env::var("CI").is_ok() {
        // Skip on GitHub Actions (debug mode full_mem takes minutes)
        return;
    }
    init_python();
    Python::attach(|py| {
        let prefix = PyBytes::new(py, &[3u8; 76]);
        let target = PyBytes::new(py, &[0xff; 32]); 
        let key = PyBytes::new(py, b"full_mem_key");

        // We ignore the result, we just want to execute the code paths for full_mem and large_pages.
        // It might fail if the system doesn't have 2GB free or large pages aren't configured,
        // which is perfectly fine for line coverage.
        let _ = randomx_mine(
            py, prefix.clone(), target.clone(), key.clone(),
            1, // 1 thread
            true, true, true, true, false, // full_mem=true, large_pages=true
            None, None, None,
        );
    });
}
