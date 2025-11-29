// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md
// RandomX mining orchestrator (multi-threaded, P2WPKH chain)

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXFlag, RandomXVM};
use num_cpus;
use std::cmp::Ordering;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

fn configure_flags(
    full_mem: bool,
    large_pages: bool,
    jit: bool,
    hard_aes: bool,
    secure: bool,
) -> RandomXFlag {
    let mut flags = RandomXFlag::FLAG_DEFAULT;
    if full_mem {
        flags.insert(RandomXFlag::FLAG_FULL_MEM);
    }
    if large_pages {
        flags.insert(RandomXFlag::FLAG_LARGE_PAGES);
    }
    if jit {
        flags.insert(RandomXFlag::FLAG_JIT);
    }
    if hard_aes {
        flags.insert(RandomXFlag::FLAG_HARD_AES);
    }
    if secure && jit {
        flags.insert(RandomXFlag::FLAG_SECURE);
    }
    flags
}

fn build_vm(key: &[u8], flags: RandomXFlag) -> Result<RandomXVM, RandomXError> {
    let cache = RandomXCache::new(flags, key)?;
    let dataset = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
        Some(RandomXDataset::new(flags, cache.clone(), 0)?)
    } else {
        None
    };
    RandomXVM::new(flags, Some(cache), dataset)
}

fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return Ordering::Less;
        } else if a[i] > b[i] {
            return Ordering::Greater;
        }
    }
    Ordering::Equal
}

#[pyfunction]
#[pyo3(signature = (header_prefix, target_be, key, threads=0, full_mem=false, large_pages=false, jit=true, hard_aes=true, secure_jit=false, progress_queue=None, progress_interval_ms=None, stop_event=None))]
pub fn randomx_mine<'py>(
    py: Python<'py>,
    header_prefix: Bound<'py, PyBytes>,
    target_be: Bound<'py, PyBytes>,
    key: Bound<'py, PyBytes>,
    threads: usize,
    full_mem: bool,
    large_pages: bool,
    jit: bool,
    hard_aes: bool,
    secure_jit: bool,
    progress_queue: Option<PyObject>,
    progress_interval_ms: Option<u64>,
    stop_event: Option<PyObject>,
) -> PyResult<Option<(u32, Bound<'py, PyBytes>)>> {
    let prefix = header_prefix.as_bytes().to_vec();
    if prefix.len() != 76 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "header_prefix must be 76 bytes (header minus nonce)",
        ));
    }
    let target_bytes = target_be.as_bytes();
    if target_bytes.len() != 32 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "target must be 32 bytes (big-endian)",
        ));
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(target_bytes);

    let key_vec = key.as_bytes().to_vec();
    if key_vec.is_empty() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "key cannot be empty",
        ));
    }

    let flags = configure_flags(full_mem, large_pages, jit, hard_aes, secure_jit);
    let threads = if threads == 0 { num_cpus::get() } else { threads }.max(1);

    let signal_err: Arc<Mutex<Option<PyErr>>> = Arc::new(Mutex::new(None));

    let result = py.allow_threads({
        let signal_err = Arc::clone(&signal_err);
        move || -> Option<(u32, [u8; 32])> {
        let found = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let hash_counters: Arc<Vec<AtomicU64>> = Arc::new((0..threads).map(|_| AtomicU64::new(0)).collect());
        let result: Arc<Mutex<Option<(u32, [u8; 32])>>> = Arc::new(Mutex::new(None));

        // Optional progress reporter thread
        let progress_handle = if let Some(q_obj) = progress_queue {
            let counters = Arc::clone(&hash_counters);
            let found_local = Arc::clone(&found);
            let stop_local = Arc::clone(&stop_flag);
            let interval_ms = progress_interval_ms.unwrap_or(2_000).max(250);
            Some(thread::spawn(move || {
                let mut last_total: u64 = 0;
                let mut last_ts = Instant::now();
                loop {
                    if found_local.load(AtomicOrdering::Relaxed) || stop_local.load(AtomicOrdering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(interval_ms));
                    let now = Instant::now();
                    let mut total: u64 = 0;
                    for c in counters.iter() {
                        total = total.saturating_add(c.load(AtomicOrdering::Relaxed));
                    }
                    let dt = now.saturating_duration_since(last_ts).as_secs_f64();
                    if dt > 0.0 {
                        let delta = total.saturating_sub(last_total) as f64;
                        let hps = delta / dt;
                        Python::with_gil(|py| {
                            let _ = q_obj.call_method1(py, "put", (("TOTAL_HPS", hps),));
                        });
                    }
                    last_total = total;
                    last_ts = now;
                }
            }))
        } else {
            None
        };

        // Stop watcher: always run to process signals; also checks optional stop_event
        let stop_handle = {
            let stop_local = Arc::clone(&stop_flag);
            let found_local = Arc::clone(&found);
            let signal_err_local = Arc::clone(&signal_err);
            // Move optional event into thread
            let stop_obj = stop_event;
            Some(thread::spawn(move || {
                loop {
                    if stop_local.load(AtomicOrdering::Relaxed) || found_local.load(AtomicOrdering::Relaxed) {
                        break;
                    }
                    let should_stop = Python::with_gil(|py| -> bool {
                        if let Err(err) = py.check_signals() {
                            let mut guard = signal_err_local.lock().unwrap();
                            *guard = Some(err);
                            return true;
                        }
                        if let Some(ev_obj) = stop_obj.as_ref() {
                            match ev_obj.call_method0(py, "is_set") {
                                Ok(val) => val.is_truthy(py).unwrap_or(false),
                                Err(_) => false,
                            }
                        } else {
                            false
                        }
                    });
                    if should_stop {
                        stop_local.store(true, AtomicOrdering::Relaxed);
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }))
        };

        let mut handles = Vec::with_capacity(threads);
        for tid in 0..threads {
            let prefix_local = prefix.clone();
            let target_local = target;
            let key_local = key_vec.clone();
            let found_local = Arc::clone(&found);
            let stop_local = Arc::clone(&stop_flag);
            let counter_local = Arc::clone(&hash_counters);
            let result_local = Arc::clone(&result);
            let flags_local = flags;
            let handle = thread::spawn(move || {
                let vm = match build_vm(&key_local, flags_local) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut header = Vec::with_capacity(80);
                header.extend_from_slice(&prefix_local);
                header.extend_from_slice(&[0u8; 4]);
                let nonce_offset = header.len() - 4;

                let mut nonce: u64 = tid as u64;
                let max_nonce: u64 = u32::MAX as u64;
                let mut local_count: u64 = 0;
                while nonce <= max_nonce {
                    if found_local.load(AtomicOrdering::Relaxed) || stop_local.load(AtomicOrdering::Relaxed) {
                        break;
                    }
                    let n32 = nonce as u32;
                    header[nonce_offset..].copy_from_slice(&n32.to_le_bytes());
                    let h = match vm.calculate_hash(&header) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    local_count = local_count.saturating_add(1);
                    if local_count >= 256 {
                        if let Some(c) = counter_local.get(tid) {
                            let _ = c.fetch_add(local_count, AtomicOrdering::Relaxed);
                        }
                        local_count = 0;
                    }
                    let mut h32 = [0u8; 32];
                    h32.copy_from_slice(&h);
                    if cmp_be(&h32, &target_local) == Ordering::Less {
                        found_local.store(true, AtomicOrdering::Relaxed);
                        if let Some(c) = counter_local.get(tid) {
                            let _ = c.fetch_add(local_count, AtomicOrdering::Relaxed);
                        }
                        let mut guard = result_local.lock().unwrap();
                        *guard = Some((n32, h32));
                        break;
                    }
                    nonce = nonce.saturating_add(threads as u64);
                }
                if local_count > 0 {
                    if let Some(c) = counter_local.get(tid) {
                        let _ = c.fetch_add(local_count, AtomicOrdering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }
        for h in handles {
            let _ = h.join();
        }
        if let Some(h) = progress_handle {
            let _ = h.join();
        }
        if let Some(h) = stop_handle {
            let _ = h.join();
        }
        let final_result = result.lock().unwrap().take();
        final_result
        }
    });

    if let Some(err) = signal_err.lock().unwrap().take() {
        return Err(err);
    }

    if let Some((nonce, hash)) = result {
        return Ok(Some((nonce, PyBytes::new_bound(py, &hash))));
    }
    Ok(None)
}
