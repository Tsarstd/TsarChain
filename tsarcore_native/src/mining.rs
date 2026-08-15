// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE
// RandomX mining orchestrator (multi-threaded, P2WPKH chain)

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXFlag, RandomXVM};
use num_cpus;
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

struct SharedCache(RandomXCache);
unsafe impl Send for SharedCache {}
unsafe impl Sync for SharedCache {}

struct SharedDataset(RandomXDataset);
unsafe impl Send for SharedDataset {}
unsafe impl Sync for SharedDataset {}

fn build_shared_cache_and_dataset(
    key: &[u8],
    flags: RandomXFlag,
) -> Result<(Arc<SharedCache>, Option<Arc<SharedDataset>>), RandomXError> {
    let mut cache_flags = RandomXFlag::FLAG_DEFAULT;
    for candidate in [
        RandomXFlag::FLAG_LARGE_PAGES,
        RandomXFlag::FLAG_JIT,
        RandomXFlag::FLAG_ARGON2,
        RandomXFlag::FLAG_ARGON2_AVX2,
        RandomXFlag::FLAG_ARGON2_SSSE3,
    ] {
        if flags.contains(candidate) {
            cache_flags.insert(candidate);
        }
    }
    let cache = match RandomXCache::new(cache_flags, key) {
        Ok(c) => c,
        Err(_e) if cache_flags.contains(RandomXFlag::FLAG_LARGE_PAGES) => {
            let fallback_flags = cache_flags - RandomXFlag::FLAG_LARGE_PAGES;
            RandomXCache::new(fallback_flags, key)?
        }
        Err(e) => return Err(e),
    };
    let dataset = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
        let ds = match RandomXDataset::new(flags, cache.clone(), 0) {
            Ok(d) => d,
            Err(_e) if flags.contains(RandomXFlag::FLAG_LARGE_PAGES) => {
                let fallback_flags = flags - RandomXFlag::FLAG_LARGE_PAGES;
                RandomXDataset::new(fallback_flags, cache.clone(), 0)?
            }
            Err(e) => return Err(e),
        };
        Some(Arc::new(SharedDataset(ds)))
    } else {
        None
    };
    Ok((Arc::new(SharedCache(cache)), dataset))
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
    progress_queue: Option<Py<PyAny>>,
    progress_interval_ms: Option<u64>,
    stop_event: Option<Py<PyAny>>,
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

    let (shared_cache, shared_dataset) = py
        .detach(|| build_shared_cache_and_dataset(&key_vec, flags))
        .map_err(|e| PyErr::new::<exceptions::PyRuntimeError, _>(format!("RandomX init error: {e}")))?;

    let signal_err: Arc<Mutex<Option<PyErr>>> = Arc::new(Mutex::new(None));

    let result = py.detach({
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
            let interval_ms = progress_interval_ms.unwrap_or(500).max(100);
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
                        Python::attach(|py| {
                            let _ = q_obj.bind(py).call_method1("put", (("TOTAL_HPS", hps),));
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
            let stop_obj = stop_event;
            Some(thread::spawn(move || {
                loop {
                    if stop_local.load(AtomicOrdering::Relaxed) || found_local.load(AtomicOrdering::Relaxed) {
                        break;
                    }
                    let should_stop = Python::attach(|py| -> bool {
                        if let Err(err) = py.check_signals() {
                            let mut guard = signal_err_local.lock().unwrap();
                            *guard = Some(err);
                            return true;
                        }
                        if let Some(ev_obj) = stop_obj.as_ref() {
                            match ev_obj.bind(py).call_method0("is_set") {
                                Ok(val) => val.is_truthy().unwrap_or(false),
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
            let found_local = Arc::clone(&found);
            let stop_local = Arc::clone(&stop_flag);
            let counter_local = Arc::clone(&hash_counters);
            let result_local = Arc::clone(&result);
            let flags_local = flags;
            let cache_local = Arc::clone(&shared_cache);
            let dataset_local = shared_dataset.as_ref().map(Arc::clone);
            let handle = thread::spawn(move || {
                let vm = match RandomXVM::new(
                    flags_local,
                    Some(cache_local.0.clone()),
                    dataset_local.as_ref().map(|d| d.0.clone()),
                ) {
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
                    if h32 < target_local {
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
        return Ok(Some((nonce, PyBytes::new(py, &hash))));
    }
    Ok(None)
}
