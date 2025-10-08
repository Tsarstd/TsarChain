// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md
// Refs: BIP143; BIP141; CompactSize; Merkle; libsecp256k1; LowS-Policy

//! == Install ==
//! cd tsarcore_native
//! maturin develop --release

//! -- (Optional)
//! maturin develop --release --features parallel

//! == Uninstall ==
//! pip uninstall -y tsarcore_native
//! cargo clean

use pyo3::sync::GILOnceCell;
use std::time::Instant;
use pyo3::{Py};
use pyo3::prelude::*;
use pyo3::exceptions;
use pyo3::types::{PyModule, PyAny, PyBytes, PyIterator, PyList, PyTuple};
use pyo3::{Bound, PyErr};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, Message, PublicKey};
use secp256k1::ecdsa::Signature;


// ---------------------
// Logger (from Python)
// ---------------------
static PY_LOGGER: GILOnceCell<Py<PyAny>> = GILOnceCell::new();

#[pyfunction]
fn set_py_logger(logger: Bound<'_, PyAny>) -> PyResult<()> {
    Python::with_gil(|py| {
        let _ = PY_LOGGER.set(py, logger.unbind());
        Ok(())
    })
}

fn py_logger_call(level: &str, msg: &str) {
    Python::with_gil(|py| {
        if let Some(handle) = PY_LOGGER.get(py) {
            let logger = handle.bind(py);
            let _ = logger.call_method(level, (msg,), None);
        }
    });
}

// Shortcut level
#[inline] fn log_trace(msg: &str)    { py_logger_call("trace", msg); }
#[inline] fn log_debug(msg: &str)    { py_logger_call("debug", msg); }
#[inline] fn log_info(msg: &str)     { py_logger_call("info",  msg); }
#[inline] fn log_warning(msg: &str)  { py_logger_call("warning", msg); }
//#[inline] fn log_error(msg: &str)    { py_logger_call("error", msg); }
//#[inline] fn log_critical(msg: &str) { py_logger_call("critical", msg); }



// ---------------------
// Script / Sigops utils
// ---------------------
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51; // .. OP_16 (0x60)
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;


fn small_int(op: u8) -> Option<u32> {
    if op == OP_0 { return Some(0); }
    if (OP_1..=0x60).contains(&op) {
        return Some((op - OP_1 + 1) as u32);
    }
    log_trace(&format!("small_int: unknown opcode 0x{:x}", op));
    None
}

fn parse_pubkey_any(bytes: &[u8]) -> Option<PublicKey> {
    if let Ok(pk) = PublicKey::from_slice(bytes) {
        return Some(pk);
    }
    if bytes.len() == 64 {
        let mut v = Vec::with_capacity(65);
        v.push(0x04);
        v.extend_from_slice(bytes);
        if let Ok(pk) = PublicKey::from_slice(&v) {
            return Some(pk);
        }
    }
    log_warning(&format!("parse_pubkey_any: invalid public key bytes: {:?}", bytes));
    None
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}


fn parse_ops(script: &[u8]) -> Vec<(Option<u8>, bool, usize)> {
    let mut v = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        if op <= 0x4b {
            let n = op as usize;
            if i + n > script.len() {
                v.push((None, true, script.len().saturating_sub(i)));
                break;
            }
            v.push((None, true, n));
            i += n;
        } else if op == OP_PUSHDATA1 {
            if i >= script.len() { break; }
            let n = script[i] as usize;
            i += 1;
            if i + n > script.len() { break; }
            v.push((None, true, n));
            i += n;
        } else if op == OP_PUSHDATA2 {
            if i + 2 > script.len() { break; }
            let n = u16::from_le_bytes([script[i], script[i+1]]) as usize;
            i += 2;
            if i + n > script.len() { break; }
            v.push((None, true, n));
            i += n;
        } else if op == OP_PUSHDATA4 {
            if i + 4 > script.len() { break; }
            let n = u32::from_le_bytes([script[i], script[i+1], script[i+2], script[i+3]]) as usize;
            i += 4;
            if i + n > script.len() { break; }
            v.push((None, true, n));
            i += n;
        } else {
            v.push((Some(op), false, 0));
        }
    }
    log_info(&format!("parse_ops: parsed {} ops from script", v.len()));
    v
}

#[pyfunction]
fn count_sigops(script: &[u8]) -> PyResult<u32> {
    let ops = parse_ops(script);
    let mut total: u32 = 0;
    for (idx, (maybe_op, _is_data, _len)) in ops.iter().enumerate() {
        if let Some(op) = maybe_op {
            match *op {
                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    total = total.saturating_add(1);
                }
                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    // cari small-int terdekat sebelumnya (jika ada)
                    let mut n: Option<u32> = None;
                    let mut j: isize = idx as isize - 1;
                    while j >= 0 {
                        if let Some(prev) = ops[j as usize].0 {
                            if let Some(si) = small_int(prev) {
                                n = Some(si);
                                break;
                            }
                        }
                        j -= 1;
                    }
                    let add = n.unwrap_or(20).min(20);
                    total = total.saturating_add(add as u32);
                }
                _ => {}
            }
        }
    }
    log_info(&format!("sigops count: {}", total));
    Ok(total)
}

#[pyfunction]
fn hash256<'py>(py: Python<'py>, data: &'py [u8]) -> PyResult<Bound<'py, PyBytes>> {
    let h = sha256d(data);
    log_debug(&format!("hash256: input len={}, output={:x?}", data.len(), h));
    Ok(PyBytes::new_bound(py, &h))
}

#[pyfunction]
fn hash160<'py>(py: Python<'py>, data: &'py [u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(&sha);
    log_debug(&format!("hash160: input len={}, output={:x?}", data.len(), ripe));
    Ok(PyBytes::new_bound(py, &ripe))
}

// ---------------------
// ECDSA verify (low-S)
// ---------------------
#[pyfunction]
fn secp_verify_der_low_s(pubkey: &[u8], digest32: &[u8], der_sig: &[u8]) -> PyResult<bool> {
    use secp256k1::{Secp256k1, Message, ecdsa::Signature};

    if digest32.len() != 32 {
        return Err(PyErr::new::<exceptions::PyValueError, _>("digest32 must be 32 bytes"));
    }

    // parse pubkey (33B compressed atau 65B uncompressed)
    let pk = match parse_pubkey_any(pubkey) {
        Some(pk) => pk,
        None => return Ok(false),
    };

    // parse DER signature (strict)
    let sig = match Signature::from_der(der_sig) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    // enforce low-S: normalisasi in-place lalu cek apakah berubah
    let mut norm = sig;
    let orig = sig;
    norm.normalize_s();
    if norm != orig {
        return Ok(false);
    }

    let msg = match Message::from_digest_slice(digest32) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    let secp = Secp256k1::verification_only();
    log_info(&format!("Verifying message: {:?}", msg));
    Ok(secp.verify_ecdsa(&msg, &norm, &pk).is_ok())
}

// ------------------------
// BIP143 SIGHASH (SegWit)
// ------------------------

mod bip143_native {
    use pyo3::{exceptions, PyErr};
    use sha2::{Digest, Sha256};

    use crate::log_info;

    const SIGHASH_ALL: u32 = 0x01;

    #[inline]
    fn sha256d(bytes: &[u8]) -> [u8; 32] {
        let first = Sha256::digest(bytes);
        let second = Sha256::digest(&first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }

    fn read_bytes<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], PyErr> {
        if *i + n > data.len() {
            return Err(PyErr::new::<exceptions::PyValueError, _>("read OOB"));
        }
        let s = &data[*i..*i + n];
        *i += n;
        Ok(s)
    }

    fn read_varint(data: &[u8], i: &mut usize) -> Result<u64, PyErr> {
        if *i >= data.len() {
            return Err(PyErr::new::<exceptions::PyValueError, _>("varint OOB"));
        }
        let b = data[*i];
        *i += 1;
        match b {
            x @ 0x00..=0xfc => Ok(x as u64),
            0xfd => {
                if *i + 2 > data.len() {
                    return Err(PyErr::new::<exceptions::PyValueError, _>("varint OOB"));
                }
                let v = u16::from_le_bytes([data[*i], data[*i + 1]]);
                *i += 2;
                Ok(v as u64)
            }
            0xfe => {
                if *i + 4 > data.len() {
                    return Err(PyErr::new::<exceptions::PyValueError, _>("varint OOB"));
                }
                let v =
                    u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
                *i += 4;
                Ok(v as u64)
            }
            0xff => {
                if *i + 8 > data.len() {
                    return Err(PyErr::new::<exceptions::PyValueError, _>("varint OOB"));
                }
                let v = u64::from_le_bytes([
                    data[*i],
                    data[*i + 1],
                    data[*i + 2],
                    data[*i + 3],
                    data[*i + 4],
                    data[*i + 5],
                    data[*i + 6],
                    data[*i + 7],
                ]);
                *i += 8;
                Ok(v)
            }
        }
    }

    struct TxView<'a> {
        version: i32,
        inputs: Vec<(&'a [u8; 32], u32, u32)>, // (prev_txid_le, vout, sequence)
        outputs_ser: Vec<Vec<u8>>,             // serialized outputs (value||varint||script)
        locktime: u32,
    }

    fn parse_tx_view(data: &[u8]) -> Result<TxView<'_>, PyErr> {
        let mut i = 0usize;

        // version
        let ver_b = read_bytes(data, &mut i, 4)?;
        let version = i32::from_le_bytes([ver_b[0], ver_b[1], ver_b[2], ver_b[3]]);

        // segwit marker/flag 0x00 0x01
        let mut segwit = false;
        if i + 2 <= data.len() && data[i] == 0x00 && data[i + 1] == 0x01 {
            segwit = true;
            i += 2;
        }

        // inputs
        let vin = read_varint(data, &mut i)? as usize;
        let mut inputs = Vec::with_capacity(vin);
        for _ in 0..vin {
            let prev = read_bytes(data, &mut i, 32)?;
            let prev_arr = <&[u8; 32]>::try_from(prev)
                .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("bad prev txid"))?;
            let vout_b = read_bytes(data, &mut i, 4)?;
            let vout = u32::from_le_bytes([vout_b[0], vout_b[1], vout_b[2], vout_b[3]]);
            let script_len = read_varint(data, &mut i)? as usize;
            let _script = read_bytes(data, &mut i, script_len)?; // scriptsig (unused)
            let seq_b = read_bytes(data, &mut i, 4)?;
            let seq = u32::from_le_bytes([seq_b[0], seq_b[1], seq_b[2], seq_b[3]]);
            inputs.push((prev_arr, vout, seq));
        }

        // outputs
        let vout = read_varint(data, &mut i)? as usize;
        let mut outputs_ser = Vec::with_capacity(vout);
        for _ in 0..vout {
            let mut buf = Vec::with_capacity(8 + 40);
            let val_b = read_bytes(data, &mut i, 8)?;
            buf.extend_from_slice(val_b);
            let sl = read_varint(data, &mut i)?;
            if sl < 0xfd {
                buf.push(sl as u8);
            } else if sl <= 0xffff {
                buf.push(0xfd);
                buf.extend_from_slice(&(sl as u16).to_le_bytes());
            } else if sl <= 0xffff_ffff {
                buf.push(0xfe);
                buf.extend_from_slice(&(sl as u32).to_le_bytes());
            } else {
                buf.push(0xff);
                buf.extend_from_slice(&(sl as u64).to_le_bytes());
            }
            let script = read_bytes(data, &mut i, sl as usize)?;
            buf.extend_from_slice(script);
            outputs_ser.push(buf);
        }

        // skip witness stacks (if segwit)
        if segwit {
            for _ in 0..vin {
                let n_stack = read_varint(data, &mut i)? as usize;
                for _ in 0..n_stack {
                    let l = read_varint(data, &mut i)? as usize;
                    let _w = read_bytes(data, &mut i, l)?;
                }
            }
        }

        // locktime
        let lock_b = read_bytes(data, &mut i, 4)?;
        let locktime = u32::from_le_bytes([lock_b[0], lock_b[1], lock_b[2], lock_b[3]]);

        Ok(TxView {
            version,
            inputs,
            outputs_ser,
            locktime,
        })
    }


    pub fn compute_sighash(
        tx_bytes: &[u8],
        input_index: u32,
        script_code: &[u8],
        value_sat: u64,
        sighash_type: u32,
    ) -> Result<[u8; 32], PyErr> {
        // TESTNET fokus: SIGHASH_ALL saja (yang umum P2WPKH)
        if (sighash_type & 0x1f) != SIGHASH_ALL {
            return Err(PyErr::new::<exceptions::PyNotImplementedError, _>(
                "Only SIGHASH_ALL supported natively; use Python fallback for others",
            ));
        }

        let tx = parse_tx_view(tx_bytes)?;
        let idx = input_index as usize;
        if idx >= tx.inputs.len() {
            return Err(PyErr::new::<exceptions::PyValueError, _>(
                "input_index out of range",
            ));
        }

        // hashPrevouts
        let mut prevouts_cat = Vec::with_capacity(tx.inputs.len() * 36);
        for (prev, vout, _) in &tx.inputs {
            prevouts_cat.extend_from_slice(prev.as_slice()); // little-endian txid as serialized
            prevouts_cat.extend_from_slice(&vout.to_le_bytes());
        }
        let hash_prevouts = sha256d(&prevouts_cat);

        // hashSequence
        let mut seq_cat = Vec::with_capacity(tx.inputs.len() * 4);
        for (_, _, seq) in &tx.inputs {
            seq_cat.extend_from_slice(&seq.to_le_bytes());
        }
        let hash_sequence = sha256d(&seq_cat);

        // hashOutputs (semua)
        let mut outs_cat = Vec::new();
        for o in &tx.outputs_ser {
            outs_cat.extend_from_slice(o);
        }
        let hash_outputs = sha256d(&outs_cat);

        // outpoint current input
        let (prev, vout, seq) = tx.inputs[idx];

        // preimage
        let mut pre = Vec::with_capacity(
            4 + 32 + 32 + 36 + (script_code.len() + 9) + 8 + 4 + 32 + 4 + 4,
        );
        pre.extend_from_slice(&tx.version.to_le_bytes());
        pre.extend_from_slice(&hash_prevouts);
        pre.extend_from_slice(&hash_sequence);
        pre.extend_from_slice(prev.as_slice());
        pre.extend_from_slice(&vout.to_le_bytes());

        // script_code (varint + bytes)
        let sl = script_code.len() as u64;
        if sl < 0xfd {
            pre.push(sl as u8);
        } else if sl <= 0xffff {
            pre.push(0xfd);
            pre.extend_from_slice(&(sl as u16).to_le_bytes());
        } else if sl <= 0xffff_ffff {
            pre.push(0xfe);
            pre.extend_from_slice(&(sl as u32).to_le_bytes());
        } else {
            pre.push(0xff);
            pre.extend_from_slice(&(sl as u64).to_le_bytes());
        }
        pre.extend_from_slice(script_code);

        pre.extend_from_slice(&value_sat.to_le_bytes());
        pre.extend_from_slice(&seq.to_le_bytes());
        pre.extend_from_slice(&hash_outputs);
        pre.extend_from_slice(&tx.locktime.to_le_bytes());
        pre.extend_from_slice(&sighash_type.to_le_bytes());

        log_info(&format!(
            "sighash_bip143: input_index={}, script_code_len={}, value_sat={}, sighash_type={}",
            input_index,
            script_code.len(),
            value_sat,
            sighash_type
        ));
        Ok(sha256d(&pre))
    }
}

#[pyfunction]
#[pyo3(signature=(tx_bytes, input_index, script_code, value_sat, sighash_type))]
fn sighash_bip143<'py>(
    py: Python<'py>,
    tx_bytes: &[u8],
    input_index: u32,
    script_code: &[u8],
    value_sat: u64,
    sighash_type: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let digest = bip143_native::compute_sighash(
        tx_bytes, input_index, script_code, value_sat, sighash_type
    )?;
    Ok(PyBytes::new_bound(py, &digest))
}


// -----------------------------------------------------
// Batch verify ECDSA (DER) with optional low-S enforce
// -----------------------------------------------------
#[pyfunction]
#[pyo3(signature=(triples, enforce_low_s=true, parallel=true))]
fn secp_verify_der_low_s_many<'py>(
    py: Python<'py>,
    triples: Bound<'py, PyAny>,
    enforce_low_s: bool,
    parallel: bool,
) -> PyResult<Bound<'py, PyList>> {
    let t0 = Instant::now();
    let ctx = Secp256k1::verification_only();
    let iter = PyIterator::from_bound_object(&triples)?;

    let mut tasks: Vec<(Vec<u8>, [u8; 32], Vec<u8>)> = Vec::new();
    for item in iter {
        let obj: Bound<'py, PyAny> = item?;
        let t: &Bound<'py, PyTuple> = obj.downcast()?;
        if t.len() != 3 {
            return Err(PyErr::new::<exceptions::PyValueError, _>(
                "each item must be (pubkey, digest32, der_sig)",
            ));
        }
        let pk: Vec<u8> = t.get_item(0)?.extract()?;
        let dg: Vec<u8> = t.get_item(1)?.extract()?;
        let sg: Vec<u8> = t.get_item(2)?.extract()?;
        if dg.len() != 32 {
            return Err(PyErr::new::<exceptions::PyValueError, _>(
                "digest32 must be 32 bytes",
            ));
        }
        let mut d32 = [0u8; 32];
        d32.copy_from_slice(&dg);
        tasks.push((pk, d32, sg));
    }

    let use_parallel = cfg!(feature = "parallel") && parallel;

    let verify_one = |pk_bytes: &Vec<u8>, d32: &[u8; 32], sig_der: &Vec<u8>| -> bool {
        let msg = match Message::from_digest_slice(d32) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let pk = match parse_pubkey_any(pk_bytes) {
            Some(p) => p,
            None => return false,
        };
        let sig = match Signature::from_der(sig_der) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if enforce_low_s {
            let mut s2 = sig;
            s2.normalize_s();
            if s2 != sig {
                return false;
            }
            ctx.verify_ecdsa(&msg, &s2, &pk).is_ok()
        } else {
            ctx.verify_ecdsa(&msg, &sig, &pk).is_ok()
        }
    };

    let results: Vec<bool> = if use_parallel {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            tasks.par_iter().map(|(pk,d32,sg)| verify_one(pk,d32,sg)).collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            tasks.iter().map(|(pk,d32,sg)| verify_one(pk,d32,sg)).collect()
        }
    } else {
        tasks.iter().map(|(pk,d32,sg)| verify_one(pk,d32,sg)).collect()
    };

    // === Logging ===
    let total = results.len();
    let ok = results.iter().filter(|b| **b).count();
    let fail = total.saturating_sub(ok);
    let dur_ms = t0.elapsed().as_millis();

    log_debug(&format!(
        "verify_many items={} ok={} fail={} parallel={} dur_ms={}",
        total, ok, fail, use_parallel, dur_ms
    ));

    Ok(PyList::new_bound(py, results))
}

// ---------------------
// Merkle root (double)
// ---------------------

#[pyfunction]
fn merkle_root<'py>(py: Python<'py>, txids_any: Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let t0 = Instant::now();
    let iter = PyIterator::from_bound_object(&txids_any)?;
    let mut layer: Vec<[u8; 32]> = Vec::new();

    for item in iter {
        let obj: Bound<'py, PyAny> = item?;
        let b: &Bound<'py, PyBytes> = obj.downcast()?;
        let raw = b.as_bytes();
        if raw.len() != 32 {
            return Err(PyErr::new::<exceptions::PyValueError, _>("txid must be 32 bytes"));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(raw);
        layer.push(d);
    }

    if layer.is_empty() {
        return Ok(PyBytes::new_bound(py, &[0u8; 32]));
    }
    if layer.len() == 1 {
        return Ok(PyBytes::new_bound(py, &layer[0]));
    }

    let leaves = layer.len();
    let mut rounds: usize = 0;
    let mut dupes: usize = 0;

    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0usize;
        while i < layer.len() {
            let left = layer[i];
            let right;
            if i + 1 < layer.len() {
                right = layer[i + 1];
            } else {
                right = layer[i];
                dupes += 1;
            }
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&left);
            cat[32..].copy_from_slice(&right);
            let h = sha256d(&cat);
            next.push(h);
            i += 2;
        }
        layer = next;
        rounds += 1;
    }

    let dur_ms = t0.elapsed().as_millis();

    log_debug(&format!(
        "merkle_root leaves={} rounds={} dupes={} dur_ms={}",
        leaves, rounds, dupes, dur_ms
    ));

    Ok(PyBytes::new_bound(py, &layer[0]))
}


// ---------------
// Module binding
// ---------------
#[pymodule]
fn tsarcore_native(_py: Python<'_>, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(count_sigops, m)?)?;
    m.add_function(wrap_pyfunction!(secp_verify_der_low_s, m)?)?;
    m.add_function(wrap_pyfunction!(sighash_bip143, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root, m)?)?;
    m.add_function(wrap_pyfunction!(hash256, m)?)?;
    m.add_function(wrap_pyfunction!(hash160, m)?)?;
    m.add_function(wrap_pyfunction!(secp_verify_der_low_s_many, m)?)?;
    m.add_function(wrap_pyfunction!(set_py_logger, m)?)?;
    Ok(())
}
