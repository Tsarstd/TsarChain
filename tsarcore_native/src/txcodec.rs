// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md
// Refs: BIP141; BIP143; CompactSize; txid/wtxid

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyList, PyTuple};
use sha2::{Digest, Sha256};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use ripemd::Ripemd160;

fn encode_varint(v: usize, out: &mut Vec<u8>) {
    let v64 = v as u64;
    if v64 < 0xfd {
        out.push(v64 as u8);
    } else if v64 <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v64 as u16).to_le_bytes());
    } else if v64 <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v64 as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&v64.to_le_bytes());
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn hash160_bytes(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn parse_input_tuple(t: &Bound<'_, PyTuple>) -> PyResult<(Vec<u8>, u32, u32, Vec<u8>, Vec<Vec<u8>>)> {
    if t.len() < 4 {
        return Err(PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_arity"));
    }
    let prev_txid_item = t
        .get_item(0)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_txid"))?;
    let prev_txid = prev_txid_item
        .downcast::<PyBytes>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_txid_not_bytes"))?;
    let prev_raw = prev_txid.as_bytes();
    if prev_raw.len() != 32 {
        return Err(PyErr::new::<exceptions::PyValueError, _>("tx_input_txid_length"));
    }
    let vout: u32 = t
        .get_item(1)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_vout"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_invalid_vout"))?;
    let seq: u32 = t
        .get_item(2)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_sequence"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_invalid_sequence"))?;
    let (script_sig, wit_any) = if t.len() >= 5 {
        let ss_any = t
            .get_item(3)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_scriptsig"))?;
        let ss_bytes = if let Ok(b) = ss_any.downcast::<PyBytes>() {
            b.as_bytes().to_vec()
        } else if let Ok(b) = ss_any.downcast::<PyByteArray>() {
            b.to_vec()
        } else {
            return Err(PyErr::new::<exceptions::PyValueError, _>("tx_input_scriptsig_not_bytes"));
        };
        let wit = t
            .get_item(4)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_witness"))?;
        (ss_bytes, wit)
    } else {
        let wit = t
            .get_item(3)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_witness"))?;
        (Vec::new(), wit)
    };
    let wit_list = wit_any
        .downcast::<PyList>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_witness_not_list"))?;
    let mut wit_vec = Vec::with_capacity(wit_list.len());
    for item in wit_list {
        let b = item
            .downcast::<PyBytes>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("witness_not_bytes"))?;
        wit_vec.push(b.as_bytes().to_vec());
    }
    Ok((prev_raw.to_vec(), vout, seq, script_sig, wit_vec))
}

fn parse_output_tuple(t: &Bound<'_, PyTuple>) -> PyResult<(u64, Vec<u8>)> {
    if t.len() < 2 {
        return Err(PyErr::new::<exceptions::PyValueError, _>("tx_output_tuple_arity"));
    }
    let amt: u64 = t
        .get_item(0)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_output_tuple_amount"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_output_invalid_amount"))?;
    let spk_item = t
        .get_item(1)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_output_tuple_script"))?;
    let spk = spk_item
        .downcast::<PyBytes>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_output_script_not_bytes"))?;
    Ok((amt, spk.as_bytes().to_vec()))
}

fn parse_compact_tx<'py>(
    tx: &Bound<'py, PyTuple>,
) -> PyResult<(i32, u32, Vec<(Vec<u8>, u32, u32, Vec<u8>, Vec<Vec<u8>>)>, Vec<(u64, Vec<u8>)>)> {
    if tx.len() < 6 {
        return Err(PyErr::new::<exceptions::PyValueError, _>("tx_tuple_arity"));
    }
    let ver: i32 = tx
        .get_item(0)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_version"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_invalid_version"))?;
    let lock: u32 = tx
        .get_item(1)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_locktime"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_invalid_locktime"))?;
    let inputs_any = tx
        .get_item(2)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_inputs"))?;
    let inputs_list = inputs_any
        .downcast::<PyList>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_inputs_not_list"))?;
    let mut inputs = Vec::with_capacity(inputs_list.len());
    for it in inputs_list {
        let t = it
            .downcast::<PyTuple>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_not_tuple"))?;
        inputs.push(parse_input_tuple(&t)?);
    }
    let outputs_any = tx
        .get_item(3)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_outputs"))?;
    let outputs_list = outputs_any
        .downcast::<PyList>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_outputs_not_list"))?;
    let mut outputs = Vec::with_capacity(outputs_list.len());
    for ot in outputs_list {
        let t = ot
            .downcast::<PyTuple>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_output_not_tuple"))?;
        outputs.push(parse_output_tuple(&t)?);
    }
    Ok((ver, lock, inputs, outputs))
}

fn serialize_compact_inner(
    version: i32,
    locktime: u32,
    inputs: &[(Vec<u8>, u32, u32, Vec<u8>, Vec<Vec<u8>>)],
    outputs: &[(u64, Vec<u8>)],
    include_witness: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + inputs.len() * 60 + outputs.len() * 40);
    buf.extend_from_slice(&version.to_le_bytes());
    let has_wit = include_witness && inputs.iter().any(|(_, _, _, _, wit)| !wit.is_empty());
    if has_wit {
        buf.push(0x00);
        buf.push(0x01);
    }
    encode_varint(inputs.len(), &mut buf);
    for (prev_txid, vout, seq, script_sig, _wit) in inputs {
        let mut prev_le = prev_txid.clone();
        prev_le.reverse();
        buf.extend_from_slice(&prev_le);
        buf.extend_from_slice(&vout.to_le_bytes());
        encode_varint(script_sig.len(), &mut buf);
        buf.extend_from_slice(script_sig);
        buf.extend_from_slice(&seq.to_le_bytes());
    }
    encode_varint(outputs.len(), &mut buf);
    for (amt, spk) in outputs {
        buf.extend_from_slice(&amt.to_le_bytes());
        encode_varint(spk.len(), &mut buf);
        buf.extend_from_slice(spk);
    }
    if has_wit {
        for (_, _, _, _, wit) in inputs {
            encode_varint(wit.len(), &mut buf);
            for w in wit {
                encode_varint(w.len(), &mut buf);
                buf.extend_from_slice(w);
            }
        }
    }
    buf.extend_from_slice(&locktime.to_le_bytes());
    buf
}

#[pyfunction]
#[pyo3(signature = (tx_tuple, include_witness=true))]
pub fn serialize_tx_compact<'py>(
    py: Python<'py>,
    tx_tuple: Bound<'py, PyTuple>,
    include_witness: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let (ver, lock, inputs, outputs) = parse_compact_tx(&tx_tuple)?;
    let raw = serialize_compact_inner(ver, lock, &inputs, &outputs, include_witness);
    Ok(PyBytes::new_bound(py, &raw))
}

#[pyfunction]
pub fn txid_from_compact<'py>(
    py: Python<'py>,
    tx_tuple: Bound<'py, PyTuple>,
) -> PyResult<Bound<'py, PyBytes>> {
    let (ver, lock, inputs, outputs) = parse_compact_tx(&tx_tuple)?;
    let raw = serialize_compact_inner(ver, lock, &inputs, &outputs, false);
    let h = sha256d(&raw);
    Ok(PyBytes::new_bound(py, &h))
}

#[pyfunction]
pub fn wtxid_from_compact<'py>(
    py: Python<'py>,
    tx_tuple: Bound<'py, PyTuple>,
) -> PyResult<Bound<'py, PyBytes>> {
    let (ver, lock, inputs, outputs) = parse_compact_tx(&tx_tuple)?;
    let raw = serialize_compact_inner(ver, lock, &inputs, &outputs, true);
    let h = sha256d(&raw);
    Ok(PyBytes::new_bound(py, &h))
}

#[derive(Clone)]
struct TxLimits {
    coinbase_maturity: u64,
    max_sigops_per_tx: u32,
    max_tx_vsize: u64,
    min_tx_vsize: u64,
    max_tx_weight: u64,
    min_tx_weight: u64,
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    enforce_low_s: bool,
}

fn parse_validation_opts(opts: &Bound<'_, PyAny>) -> PyResult<TxLimits> {
    let dict = opts
        .downcast::<pyo3::types::PyDict>()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("opts_not_dict"))?;

    fn read_u64(dict: &Bound<'_, pyo3::types::PyDict>, key: &str, err: &str) -> PyResult<u64> {
        let err_owned = err.to_string();
        let item = dict
            .get_item(key)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        let val = item.ok_or_else(|| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        val.extract().map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))
    }
    fn read_u32(dict: &Bound<'_, pyo3::types::PyDict>, key: &str, err: &str) -> PyResult<u32> {
        let err_owned = err.to_string();
        let item = dict
            .get_item(key)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        let val = item.ok_or_else(|| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        val.extract().map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))
    }
    fn read_usize(dict: &Bound<'_, pyo3::types::PyDict>, key: &str, err: &str) -> PyResult<usize> {
        let err_owned = err.to_string();
        let item = dict
            .get_item(key)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        let val = item.ok_or_else(|| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))?;
        val.extract().map_err(|_| PyErr::new::<exceptions::PyValueError, _>(err_owned.clone()))
    }

    let enforce_low_s = match dict.get_item("enforce_low_s") {
        Ok(Some(v)) => v
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("opts_invalid_enforce_low_s"))?,
        _ => true,
    };

    Ok(TxLimits {
        coinbase_maturity: read_u64(&dict, "coinbase_maturity", "opts_invalid_coinbase_maturity")?,
        max_sigops_per_tx: read_u32(&dict, "max_sigops_per_tx", "opts_invalid_max_sigops_per_tx")?,
        max_tx_vsize: read_u64(&dict, "max_tx_vsize", "opts_invalid_max_tx_vsize")?,
        min_tx_vsize: read_u64(&dict, "min_tx_vsize", "opts_invalid_min_tx_vsize")?,
        max_tx_weight: read_u64(&dict, "max_tx_weight", "opts_invalid_max_tx_weight")?,
        min_tx_weight: read_u64(&dict, "min_tx_weight", "opts_invalid_min_tx_weight")?,
        max_tx_inputs: read_usize(&dict, "max_tx_inputs", "opts_invalid_max_tx_inputs")?,
        max_tx_outputs: read_usize(&dict, "max_tx_outputs", "opts_invalid_max_tx_outputs")?,
        enforce_low_s,
    })
}

#[pyfunction]
#[pyo3(signature = (tx_tuple, input_index, script_code, value_sat, sighash_type))]
pub fn sighash_bip143_compact<'py>(
    py: Python<'py>,
    tx_tuple: Bound<'py, PyTuple>,
    input_index: u32,
    script_code: &[u8],
    value_sat: u64,
    sighash_type: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    const SIGHASH_ALL: u32 = 0x01;
    if (sighash_type & 0x1f) != SIGHASH_ALL || (sighash_type & 0x80) != 0 {
        return Err(PyErr::new::<exceptions::PyNotImplementedError, _>(
            "Only SIGHASH_ALL (no ANYONECANPAY) supported for compact",
        ));
    }
    let (ver, lock, inputs, outputs) = parse_compact_tx(&tx_tuple)?;
    let idx = input_index as usize;
    if idx >= inputs.len() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "input_index out of range",
        ));
    }

    let mut prevouts_cat = Vec::with_capacity(inputs.len() * 36);
    let mut seq_cat = Vec::with_capacity(inputs.len() * 4);
    for (prev, vout, seq, _ss, _) in &inputs {
        let mut prev_le = prev.clone();
        prev_le.reverse();
        prevouts_cat.extend_from_slice(&prev_le);
        prevouts_cat.extend_from_slice(&vout.to_le_bytes());
        seq_cat.extend_from_slice(&seq.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_cat);
    let hash_sequence = sha256d(&seq_cat);

    let mut outs_cat = Vec::new();
    for (amt, spk) in &outputs {
        outs_cat.extend_from_slice(&amt.to_le_bytes());
        encode_varint(spk.len(), &mut outs_cat);
        outs_cat.extend_from_slice(spk);
    }
    let hash_outputs = sha256d(&outs_cat);

    let (prev_txid, vout, seq, _ss, _wit) = &inputs[idx];
    let mut preimage = Vec::with_capacity(156 + script_code.len());
    preimage.extend_from_slice(&ver.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    let mut prev_le = prev_txid.clone();
    prev_le.reverse();
    preimage.extend_from_slice(&prev_le);
    preimage.extend_from_slice(&vout.to_le_bytes());
    encode_varint(script_code.len(), &mut preimage);
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&value_sat.to_le_bytes());
    preimage.extend_from_slice(&seq.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&lock.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    let digest = sha256d(&preimage);
    Ok(PyBytes::new_bound(py, &digest))
}

#[pyfunction]
#[pyo3(signature = (tx_tuple, utxo_items, spend_height, opts))]
pub fn validate_tx_p2wpkh_compact<'py>(
    _py: Python<'py>,
    tx_tuple: Bound<'py, PyTuple>,
    utxo_items: Bound<'py, PyList>,
    spend_height: u64,
    opts: Bound<'py, PyAny>,
) -> PyResult<(bool, Option<String>, Option<u64>)> {
    // parse opts + tx (compact)
    let limits = parse_validation_opts(&opts)?;
    let (ver, lock, inputs, outputs) = parse_compact_tx(&tx_tuple)?;
    let base_raw = serialize_compact_inner(ver, lock, &inputs, &outputs, false);
    let total_raw = serialize_compact_inner(ver, lock, &inputs, &outputs, true);
    let base_size = base_raw.len() as u64;
    let total_size = total_raw.len() as u64;
    let weight = base_size.saturating_mul(3).saturating_add(total_size);
    let vsize = (weight + 3) / 4;
    let vin_count = inputs.len();
    let vout_count = outputs.len();

    if vsize > limits.max_tx_vsize {
        return Ok((false, Some("tx_vsize_exceeds_limit".to_string()), None));
    }
    if vsize < limits.min_tx_vsize {
        return Ok((false, Some("tx_vsize_below_min".to_string()), None));
    }
    if weight > limits.max_tx_weight {
        return Ok((false, Some("tx_weight_exceeds_limit".to_string()), None));
    }
    if weight < limits.min_tx_weight {
        return Ok((false, Some("tx_weight_below_min".to_string()), None));
    }
    if vin_count > limits.max_tx_inputs {
        return Ok((false, Some("tx_inputs_exceed_limit".to_string()), None));
    }
    if vout_count > limits.max_tx_outputs {
        return Ok((false, Some("tx_outputs_exceed_limit".to_string()), None));
    }

    if inputs.is_empty() {
        return Ok((false, Some("missing_inputs".to_string()), None));
    }
    if outputs.is_empty() {
        return Ok((false, Some("missing_outputs".to_string()), None));
    }
    let is_coinbase: bool = tx_tuple
        .get_item(5)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_coinbase"))?
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_coinbase_invalid"))?;
    if is_coinbase {
        return Ok((false, Some("coinbase_in_mempool".to_string()), None));
    }

    // parse utxo items into map
    use std::collections::HashMap;
    #[derive(Clone)]
    struct UtxoEntry {
        amount: u64,
        spk: Vec<u8>,
        is_coinbase: bool,
        height: i64,
    }
    let mut utxo_map: HashMap<(Vec<u8>, u32), UtxoEntry> = HashMap::with_capacity(utxo_items.len());
    for item in utxo_items {
        let t = item
            .downcast::<PyTuple>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_not_tuple"))?;
        if t.len() < 6 {
            return Ok((false, Some("utxo_tuple_arity".to_string()), None));
        }
        let txid_item = t
            .get_item(0)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_txid_missing"))?;
        let txid_b: &Bound<'_, PyBytes> = txid_item
            .downcast()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_txid_not_bytes"))?;
        let txid_raw = txid_b.as_bytes();
        if txid_raw.len() != 32 {
            return Ok((false, Some("utxo_txid_length".to_string()), None));
        }
        let vout: u32 = t
            .get_item(1)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_vout_missing"))?
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_vout_invalid"))?;
        let amount: u64 = t
            .get_item(2)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_amount_missing"))?
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_amount_invalid"))?;
        let spk_item = t
            .get_item(3)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_script_missing"))?;
        let spk_b: &Bound<'_, PyBytes> = spk_item
            .downcast()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_script_not_bytes"))?;
        let spk = spk_b.as_bytes().to_vec();
        let is_cb: bool = t
            .get_item(4)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_coinbase_missing"))?
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_coinbase_invalid"))?;
        let born: i64 = t
            .get_item(5)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_height_missing"))?
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("utxo_height_invalid"))?;

        utxo_map.insert(
            (txid_raw.to_vec(), vout),
            UtxoEntry {
                amount,
                spk,
                is_coinbase: is_cb,
                height: born,
            },
        );
    }

    // precompute hashes
    let mut prevouts_cat = Vec::with_capacity(inputs.len() * 36);
    let mut seq_cat = Vec::with_capacity(inputs.len() * 4);
    for (prev, vout, seq, _ss, _) in &inputs {
        let mut prev_le = prev.clone();
        prev_le.reverse();
        prevouts_cat.extend_from_slice(&prev_le);
        prevouts_cat.extend_from_slice(&vout.to_le_bytes());
        seq_cat.extend_from_slice(&seq.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_cat);
    let hash_sequence = sha256d(&seq_cat);

    let mut outs_cat = Vec::new();
    for (amt, spk) in &outputs {
        outs_cat.extend_from_slice(&amt.to_le_bytes());
        encode_varint(spk.len(), &mut outs_cat);
        outs_cat.extend_from_slice(spk);
    }
    let hash_outputs = sha256d(&outs_cat);

    let secp = Secp256k1::verification_only();

    let mut seen: HashMap<(Vec<u8>, u32), ()> = HashMap::new();
    let mut input_sum: u128 = 0;
    let mut sigops: u32 = 0;

    for (_idx, (prev, vout, seq, _ss, wit)) in inputs.iter().enumerate() {
        let key = (prev.clone(), *vout);
        if seen.contains_key(&key) {
            return Ok((false, Some("duplicate_prevout_in_tx".to_string()), None));
        }
        seen.insert(key.clone(), ());

        let entry = match utxo_map.get(&key) {
            Some(e) => e,
            None => {
                return Ok((false, Some("prevout_missing".to_string()), None));
            }
        };
        if entry.is_coinbase {
            let confs = spend_height as i64 - entry.height;
            if confs < limits.coinbase_maturity as i64 {
                return Ok((false, Some("coinbase_immature".to_string()), None));
            }
        }
        input_sum += entry.amount as u128;

        // witness checks
        if wit.len() < 2 {
            return Ok((false, Some("missing_witness".to_string()), None));
        }
        let sig_full = &wit[0];
        if sig_full.len() < 2 {
            return Ok((false, Some("invalid_signature".to_string()), None));
        }
        let sighash_type = sig_full[sig_full.len() - 1];
        if (sighash_type & 0x1f) != 0x01 || (sighash_type & 0x80) != 0 {
            return Ok((false, Some("unsupported_sighash".to_string()), None));
        }
        let sig_der = &sig_full[..sig_full.len() - 1];
        let pubkey = &wit[1];
        let spk = &entry.spk;
        if spk.len() != 22 || spk[0] != 0x00 || spk[1] != 0x14 {
            return Ok((false, Some("unsupported_spk_type".to_string()), None));
        }
        if hash160_bytes(pubkey) != spk[2..22] {
            return Ok((false, Some("pubkey_hash_mismatch".to_string()), None));
        }

        // build sighash
        let mut preimage = Vec::with_capacity(156 + 25);
        preimage.extend_from_slice(&ver.to_le_bytes());
        preimage.extend_from_slice(&hash_prevouts);
        preimage.extend_from_slice(&hash_sequence);
        let mut prev_le = prev.clone();
        prev_le.reverse();
        preimage.extend_from_slice(&prev_le);
        preimage.extend_from_slice(&vout.to_le_bytes());
        // script_code for p2wpkh
        preimage.push(0x19); // varint 25
        preimage.extend_from_slice(&[0x76, 0xa9, 0x14]);
        preimage.extend_from_slice(&spk[2..22]);
        preimage.extend_from_slice(&[0x88, 0xac]);
        preimage.extend_from_slice(&entry.amount.to_le_bytes());
        preimage.extend_from_slice(&seq.to_le_bytes());
        preimage.extend_from_slice(&hash_outputs);
        preimage.extend_from_slice(&lock.to_le_bytes());
        preimage.extend_from_slice(&(sighash_type as u32).to_le_bytes());

        let digest = sha256d(&preimage);

        let msg = match Message::from_digest_slice(&digest) {
            Ok(m) => m,
            Err(_) => return Ok((false, Some("invalid_digest".to_string()), None)),
        };
        let pk = match PublicKey::from_slice(pubkey) {
            Ok(p) => p,
            Err(_) => return Ok((false, Some("invalid_pubkey".to_string()), None)),
        };
        let sig = match Signature::from_der(sig_der) {
            Ok(s) => s,
            Err(_) => return Ok((false, Some("bad_der".to_string()), None)),
        };
        let mut norm = sig;
        if limits.enforce_low_s {
            norm.normalize_s();
            if norm != sig {
                return Ok((false, Some("high_s".to_string()), None));
            }
        }
        if secp.verify_ecdsa(&msg, &norm, &pk).is_err() {
            return Ok((false, Some("ecdsa_verify_failed".to_string()), None));
        }

        sigops = sigops.saturating_add(1);
    }

    if sigops > limits.max_sigops_per_tx {
        return Ok((false, Some("tx_sigops_limit".to_string()), None));
    }

    let mut output_sum: u128 = 0;
    for (amt, spk) in &outputs {
        if spk.is_empty() {
            return Ok((false, Some("empty_script".to_string()), None));
        }
        output_sum += *amt as u128;
    }
    if input_sum < output_sum {
        return Ok((false, Some("inputs_less_than_outputs".to_string()), None));
    }
    let fee = (input_sum - output_sum) as u64;
    Ok((true, None, Some(fee)))
}
