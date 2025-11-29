// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md
// Refs: BIP141; BIP143; CompactSize; txid/wtxid

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use sha2::{Digest, Sha256};

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

fn parse_input_tuple(t: &Bound<'_, PyTuple>) -> PyResult<(Vec<u8>, u32, u32, Vec<Vec<u8>>)> {
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
    let wit_any = t
        .get_item(3)
        .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_input_tuple_witness"))?;
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
    Ok((prev_raw.to_vec(), vout, seq, wit_vec))
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
) -> PyResult<(i32, u32, Vec<(Vec<u8>, u32, u32, Vec<Vec<u8>>)>, Vec<(u64, Vec<u8>)>)> {
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
    inputs: &[(Vec<u8>, u32, u32, Vec<Vec<u8>>)],
    outputs: &[(u64, Vec<u8>)],
    include_witness: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + inputs.len() * 60 + outputs.len() * 40);
    buf.extend_from_slice(&version.to_le_bytes());
    let has_wit = include_witness && inputs.iter().any(|(_, _, _, wit)| !wit.is_empty());
    if has_wit {
        buf.push(0x00);
        buf.push(0x01);
    }
    encode_varint(inputs.len(), &mut buf);
    for (prev_txid, vout, seq, _wit) in inputs {
        let mut prev_le = prev_txid.clone();
        prev_le.reverse();
        buf.extend_from_slice(&prev_le);
        buf.extend_from_slice(&vout.to_le_bytes());
        buf.push(0x00); // empty scriptsig for segwit
        buf.extend_from_slice(&seq.to_le_bytes());
    }
    encode_varint(outputs.len(), &mut buf);
    for (amt, spk) in outputs {
        buf.extend_from_slice(&amt.to_le_bytes());
        encode_varint(spk.len(), &mut buf);
        buf.extend_from_slice(spk);
    }
    if has_wit {
        for (_, _, _, wit) in inputs {
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
    for (prev, vout, seq, _) in &inputs {
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

    let (prev_txid, vout, seq, _wit) = &inputs[idx];
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
