// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md
// Refs: BIP141; libsecp256k1

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyAnyMethods, PyByteArray, PyBytes, PyDict, PyDictMethods, PyList, PyListMethods, PyTuple};
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use ahash::{AHashMap, AHashSet};

fn log_py(level: &str, msg: &str) {
    Python::attach(|py| {
        if let Ok(logging) = py.import("logging") {
            if let Ok(logger) = logging.call_method1("getLogger", ("tsarchain.native",)) {
                let _ = logger.call_method1(level, (msg,));
            }
        }
    });
}
#[inline]
fn log_info(msg: &str) {
    log_py("info", msg);
}
#[inline]
fn log_warning(msg: &str) {
    log_py("warning", msg);
}

#[derive(Clone, Debug)]
struct UtxoEntry {
    amount: u64,
    script: Vec<u8>,
    is_coinbase: bool,
    block_height: i64,
}

#[derive(Clone)]
struct ValidationOptions {
    coinbase_maturity: i64,
    max_sigops_per_tx: u32,
    max_sigops_per_block: u32,
    max_tx_vsize: u64,
    min_tx_vsize: u64,
    max_tx_weight: u64,
    min_tx_weight: u64,
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    enforce_low_s: bool,
}

#[derive(Clone)]
struct InputParts {
    txid_hex: String,
    txid_be: [u8; 32],
    txid_le: [u8; 32],
    vout: u32,
    sequence: u32,
    #[allow(dead_code)] // script_sig disimpan untuk konsistensi/serialisasi txid coinbase, belum dipakai validator
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct OutputParts {
    amount: u64,
    script_pubkey: Vec<u8>,
}

#[derive(Clone)]
struct TxParts {
    version: i32,
    locktime: u32,
    inputs: Vec<InputParts>,
    outputs: Vec<OutputParts>,
    txid_be: [u8; 32],
}

#[derive(Clone, Copy)]
enum ScriptKind {
    P2wpkh([u8; 20]),
    P2wsh([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PrevoutKey {
    txid: [u8; 32], // big-endian as provided by hex/bytes
    vout: u32,
}

fn hash160_bytes(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn detect_script_kind(script: &[u8]) -> Option<ScriptKind> {
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[2..22]);
        return Some(ScriptKind::P2wpkh(h));
    }
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[2..34]);
        return Some(ScriptKind::P2wsh(h));
    }
    None
}

fn build_p2wpkh_script_code(hash20: &[u8; 20]) -> Vec<u8> {
    let mut code = Vec::with_capacity(25);
    code.push(0x76);
    code.push(0xa9);
    code.push(0x14);
    code.extend_from_slice(hash20);
    code.push(0x88);
    code.push(0xac);
    code
}

fn encode_varint(v: u64, out: &mut Vec<u8>) {
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn parse_bytes_or_hex(value: &Bound<'_, PyAny>, field: &str) -> Result<Vec<u8>, String> {
    if let Ok(b) = value.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(hex_str) = value.extract::<String>() {
        if hex_str.is_empty() {
            return Ok(Vec::new());
        }
        return hex::decode(&hex_str).map_err(|_| format!("failed decoding hex in field {}", field));
    }
    Err(format!("field {} must be bytes or hex string", field))
}

fn parse_witness_field(value: Option<Bound<'_, PyAny>>) -> Result<Vec<Vec<u8>>, String> {
    let Some(obj) = value else {
        return Ok(Vec::new());
    };
    let list: &Bound<'_, PyList> = obj
        .cast::<PyList>()
        .map_err(|_| "witness must be list".to_string())?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        if let Ok(b) = item.cast::<PyBytes>() {
            out.push(b.as_bytes().to_vec());
            continue;
        }
        let hex_item: String = item
            .extract()
            .map_err(|_| "witness element must be hex string/bytes".to_string())?;
        let bytes = hex::decode(hex_item).map_err(|_| "invalid witness hex".to_string())?;
        out.push(bytes);
    }
    Ok(out)
}

struct TxidParts {
    be: [u8; 32],
    le: [u8; 32],
    hex_lower: String,
}

fn parse_txid_field(value: &Bound<'_, PyAny>, field: &str) -> Result<TxidParts, String> {
    let (be_bytes, hex_lower) = if let Ok(b) = value.cast::<PyBytes>() {
        let slice = b.as_bytes();
        if slice.len() != 32 {
            return Err(format!("{} must be 32-byte txid", field));
        }
        let mut be = [0u8; 32];
        be.copy_from_slice(slice);
        (be, hex::encode(slice).to_lowercase())
    } else {
        let hex_str: String = value
            .extract()
            .map_err(|_| format!("{} must be txid hex/bytes", field))?;
        let txid_bytes = hex::decode(&hex_str).map_err(|_| format!("{} invalid txid hex", field))?;
        if txid_bytes.len() != 32 {
            return Err(format!("{} invalid txid length", field));
        }
        let mut be = [0u8; 32];
        be.copy_from_slice(&txid_bytes);
        (be, hex_str.to_lowercase())
    };

    let mut le = [0u8; 32];
    for (i, b) in be_bytes.iter().enumerate() {
        le[31 - i] = *b;
    }

    Ok(TxidParts {
        be: be_bytes,
        le,
        hex_lower,
    })
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

#[derive(Clone)]
struct SighashCache {
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
}

fn build_sighash_cache(tx: &TxParts) -> SighashCache {
    let mut prevouts_cat = Vec::with_capacity(tx.inputs.len() * 36);
    let mut seq_cat = Vec::with_capacity(tx.inputs.len() * 4);
    for inp in &tx.inputs {
        prevouts_cat.extend_from_slice(&inp.txid_le);
        prevouts_cat.extend_from_slice(&inp.vout.to_le_bytes());
        seq_cat.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_cat);
    let hash_sequence = sha256d(&seq_cat);

    // setiap output: 8 byte amount + varint + script
    let mut outs_cat = Vec::with_capacity(tx.outputs.len().saturating_mul(16));
    for outp in &tx.outputs {
        outs_cat.extend_from_slice(&outp.amount.to_le_bytes());
        encode_varint(outp.script_pubkey.len() as u64, &mut outs_cat);
        outs_cat.extend_from_slice(&outp.script_pubkey);
    }
    let hash_outputs = sha256d(&outs_cat);

    SighashCache {
        hash_prevouts,
        hash_sequence,
        hash_outputs,
    }
}

fn bip143_sighash_from_parts(
    tx: &TxParts,
    cache: &SighashCache,
    input_index: usize,
    script_code: &[u8],
    value_sat: u64,
    sighash_type: u32,
) -> Result<[u8; 32], String> {
    if input_index >= tx.inputs.len() {
        return Err("input_index_out_of_range".to_string());
    }
    // 4 (ver) + 32*3 + 36 + script + 8 + 4 + 32 + 4 + 4
    let mut pre = Vec::with_capacity(156 + script_code.len());
    pre.extend_from_slice(&tx.version.to_le_bytes());
    pre.extend_from_slice(&cache.hash_prevouts);
    pre.extend_from_slice(&cache.hash_sequence);

    let inp = &tx.inputs[input_index];
    pre.extend_from_slice(&inp.txid_le);
    pre.extend_from_slice(&inp.vout.to_le_bytes());

    encode_varint(script_code.len() as u64, &mut pre);
    pre.extend_from_slice(script_code);

    pre.extend_from_slice(&value_sat.to_le_bytes());
    pre.extend_from_slice(&inp.sequence.to_le_bytes());
    pre.extend_from_slice(&cache.hash_outputs);
    pre.extend_from_slice(&tx.locktime.to_le_bytes());
    pre.extend_from_slice(&sighash_type.to_le_bytes());

    Ok(sha256d(&pre))
}

fn tx_parts_size(tx: &TxParts, include_witness: bool) -> usize {
    let mut buf = Vec::with_capacity(4 + tx.inputs.len().saturating_mul(60) + tx.outputs.len().saturating_mul(40));
    buf.extend_from_slice(&tx.version.to_le_bytes());
    let has_wit = include_witness && tx.inputs.iter().any(|i| !i.witness.is_empty());
    if has_wit {
        buf.push(0x00);
        buf.push(0x01);
    }
    encode_varint(tx.inputs.len() as u64, &mut buf);
    for inp in &tx.inputs {
        buf.extend_from_slice(&inp.txid_le);
        buf.extend_from_slice(&inp.vout.to_le_bytes());
        encode_varint(inp.script_sig.len() as u64, &mut buf);
        buf.extend_from_slice(&inp.script_sig);
        buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    encode_varint(tx.outputs.len() as u64, &mut buf);
    for outp in &tx.outputs {
        buf.extend_from_slice(&outp.amount.to_le_bytes());
        encode_varint(outp.script_pubkey.len() as u64, &mut buf);
        buf.extend_from_slice(&outp.script_pubkey);
    }
    if has_wit {
        for inp in &tx.inputs {
            encode_varint(inp.witness.len() as u64, &mut buf);
            for w in &inp.witness {
                encode_varint(w.len() as u64, &mut buf);
                buf.extend_from_slice(w);
            }
        }
    }
    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    buf.len()
}

fn tx_parts_weight_vsize(tx: &TxParts) -> (u64, u64, u64, u64) {
    let base = tx_parts_size(tx, false) as u64;
    let total = tx_parts_size(tx, true) as u64;
    let weight = base.saturating_mul(3).saturating_add(total);
    let vsize = (weight + 3) / 4;
    (weight, vsize, base, total)
}

fn get_required<'py>(
    dict: &Bound<'py, PyDict>,
    key: &str,
    err: &str,
) -> Result<Bound<'py, PyAny>, String> {
    dict.get_item(key)
        .map_err(|_| err.to_string())?
        .ok_or_else(|| err.to_string())
}

fn get_optional<'py>(
    dict: &Bound<'py, PyDict>,
    key: &str,
) -> Result<Option<Bound<'py, PyAny>>, String> {
    dict.get_item(key).map_err(|_| format!("pyerr_get_{}", key))
}

impl TxParts {
    fn from_dict(tx: &Bound<'_, PyDict>) -> Result<Self, String> {
        let version: i32 = get_required(tx, "version", "tx_missing_version")?
            .extract()
            .map_err(|_| "tx_invalid_version".to_string())?;
        let locktime: u32 = match get_optional(tx, "locktime")? {
            Some(v) => v.extract().map_err(|_| "tx_invalid_locktime".to_string())?,
            None => 0,
        };

        let txid_field = get_required(tx, "txid", "tx_missing_txid")?;
        let txid_parts =
            parse_txid_field(&txid_field, "txid").map_err(|_| "tx_invalid_txid".to_string())?;

        let inputs_any = get_required(tx, "inputs", "tx_missing_inputs")?;
        let inputs_list = inputs_any
            .cast::<PyList>()
            .map_err(|_| "tx_inputs_not_list".to_string())?;
        if inputs_list.is_empty() {
            return Err("tx_missing_inputs".to_string());
        }
        let mut inputs = Vec::with_capacity(inputs_list.len());
        for item in inputs_list {
            let inp = item
                .cast::<PyDict>()
                .map_err(|_| "tx_input_not_dict".to_string())?;
            let txid_field = get_required(&inp, "txid", "tx_input_missing_txid")?;
            let txid_parts_inp = parse_txid_field(&txid_field, "tx_input_txid")
                .map_err(|_| "tx_input_invalid_txid".to_string())?;
            let vout: u32 = get_required(&inp, "vout", "tx_input_missing_vout")?
                .extract()
                .map_err(|_| "tx_input_invalid_vout".to_string())?;
            let sequence: u32 = match get_optional(inp, "sequence")? {
                Some(v) => v
                    .extract()
                    .map_err(|_| "tx_input_invalid_sequence".to_string())?,
                None => 0xffffffff,
            };
            let witness = parse_witness_field(get_optional(inp, "witness")?)?;
            inputs.push(InputParts {
                txid_hex: txid_parts_inp.hex_lower.clone(),
                txid_be: txid_parts_inp.be,
                txid_le: txid_parts_inp.le,
                vout,
                sequence,
                script_sig: Vec::new(),
                witness,
            });
        }

        let outputs_any = get_required(tx, "outputs", "tx_missing_outputs")?;
        let outputs_list = outputs_any
            .cast::<PyList>()
            .map_err(|_| "tx_outputs_not_list".to_string())?;
        let mut outputs = Vec::with_capacity(outputs_list.len());
        for item in outputs_list {
            let out = item
                .cast::<PyDict>()
                .map_err(|_| "tx_output_not_dict".to_string())?;
            let amount: u64 = get_required(&out, "amount", "tx_output_missing_amount")?
                .extract()
                .map_err(|_| "tx_output_invalid_amount".to_string())?;
            let script_hex = get_required(&out, "script_pubkey", "tx_output_missing_spk")?;
            let script_pubkey = parse_bytes_or_hex(&script_hex, "script_pubkey")?;
            outputs.push(OutputParts {
                amount,
                script_pubkey,
            });
        }

        Ok(TxParts {
            version,
            locktime,
            inputs,
            outputs,
            txid_be: txid_parts.be,
        })
    }
}

fn parse_validation_options(opts: &Bound<'_, PyDict>) -> Result<ValidationOptions, String> {
    let coinbase_maturity =
        get_required(opts, "coinbase_maturity", "opts_missing_coinbase_maturity")?
            .extract::<i64>()
            .map_err(|_| "opts_invalid_coinbase_maturity".to_string())?;
    let max_sigops_per_tx =
        get_required(opts, "max_sigops_per_tx", "opts_missing_max_sigops_per_tx")?
            .extract::<u32>()
            .map_err(|_| "opts_invalid_max_sigops_per_tx".to_string())?;
    let max_sigops_per_block = get_required(
        opts,
        "max_sigops_per_block",
        "opts_missing_max_sigops_per_block",
    )?
    .extract::<u32>()
    .map_err(|_| "opts_invalid_max_sigops_per_block".to_string())?;
    let max_tx_vsize =
        get_required(opts, "max_tx_vsize", "opts_missing_max_tx_vsize")?
            .extract::<u64>()
            .map_err(|_| "opts_invalid_max_tx_vsize".to_string())?;
    let min_tx_vsize =
        get_required(opts, "min_tx_vsize", "opts_missing_min_tx_vsize")?
            .extract::<u64>()
            .map_err(|_| "opts_invalid_min_tx_vsize".to_string())?;
    let max_tx_weight =
        get_required(opts, "max_tx_weight", "opts_missing_max_tx_weight")?
            .extract::<u64>()
            .map_err(|_| "opts_invalid_max_tx_weight".to_string())?;
    let min_tx_weight =
        get_required(opts, "min_tx_weight", "opts_missing_min_tx_weight")?
            .extract::<u64>()
            .map_err(|_| "opts_invalid_min_tx_weight".to_string())?;
    let max_tx_inputs =
        get_required(opts, "max_tx_inputs", "opts_missing_max_tx_inputs")?
            .extract::<usize>()
            .map_err(|_| "opts_invalid_max_tx_inputs".to_string())?;
    let max_tx_outputs =
        get_required(opts, "max_tx_outputs", "opts_missing_max_tx_outputs")?
            .extract::<usize>()
            .map_err(|_| "opts_invalid_max_tx_outputs".to_string())?;
    let enforce_low_s = match get_optional(opts, "enforce_low_s")? {
        Some(v) => v
            .extract()
            .map_err(|_| "opts_invalid_enforce_low_s".to_string())?,
        None => true,
    };
    Ok(ValidationOptions {
        coinbase_maturity,
        max_sigops_per_tx,
        max_sigops_per_block,
        max_tx_vsize,
        min_tx_vsize,
        max_tx_weight,
        min_tx_weight,
        max_tx_inputs,
        max_tx_outputs,
        enforce_low_s,
    })
}

fn parse_prevout_key_str(s: &str) -> Option<PrevoutKey> {
    let mut parts = s.split(':');
    let tx_part = parts.next()?;
    let vout_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let tx_bytes = hex::decode(tx_part).ok()?;
    if tx_bytes.len() != 32 {
        return None;
    }
    let mut be = [0u8; 32];
    be.copy_from_slice(&tx_bytes);
    let vout = vout_part.parse::<u32>().ok()?;
    Some(PrevoutKey { txid: be, vout })
}

fn build_utxo_index(utxo: &Bound<'_, PyDict>) -> Result<AHashMap<PrevoutKey, UtxoEntry>, String> {
    let mut out: AHashMap<PrevoutKey, UtxoEntry> = AHashMap::with_capacity(utxo.len());
    let mut iter = utxo.iter();
    while let Some((key_obj, value_obj)) = iter.next() {
        let key_raw: String = match key_obj.extract::<String>() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let key = match parse_prevout_key_str(&key_raw) {
            Some(k) => k,
            None => continue,
        };
        let entry_dict = match value_obj.cast::<PyDict>() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut script_bytes: Option<Vec<u8>> = None;
        let mut amount_val = None;
        if let Some(tx_out) = entry_dict
            .get_item("tx_out")
            .map_err(|_| "utxo_pyerr".to_string())?
        {
            if let Ok(tx_out_dict) = tx_out.cast::<PyDict>() {
                if let Some(spk) = tx_out_dict
                    .get_item("script_pubkey")
                    .map_err(|_| "utxo_pyerr".to_string())?
                {
                    script_bytes = parse_bytes_or_hex(&spk, "utxo_spk").ok();
                }
                if let Some(am) = tx_out_dict
                    .get_item("amount")
                    .map_err(|_| "utxo_pyerr".to_string())?
                {
                    amount_val = am.extract::<u64>().ok();
                }
            }
        }
        if script_bytes.is_none() {
            if let Some(spk) = entry_dict
                .get_item("script_pubkey")
                .map_err(|_| "utxo_pyerr".to_string())?
            {
                script_bytes = parse_bytes_or_hex(&spk, "utxo_spk").ok();
            }
        }
        if amount_val.is_none() {
            if let Some(am) = entry_dict
                .get_item("amount")
                .map_err(|_| "utxo_pyerr".to_string())?
            {
                amount_val = am.extract::<u64>().ok();
            }
        }
        let script = match script_bytes {
            Some(s) => s,
            None => continue,
        };
        let amount = match amount_val {
            Some(a) => a,
            None => continue,
        };
        let is_coinbase = entry_dict
            .get_item("is_coinbase")
            .map_err(|_| "utxo_pyerr".to_string())?
            .map(|v| v.extract().unwrap_or(false))
            .unwrap_or(false);
        let block_height = entry_dict
            .get_item("block_height")
            .map_err(|_| "utxo_pyerr".to_string())?
            .map(|v| v.extract().unwrap_or(0i64))
            .unwrap_or(0i64);
        out.insert(
            key,
            UtxoEntry {
                amount,
                script,
                is_coinbase,
                block_height,
            },
        );
    }
    Ok(out)
}

fn verify_signature(
    secp: &Secp256k1<secp256k1::VerifyOnly>,
    pubkey: &[u8],
    sig_der: &[u8],
    digest: &[u8; 32],
    enforce_low_s: bool,
) -> bool {
    let pk = match PublicKey::from_slice(pubkey) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(sig_der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut norm = sig;
    if enforce_low_s {
        norm.normalize_s();
        if norm != sig {
            return false;
        }
    }
    let msg = Message::from_digest(*digest);
    secp.verify_ecdsa(msg, &norm, &pk).is_ok()
}

fn validate_transaction_parts(
    tx: &TxParts,
    spend_height: u64,
    utxo_map: &mut AHashMap<PrevoutKey, UtxoEntry>,
    opts: &ValidationOptions,
    secp: &Secp256k1<secp256k1::VerifyOnly>,
) -> Result<(u64, u32), String> {
    let (weight, vsize, _base_size, _total_size) = tx_parts_weight_vsize(tx);
    let vin_count = tx.inputs.len();
    let vout_count = tx.outputs.len();

    if vsize > opts.max_tx_vsize {
        return Err("tx_vsize_exceeds_limit".to_string());
    }
    if vsize < opts.min_tx_vsize {
        return Err("tx_vsize_below_min".to_string());
    }
    if weight > opts.max_tx_weight {
        return Err("tx_weight_exceeds_limit".to_string());
    }
    if weight < opts.min_tx_weight {
        return Err("tx_weight_below_min".to_string());
    }
    if vin_count > opts.max_tx_inputs {
        return Err("tx_inputs_exceed_limit".to_string());
    }
    if vout_count > opts.max_tx_outputs {
        return Err("tx_outputs_exceed_limit".to_string());
    }

    let mut seen_prevouts: AHashSet<PrevoutKey> = AHashSet::with_capacity(tx.inputs.len());
    let mut input_sum: u128 = 0;
    let mut sigops_tx: u32 = 0;
    let cache = build_sighash_cache(tx);

    for (idx, inp) in tx.inputs.iter().enumerate() {
        let key = PrevoutKey {
            txid: inp.txid_be,
            vout: inp.vout,
        };
        if !seen_prevouts.insert(key) {
            return Err("duplicate_prevout_in_tx".to_string());
        }
        let entry = match utxo_map.remove(&key) {
            Some(e) => e,
            None => {
                return Err(format!(
                    "prevout_missing {}:{}",
                    inp.txid_hex,
                    inp.vout
                ))
            }
        };
        if entry.is_coinbase {
            let confs = (spend_height as i64).saturating_sub(entry.block_height);
            if confs < opts.coinbase_maturity {
                return Err(format!(
                    "coinbase_immature conf={} need>={}",
                    confs, opts.coinbase_maturity
                ));
            }
        }
        input_sum += entry.amount as u128;
        let Some(kind) = detect_script_kind(&entry.script) else {
            return Err("unsupported_script".to_string());
        };
        match kind {
            ScriptKind::P2wpkh(hash20) => {
                if inp.witness.len() < 2 {
                    return Err("missing_witness".to_string());
                }
                let sig_full = &inp.witness[0];
                if sig_full.len() < 2 {
                    return Err("invalid_signature".to_string());
                }
                let sighash_type = sig_full[sig_full.len() - 1];
                if (sighash_type & 0x1f) != 0x01 || (sighash_type & 0x80) != 0 {
                    return Err("unsupported_sighash".to_string());
                }
                let sig_der = &sig_full[..sig_full.len() - 1];
                let pubkey = &inp.witness[1];
                if hash160_bytes(pubkey) != hash20 {
                    return Err("pubkey_hash_mismatch".to_string());
                }
                let script_code = build_p2wpkh_script_code(&hash20);
                let digest = bip143_sighash_from_parts(
                    tx,
                    &cache,
                    idx,
                    &script_code,
                    entry.amount,
                    sighash_type as u32,
                )
                .map_err(|_| "bip143_sighash_error".to_string())?;
                if !verify_signature(&secp, pubkey, sig_der, &digest, opts.enforce_low_s) {
                    return Err(format!("sig_verify_failed index={}", idx));
                }
                sigops_tx = sigops_tx.saturating_add(1);
            }
            ScriptKind::P2wsh(hash32) => {
                // Graffiti payout covenant: witness [art_digest, redeem_script]; redeem_script: <push art_digest> OP_EQUAL
                if inp.witness.len() < 2 {
                    return Err("missing_witness".to_string());
                }
                let art_digest = &inp.witness[0];
                let redeem_script = &inp.witness[1];
                if Sha256::digest(redeem_script).as_slice() != hash32 {
                    return Err("witness_script_hash_mismatch".to_string());
                }
                if redeem_script.len() < 2 {
                    return Err("redeem_script_too_short".to_string());
                }
                let push_len = redeem_script[0] as usize;
                if push_len + 2 != redeem_script.len() {
                    return Err("redeem_script_malformed".to_string());
                }
                let pushed = &redeem_script[1..1 + push_len];
                if redeem_script[redeem_script.len() - 1] != 0x87 {
                    return Err("redeem_script_missing_equal".to_string());
                }
                if pushed != art_digest {
                    return Err("redeem_script_data_mismatch".to_string());
                }
                // No additional sigops for OP_EQUAL covenant
            }
        }
    }

    if sigops_tx > opts.max_sigops_per_tx {
        return Err("tx_sigops_limit".to_string());
    }

    let mut output_sum: u128 = 0;
    for (idx, outp) in tx.outputs.iter().enumerate() {
        if outp.amount == 0 {
            if outp
                .script_pubkey
                .first()
                .map(|b| *b == 0x6a)
                .unwrap_or(false)
            {
                // allow OP_RETURN zero amount
            } else {
                return Err("nonpositive_output_amount".to_string());
            }
        } else {
            output_sum += outp.amount as u128;
        }
        let key = PrevoutKey {
            txid: tx.txid_be,
            vout: idx as u32,
        };
        utxo_map.insert(
            key,
            UtxoEntry {
                amount: outp.amount,
                script: outp.script_pubkey.clone(),
                is_coinbase: false,
                block_height: spend_height as i64,
            },
        );
    }

    if input_sum < output_sum {
        return Err(format!(
            "inputs_less_than_outputs in={} out={}",
            input_sum, output_sum
        ));
    }
    let fee = (input_sum - output_sum) as u64;
    Ok((fee, sigops_tx))
}

fn validate_block_impl(
    block: &Bound<'_, PyDict>,
    utxo: &Bound<'_, PyDict>,
    spend_height: u64,
    opts: &Bound<'_, PyDict>,
) -> Result<Vec<u64>, String> {
    let opts = parse_validation_options(opts)?;
    let mut utxo_map = build_utxo_index(utxo)?;
    let secp = Secp256k1::verification_only();
    let txs_any = get_required(block, "transactions", "empty_block_transactions")?;
    let txs = txs_any
        .cast::<PyList>()
        .map_err(|_| "transactions_not_list".to_string())?;
    if txs.len() < 1 {
        return Err("empty_block_transactions".to_string());
    }
    let mut fees = Vec::with_capacity(txs.len().saturating_sub(1));
    let mut total_sigops = 0u32;

    for (idx, item) in txs.iter().enumerate() {
        let tx_dict = item
            .cast::<PyDict>()
            .map_err(|_| "tx_not_dict".to_string())?;
        let is_coinbase = match get_optional(&tx_dict, "is_coinbase")? {
            Some(v) => v.extract().unwrap_or(false),
            None => false,
        };
        if idx == 0 {
            if !is_coinbase {
                return Err("missing_coinbase".to_string());
            }
            continue;
        } else if is_coinbase {
            return Err("duplicate_coinbase".to_string());
        }
        let tx_parts = TxParts::from_dict(&tx_dict)?;
        let (fee, sigops) =
            validate_transaction_parts(&tx_parts, spend_height, &mut utxo_map, &opts, &secp)?;
        fees.push(fee);
        total_sigops = total_sigops.saturating_add(sigops);
        if total_sigops > opts.max_sigops_per_block {
            return Err("block_sigops_limit".to_string());
        }
    }

    if fees.len() != txs.len().saturating_sub(1) {
        return Err("fee_mismatch".to_string());
    }
    Ok(fees)
}

#[pyfunction]
pub fn validate_block_txs_native(
    block: &Bound<PyDict>,
    utxo: &Bound<PyDict>,
    spend_height: u64,
    opts: &Bound<PyDict>,
) -> PyResult<(bool, Option<String>, Option<Vec<u64>>)> {
    let tx_len = match block.get_item("transactions") {
        Ok(Some(v)) => v.cast::<PyList>().map(|l| l.len()).unwrap_or(0),
        _ => 0,
    };
    match validate_block_impl(block, utxo, spend_height, opts) {
        Ok(fees) => {
            let total_fee: u64 = fees.iter().copied().sum();
            log_info(&format!(
                "[validate_block] height={} txs={} total_fee={}",
                spend_height, tx_len, total_fee
            ));
            Ok((true, None, Some(fees)))
        }
        Err(reason) => {
            log_warning(&format!(
                "[validate_block] fail height={} txs={} reason={}",
                spend_height, tx_len, reason
            ));
            Ok((false, Some(reason), None))
        }
    }
}

fn parse_compact_input(obj: &Bound<'_, PyAny>) -> Result<InputParts, String> {
    let tuple = obj
        .cast::<PyTuple>()
        .map_err(|_| "tx_input_not_tuple".to_string())?;
    if tuple.len() < 4 {
        return Err("tx_input_tuple_arity".to_string());
    }
    let txid_item = tuple
        .get_item(0)
        .map_err(|_| "tx_input_tuple_txid".to_string())?;
    let txid_bytes = txid_item
        .cast::<PyBytes>()
        .map_err(|_| "tx_input_txid_not_bytes".to_string())?;
    let txid_slice = txid_bytes.as_bytes();
    if txid_slice.len() != 32 {
        return Err("tx_input_txid_length".to_string());
    }
    let mut txid_be = [0u8; 32];
    txid_be.copy_from_slice(txid_slice);
    let mut txid_le = [0u8; 32];
    for (i, b) in txid_slice.iter().enumerate() {
        txid_le[31 - i] = *b;
    }
    let vout: u32 = tuple
        .get_item(1)
        .map_err(|_| "tx_input_tuple_vout".to_string())?
        .extract()
        .map_err(|_| "tx_input_invalid_vout".to_string())?;
    let sequence: u32 = tuple
        .get_item(2)
        .map_err(|_| "tx_input_tuple_sequence".to_string())?
        .extract()
        .map_err(|_| "tx_input_invalid_sequence".to_string())?;
    let (script_sig, wit_any) = if tuple.len() >= 5 {
        let ss_any = tuple
            .get_item(3)
            .map_err(|_| "tx_input_tuple_scriptsig".to_string())?;
        let ss_bytes = if let Ok(b) = ss_any.cast::<PyBytes>() {
            b.as_bytes().to_vec()
        } else if let Ok(b) = ss_any.cast::<PyByteArray>() {
            b.to_vec()
        } else {
            return Err("tx_input_scriptsig_not_bytes".to_string());
        };
        let wit = tuple
            .get_item(4)
            .map_err(|_| "tx_input_tuple_witness".to_string())?;
        (ss_bytes, wit)
    } else {
        let wit = tuple
            .get_item(3)
            .map_err(|_| "tx_input_tuple_witness".to_string())?;
        (Vec::new(), wit)
    };
    let witness = parse_witness_field(Some(wit_any))?;
    Ok(InputParts {
        txid_hex: hex::encode(txid_slice),
        txid_be,
        txid_le,
        vout,
        sequence,
        script_sig,
        witness,
    })
}

fn parse_compact_output(obj: &Bound<'_, PyAny>) -> Result<OutputParts, String> {
    let tuple = obj
        .cast::<PyTuple>()
        .map_err(|_| "tx_output_not_tuple".to_string())?;
    if tuple.len() < 2 {
        return Err("tx_output_tuple_arity".to_string());
    }
    let amount_item = tuple
        .get_item(0)
        .map_err(|_| "tx_output_tuple_amount".to_string())?;
    let amount: u64 = amount_item
        .extract()
        .map_err(|_| "tx_output_invalid_amount".to_string())?;
    let spk_item = tuple
        .get_item(1)
        .map_err(|_| "tx_output_tuple_script".to_string())?;
    let spk_bytes = spk_item
        .cast::<PyBytes>()
        .map_err(|_| "tx_output_script_not_bytes".to_string())?
        .as_bytes()
        .to_vec();
    Ok(OutputParts {
        amount,
        script_pubkey: spk_bytes,
    })
}

fn parse_compact_tx(obj: &Bound<'_, PyAny>) -> Result<(TxParts, bool), String> {
    let tuple = obj
        .cast::<PyTuple>()
        .map_err(|_| "tx_not_tuple".to_string())?;
    if tuple.len() < 6 {
        return Err("tx_tuple_arity".to_string());
    }
    let version_item = tuple
        .get_item(0)
        .map_err(|_| "tx_tuple_version".to_string())?;
    let version: i32 = version_item
        .extract()
        .map_err(|_| "tx_invalid_version".to_string())?;
    let locktime_item = tuple
        .get_item(1)
        .map_err(|_| "tx_tuple_locktime".to_string())?;
    let locktime: u32 = locktime_item
        .extract()
        .map_err(|_| "tx_invalid_locktime".to_string())?;
    let inputs_item = tuple
        .get_item(2)
        .map_err(|_| "tx_tuple_inputs".to_string())?;
    let inputs_any = inputs_item
        .cast::<PyList>()
        .map_err(|_| "tx_inputs_not_list".to_string())?;
    if inputs_any.is_empty() {
        return Err("tx_missing_inputs".to_string());
    }
    let mut inputs = Vec::with_capacity(inputs_any.len());
    for item in inputs_any {
        inputs.push(parse_compact_input(&item)?);
    }
    let outputs_item = tuple
        .get_item(3)
        .map_err(|_| "tx_tuple_outputs".to_string())?;
    let outputs_any = outputs_item
        .cast::<PyList>()
        .map_err(|_| "tx_outputs_not_list".to_string())?;
    let mut outputs = Vec::with_capacity(outputs_any.len());
    for item in outputs_any {
        outputs.push(parse_compact_output(&item)?);
    }
    let txid_item = tuple
        .get_item(4)
        .map_err(|_| "tx_tuple_txid".to_string())?;
    let txid_bytes = txid_item
        .cast::<PyBytes>()
        .map_err(|_| "tx_txid_not_bytes".to_string())?;
    let txid_slice = txid_bytes.as_bytes();
    if txid_slice.len() != 32 {
        return Err("tx_txid_length".to_string());
    }
    let mut txid_be = [0u8; 32];
    txid_be.copy_from_slice(txid_slice);
    let coinbase_item = tuple
        .get_item(5)
        .map_err(|_| "tx_tuple_coinbase".to_string())?;
    let is_coinbase: bool = coinbase_item
        .extract()
        .map_err(|_| "tx_coinbase_invalid".to_string())?;

    let tx_parts = TxParts {
        version,
        locktime,
        inputs,
        outputs,
        txid_be,
    };
    Ok((tx_parts, is_coinbase))
}

fn parse_compact_utxo_list(utxo: &Bound<'_, PyList>) -> Result<AHashMap<PrevoutKey, UtxoEntry>, String> {
    let mut out: AHashMap<PrevoutKey, UtxoEntry> = AHashMap::with_capacity(utxo.len());
    for item in utxo {
        let tuple = item.cast::<PyTuple>().map_err(|_| "utxo_not_tuple".to_string())?;
        if tuple.len() < 6 {
            return Err("utxo_tuple_arity".to_string());
        }
        let txid_item = tuple
            .get_item(0)
            .map_err(|_| "utxo_tuple_txid".to_string())?;
        let txid_b = txid_item
            .cast::<PyBytes>()
            .map_err(|_| "utxo_txid_not_bytes".to_string())?
            .as_bytes();
        if txid_b.len() != 32 {
            return Err("utxo_txid_length".to_string());
        }
        let mut txid_be = [0u8; 32];
        txid_be.copy_from_slice(txid_b);
        let vout_item = tuple
            .get_item(1)
            .map_err(|_| "utxo_tuple_vout".to_string())?;
        let vout: u32 = vout_item
            .extract()
            .map_err(|_| "utxo_invalid_vout".to_string())?;
        let amount_item = tuple
            .get_item(2)
            .map_err(|_| "utxo_tuple_amount".to_string())?;
        let amount: u64 = amount_item
            .extract()
            .map_err(|_| "utxo_invalid_amount".to_string())?;
        let script_item = tuple
            .get_item(3)
            .map_err(|_| "utxo_tuple_script".to_string())?;
        let script = script_item
            .cast::<PyBytes>()
            .map_err(|_| "utxo_script_not_bytes".to_string())?
            .as_bytes()
            .to_vec();
        let coinbase_item = tuple
            .get_item(4)
            .map_err(|_| "utxo_tuple_coinbase".to_string())?;
        let is_coinbase: bool = coinbase_item
            .extract()
            .map_err(|_| "utxo_invalid_coinbase".to_string())?;
        let height_item = tuple
            .get_item(5)
            .map_err(|_| "utxo_tuple_height".to_string())?;
        let block_height: i64 = height_item
            .extract()
            .map_err(|_| "utxo_invalid_height".to_string())?;
        out.insert(
            PrevoutKey { txid: txid_be, vout },
            UtxoEntry {
                amount,
                script,
                is_coinbase,
                block_height,
            },
        );
    }
    Ok(out)
}

#[pyfunction]
pub fn validate_block_txs_compact(
    block_txs: &Bound<PyList>,
    utxo: &Bound<PyList>,
    spend_height: u64,
    opts: &Bound<PyDict>,
) -> PyResult<(bool, Option<String>, Option<Vec<u64>>)> {
    let opts = match parse_validation_options(opts) {
        Ok(o) => o,
        Err(e) => return Ok((false, Some(e), None)),
    };
    let mut utxo_map = match parse_compact_utxo_list(utxo) {
        Ok(m) => m,
        Err(e) => return Ok((false, Some(e), None)),
    };
    if block_txs.is_empty() {
        return Ok((false, Some("empty_block_transactions".to_string()), None));
    }
    let mut fees = Vec::with_capacity(block_txs.len().saturating_sub(1));
    let mut total_sigops = 0u32;
    let secp = Secp256k1::verification_only();

    for (idx, item) in block_txs.iter().enumerate() {
        let (tx_parts, is_coinbase) = match parse_compact_tx(&item) {
            Ok(t) => t,
            Err(e) => return Ok((false, Some(e), None)),
        };
        if idx == 0 {
            if !is_coinbase {
                return Ok((false, Some("missing_coinbase".to_string()), None));
            }
            continue;
        } else if is_coinbase {
            return Ok((false, Some("duplicate_coinbase".to_string()), None));
        }
        let (fee, sigops) =
            match validate_transaction_parts(&tx_parts, spend_height, &mut utxo_map, &opts, &secp) {
                Ok(v) => v,
                Err(e) => return Ok((false, Some(e), None)),
            };
        fees.push(fee);
        total_sigops = total_sigops.saturating_add(sigops);
        if total_sigops > opts.max_sigops_per_block {
            return Ok((false, Some("block_sigops_limit".to_string()), None));
        }
    }

    if fees.len() != block_txs.len().saturating_sub(1) {
        return Ok((false, Some("fee_mismatch".to_string()), None));
    }
    Ok((true, None, Some(fees)))
}
