// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md
// Refs: BIP141; libsecp256k1

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyAnyMethods, PyBytes, PyDict, PyDictMethods, PyList, PyListMethods};
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn log_py(level: &str, msg: &str) {
    Python::with_gil(|py| {
        if let Ok(logging) = py.import_bound("logging") {
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
    enforce_low_s: bool,
}

#[derive(Clone)]
struct InputParts {
    txid_hex: String,
    txid_le: [u8; 32],
    vout: u32,
    sequence: u32,
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
    txid_hex: String,
}

#[derive(Clone, Copy)]
enum ScriptKind {
    P2wpkh([u8; 20]),
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
    if let Ok(b) = value.downcast::<PyBytes>() {
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
    let list = obj
        .downcast::<PyList>()
        .map_err(|_| "witness must be list".to_string())?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        if let Ok(b) = item.downcast::<PyBytes>() {
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

fn parse_txid_field(value: &Bound<'_, PyAny>, field: &str) -> Result<([u8; 32], String), String> {
    if let Ok(b) = value.downcast::<PyBytes>() {
        let slice = b.as_bytes();
        if slice.len() != 32 {
            return Err(format!("{} must be 32-byte txid", field));
        }
        let mut le = [0u8; 32];
        for (i, byte) in slice.iter().enumerate() {
            le[31 - i] = *byte;
        }
        return Ok((le, hex::encode(slice).to_lowercase()));
    }
    let hex_str: String = value
        .extract()
        .map_err(|_| format!("{} must be txid hex/bytes", field))?;
    let txid_bytes = hex::decode(&hex_str).map_err(|_| format!("{} invalid txid hex", field))?;
    if txid_bytes.len() != 32 {
        return Err(format!("{} invalid txid length", field));
    }
    let mut le = [0u8; 32];
    for (i, b) in txid_bytes.iter().enumerate() {
        le[31 - i] = *b;
    }
    Ok((le, hex_str.to_lowercase()))
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
        let (_txid_le, txid_hex) =
            parse_txid_field(&txid_field, "txid").map_err(|_| "tx_invalid_txid".to_string())?;

        let inputs_any = get_required(tx, "inputs", "tx_missing_inputs")?;
        let inputs_list = inputs_any
            .downcast::<PyList>()
            .map_err(|_| "tx_inputs_not_list".to_string())?;
        if inputs_list.is_empty() {
            return Err("tx_missing_inputs".to_string());
        }
        let mut inputs = Vec::with_capacity(inputs_list.len());
        for item in inputs_list {
            let inp = item
                .downcast::<PyDict>()
                .map_err(|_| "tx_input_not_dict".to_string())?;
            let txid_field = get_required(&inp, "txid", "tx_input_missing_txid")?;
            let (txid_le, txid_hex) =
                parse_txid_field(&txid_field, "tx_input_txid").map_err(|_| "tx_input_invalid_txid".to_string())?;
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
                txid_hex: txid_hex.to_lowercase(),
                txid_le,
                vout,
                sequence,
                witness,
            });
        }

        let outputs_any = get_required(tx, "outputs", "tx_missing_outputs")?;
        let outputs_list = outputs_any
            .downcast::<PyList>()
            .map_err(|_| "tx_outputs_not_list".to_string())?;
        let mut outputs = Vec::with_capacity(outputs_list.len());
        for item in outputs_list {
            let out = item
                .downcast::<PyDict>()
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
            txid_hex: txid_hex.to_lowercase(),
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
        enforce_low_s,
    })
}

fn build_utxo_index(utxo: &Bound<'_, PyDict>) -> Result<HashMap<String, UtxoEntry>, String> {
    let mut out = HashMap::with_capacity(utxo.len());
    let mut iter = utxo.iter();
    while let Some((key_obj, value_obj)) = iter.next() {
        let key: String = match key_obj.extract::<String>() {
            Ok(s) => s.to_lowercase(),
            Err(_) => continue,
        };
        let entry_dict = match value_obj.downcast::<PyDict>() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut script_bytes: Option<Vec<u8>> = None;
        let mut amount_val = None;
        if let Some(tx_out) = entry_dict
            .get_item("tx_out")
            .map_err(|_| "utxo_pyerr".to_string())?
        {
            if let Ok(tx_out_dict) = tx_out.downcast::<PyDict>() {
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
    let msg = match Message::from_digest_slice(digest) {
        Ok(m) => m,
        Err(_) => return false,
    };
    secp.verify_ecdsa(&msg, &norm, &pk).is_ok()
}

fn validate_transaction_parts(
    tx: &TxParts,
    spend_height: u64,
    utxo_map: &mut HashMap<String, UtxoEntry>,
    opts: &ValidationOptions,
    secp: &Secp256k1<secp256k1::VerifyOnly>,
) -> Result<(u64, u32), String> {
    let mut seen_prevouts = HashSet::new();
    let mut input_sum: u128 = 0;
    let mut sigops_tx: u32 = 0;
    let cache = build_sighash_cache(tx);

    for (idx, inp) in tx.inputs.iter().enumerate() {
        let key = format!("{}:{}", inp.txid_hex, inp.vout);
        if !seen_prevouts.insert(key.clone()) {
            return Err("duplicate_prevout_in_tx".to_string());
        }
        let entry = match utxo_map.remove(&key) {
            Some(e) => e,
            None => return Err(format!("prevout_missing {}", key)),
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
        let key = format!("{}:{}", tx.txid_hex, idx);
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
        .downcast::<PyList>()
        .map_err(|_| "transactions_not_list".to_string())?;
    if txs.len() < 1 {
        return Err("empty_block_transactions".to_string());
    }
    let mut fees = Vec::with_capacity(txs.len().saturating_sub(1));
    let mut total_sigops = 0u32;

    for (idx, item) in txs.iter().enumerate() {
        let tx_dict = item
            .downcast::<PyDict>()
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
        Ok(Some(v)) => v.downcast::<PyList>().map(|l| l.len()).unwrap_or(0),
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
