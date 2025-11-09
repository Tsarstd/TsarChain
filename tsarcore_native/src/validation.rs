// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md
// Refs: see REFERENCES.md

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyAnyMethods, PyDict, PyDictMethods, PyList, PyListMethods};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::collections::{HashMap, HashSet};

use crate::bip143_native;

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
    script_sig: Vec<u8>,
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
    code.push(0x19);
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

fn serialize_tx_parts(tx: &TxParts, include_witness: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&tx.version.to_le_bytes());

    let has_witness = include_witness && tx.inputs.iter().any(|inp| !inp.witness.is_empty());
    if has_witness {
        buf.extend_from_slice(&[0x00, 0x01]);
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

    if has_witness {
        for inp in &tx.inputs {
            encode_varint(inp.witness.len() as u64, &mut buf);
            for item in &inp.witness {
                encode_varint(item.len() as u64, &mut buf);
                buf.extend_from_slice(item);
            }
        }
    }

    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    buf
}

fn parse_hex_field(value: &Bound<'_, PyAny>, field: &str) -> Result<Vec<u8>, String> {
    let hex_str: String = value
        .extract()
        .map_err(|_| format!("field {} must be hex string", field))?;
    if hex_str.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex_str)
        .map_err(|_| format!("failed decoding hex in field {}", field))
}

fn parse_witness_field(value: Option<Bound<'_, PyAny>>) -> Result<Vec<Vec<u8>>, String> {
    let Some(obj) = value else { return Ok(Vec::new()); };
    let list = obj
        .downcast::<PyList>()
        .map_err(|_| "witness must be list".to_string())?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        let hex_item: String = item
            .extract()
            .map_err(|_| "witness element must be hex string".to_string())?;
        let bytes = hex::decode(hex_item)
            .map_err(|_| "invalid witness hex".to_string())?;
        out.push(bytes);
    }
    Ok(out)
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
            Some(v) => v
                .extract()
                .map_err(|_| "tx_invalid_locktime".to_string())?,
            None => 0,
        };

        let txid_hex: String = get_required(tx, "txid", "tx_missing_txid")?
            .extract()
            .map_err(|_| "tx_invalid_txid".to_string())?;

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
            let txid_hex: String = get_required(&inp, "txid", "tx_input_missing_txid")?
                .extract()
                .map_err(|_| "tx_input_invalid_txid".to_string())?;
            let txid_bytes = hex::decode(&txid_hex)
                .map_err(|_| "tx_input_invalid_txid".to_string())?;
            if txid_bytes.len() != 32 {
                return Err("tx_input_invalid_txid".to_string());
            }
            let mut txid_le = [0u8; 32];
            for (i, b) in txid_bytes.iter().enumerate() {
                txid_le[31 - i] = *b;
            }
            let vout: u32 = get_required(&inp, "vout", "tx_input_missing_vout")?
                .extract()
                .map_err(|_| "tx_input_invalid_vout".to_string())?;
            let script_sig = if let Some(sig_any) = get_optional(inp, "script_sig")? {
                parse_hex_field(&sig_any, "script_sig")?
            } else {
                Vec::new()
            };
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
                script_sig,
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
            let script_pubkey = parse_hex_field(&script_hex, "script_pubkey")?;
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
    let coinbase_maturity = get_required(opts, "coinbase_maturity", "opts_missing_coinbase_maturity")?
        .extract::<i64>()
        .map_err(|_| "opts_invalid_coinbase_maturity".to_string())?;
    let max_sigops_per_tx = get_required(opts, "max_sigops_per_tx", "opts_missing_max_sigops_per_tx")?
        .extract::<u32>()
        .map_err(|_| "opts_invalid_max_sigops_per_tx".to_string())?;
    let max_sigops_per_block = get_required(opts, "max_sigops_per_block", "opts_missing_max_sigops_per_block")?
        .extract::<u32>()
        .map_err(|_| "opts_invalid_max_sigops_per_block".to_string())?;
    let enforce_low_s = match get_optional(opts, "enforce_low_s")? {
        Some(v) => v.extract().map_err(|_| "opts_invalid_enforce_low_s".to_string())?,
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
    let mut out = HashMap::new();
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
        let mut script_hex = None;
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
                    script_hex = spk.extract::<String>().ok();
                }
                if let Some(am) = tx_out_dict
                    .get_item("amount")
                    .map_err(|_| "utxo_pyerr".to_string())?
                {
                    amount_val = am.extract::<u64>().ok();
                }
            }
        }
        if script_hex.is_none() {
            if let Some(spk) = entry_dict
                .get_item("script_pubkey")
                .map_err(|_| "utxo_pyerr".to_string())?
            {
                script_hex = spk.extract::<String>().ok();
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
        let script_hex = match script_hex {
            Some(s) => s,
            None => continue,
        };
        let amount = match amount_val {
            Some(a) => a,
            None => continue,
        };
        let script = match hex::decode(script_hex) {
            Ok(v) => v,
            Err(_) => continue,
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
) -> Result<(u64, u32), String> {
    let secp = Secp256k1::verification_only();
    let tx_bytes = serialize_tx_parts(tx, true);
    let mut seen_prevouts = HashSet::new();
    let mut input_sum: u128 = 0;
    let mut sigops_tx: u32 = 0;

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
                if (sighash_type & 0x1f) != 0x01 {
                    return Err("unsupported_sighash".to_string());
                }
                let sig_der = &sig_full[..sig_full.len() - 1];
                let pubkey = &inp.witness[1];
                if hash160_bytes(pubkey) != hash20 {
                    return Err("pubkey_hash_mismatch".to_string());
                }
                let script_code = build_p2wpkh_script_code(&hash20);
                let digest = bip143_native::compute_sighash(
                    &tx_bytes,
                    idx as u32,
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
            validate_transaction_parts(&tx_parts, spend_height, &mut utxo_map, &opts)?;
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
    match validate_block_impl(block, utxo, spend_height, opts) {
        Ok(fees) => Ok((true, None, Some(fees))),
        Err(reason) => Ok((false, Some(reason), None)),
    }
}
