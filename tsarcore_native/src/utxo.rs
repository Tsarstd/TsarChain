// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md
// Refs: UTXO apply-set; LMDB batch compatible; P2WPKH

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

fn op_return(script: &[u8]) -> bool {
    !script.is_empty() && script[0] == 0x6a
}

/// Build UTXO delta ops (delete spent prevouts, insert new outputs) from
/// the compact TX format used by `validate_block_txs_compact`.
///
/// Input `block_txs`: list of tuples
///   (version, locktime, inputs:list, outputs:list, txid:bytes32, is_coinbase:bool)
/// Each input tuple: (prev_txid:bytes32, vout:u32, sequence:u32, witness:list|bytes[])
/// Each output tuple: (amount:u64, script_pubkey:bytes)
///
/// Output: Python list of tuples:
///   (key:str, amount:Optional[u64], script:Optional[bytes], is_coinbase:Optional[bool], height:Optional[i64])
/// - Deletes are encoded as (key, None, None, None, None)
/// - Inserts have all fields set (amount, script, is_coinbase, height)
///
/// Notes:
/// - OP_RETURN outputs are skipped (unspendable)
/// - No signature/amount validation is performed here; this is purely a delta builder.

#[pyfunction]
#[pyo3(signature = (block_txs, spend_height))]
pub fn utxo_build_ops_compact<'py>(
    py: Python<'py>,
    block_txs: &Bound<'py, PyList>,
    spend_height: u64,
) -> PyResult<Bound<'py, PyList>> {
    let ops = PyList::empty(py);

    for tx_any in block_txs {
        let tx = tx_any
            .cast::<PyTuple>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_not_tuple"))?;
        if tx.len() < 6 {
            return Err(PyErr::new::<exceptions::PyValueError, _>(
                "tx_tuple_arity",
            ));
        }

        let inputs_any = tx
            .get_item(2)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_inputs"))?;
        let inputs = inputs_any
            .cast::<PyList>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_inputs_not_list"))?;

        let outputs_any = tx
            .get_item(3)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_outputs"))?;
        let outputs = outputs_any
            .cast::<PyList>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_outputs_not_list"))?;

        let txid_item = tx
            .get_item(4)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_txid"))?;
        let txid_bytes = txid_item
            .cast::<PyBytes>()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_txid_not_bytes"))?;
        let txid_raw = txid_bytes.as_bytes();
        if txid_raw.len() != 32 {
            return Err(PyErr::new::<exceptions::PyValueError, _>(
                "tx_txid_length",
            ));
        }
        let is_coinbase: bool = tx
            .get_item(5)
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_tuple_coinbase"))?
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyValueError, _>("tx_coinbase_invalid"))?;

        // Spent prevouts -> delete
        if !is_coinbase {
            for inp_any in inputs {
                let inp = inp_any
                    .cast::<PyTuple>()
                    .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_not_tuple",
                    ))?;
                if inp.len() < 2 {
                    return Err(PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_tuple_arity",
                    ));
                }
                let prev_txid_item = inp
                    .get_item(0)
                    .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_tuple_txid",
                    ))?;
                let prev_txid = prev_txid_item
                    .cast::<PyBytes>()
                    .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_txid_not_bytes",
                    ))?;
                let prev_txid_raw = prev_txid.as_bytes();
                if prev_txid_raw.len() != 32 {
                    return Err(PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_txid_length",
                    ));
                }
                let vout: u32 = inp
                    .get_item(1)
                    .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_tuple_vout",
                    ))?
                    .extract()
                    .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                        "tx_input_invalid_vout",
                    ))?;

                let key = format!("{}:{}", hex::encode(prev_txid_raw), vout);
                ops.append((
                    key,
                    None::<u64>,
                    None::<Vec<u8>>,
                    None::<bool>,
                    None::<i64>,
                ))?;
            }
        }

        // New outputs -> insert
        for (idx, out_any) in outputs.iter().enumerate() {
            let out_t = out_any.cast::<PyTuple>().map_err(|_| {
                PyErr::new::<exceptions::PyValueError, _>("tx_output_not_tuple")
            })?;
            if out_t.len() < 2 {
                return Err(PyErr::new::<exceptions::PyValueError, _>(
                    "tx_output_tuple_arity",
                ));
            }
            let amount: u64 = out_t
                .get_item(0)
                .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                    "tx_output_tuple_amount",
                ))?
                .extract()
                .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                    "tx_output_invalid_amount",
                ))?;
            let spk_item = out_t
                .get_item(1)
                .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                    "tx_output_tuple_script",
                ))?;
            let spk_bytes = spk_item
                .cast::<PyBytes>()
                .map_err(|_| PyErr::new::<exceptions::PyValueError, _>(
                    "tx_output_script_not_bytes",
                ))?
                .as_bytes()
                .to_vec();

            if op_return(&spk_bytes) {
                continue;
            }

            let key = format!("{}:{}", hex::encode(txid_raw), idx as u32);
            let py_spk = PyBytes::new(py, &spk_bytes);
            ops.append((key, amount, py_spk, is_coinbase, spend_height as i64))?;
        }
    }

    Ok(ops)
}
