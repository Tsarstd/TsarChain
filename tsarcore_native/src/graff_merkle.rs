// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md

use std::fs::File;
use pyo3::exceptions;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
use pyo3::types::{PyAny, PyBytes, PyDict, PyIterator, PyList};


fn log_py(level: &str, msg: &str) {
    Python::attach(|py| {
        if let Ok(logging) = py.import("logging") {
            if let Ok(logger) = logging.call_method1("getLogger", ("tsarchain.native",)) {
                let _ = logger.call_method1(level, (msg,));
            }
        }
    });
}
// #[inline]
// fn log_debug(msg: &str) {
//     log_py("info", msg);
// }
#[inline]
fn log_warning(msg: &str) {
    log_py("warning", msg);
}


fn sha256_once(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256_once(&buf)
}

fn parse_hex32(input: &str) -> Option<[u8; 32]> {
    let s = input.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = match hex::decode(s) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn build_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            let last = *leaves.last().unwrap();
            leaves.push(last);
        }
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for i in (0..leaves.len()).step_by(2) {
            next.push(hash_pair(&leaves[i], &leaves[i + 1]));
        }
        leaves = next;
    }
    leaves[0]
}

pub(crate) fn build_path_internal(leaves: Vec<[u8; 32]>, index: usize) -> Result<Vec<(char, [u8; 32])>, PyErr> {
    if leaves.is_empty() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "empty_merkle_leaves",
        ));
    }
    if index >= leaves.len() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "merkle_index_out_of_range",
        ));
    }
    let mut path: Vec<(char, [u8; 32])> = Vec::new();
    let mut level = leaves;
    let mut idx = index;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let sibling_idx = idx ^ 1;
        let side = if idx % 2 == 1 { 'L' } else { 'R' };
        path.push((side, level[sibling_idx]));
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for i in (0..level.len()).step_by(2) {
            next.push(hash_pair(&level[i], &level[i + 1]));
        }
        idx /= 2;
        level = next;
    }
    Ok(path)
}

pub(crate) fn leaves_from_bytes_internal(data: &[u8], chunk_size: usize) -> Result<Vec<[u8; 32]>, PyErr> {
    if chunk_size == 0 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "bad_merkle_chunk",
        ));
    }
    if data.is_empty() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "empty_merkle_leaves",
        ));
    }
    let mut leaves = Vec::new();
    for part in data.chunks(chunk_size) {
        if part.is_empty() {
            break;
        }
        leaves.push(sha256_once(part));
    }
    if leaves.is_empty() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "empty_merkle_leaves",
        ));
    }
    Ok(leaves)
}

fn leaves_from_reader(reader: &mut dyn Read, chunk_size: usize) -> Result<Vec<[u8; 32]>, PyErr> {
    if chunk_size == 0 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "bad_merkle_chunk",
        ));
    }
    let mut leaves = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| PyErr::new::<exceptions::PyIOError, _>(e.to_string()))?;
        if n == 0 {
            break;
        }
        leaves.push(sha256_once(&buf[..n]));
    }
    if leaves.is_empty() {
        return Err(PyErr::new::<exceptions::PyValueError, _>(
            "empty_merkle_leaves",
        ));
    }
    Ok(leaves)
}

pub(crate) fn path_to_pylist<'py>(py: Python<'py>, path: Vec<(char, [u8; 32])>) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty(py);
    for (side, hash) in path {
        let dict = PyDict::new(py);
        dict.set_item("side", side.to_string())?;
        dict.set_item("hash", hex::encode(hash))?;
        out.append(dict)?;
    }
    Ok(out)
}

#[pyfunction]
pub fn graff_merkle_root_for_file<'py>(
    py: Python<'py>,
    path: &str,
    chunk_size: usize,
) -> PyResult<(Bound<'py, PyBytes>, usize)> {
    let file = File::open(path)
        .map_err(|e| {
            log_warning(&format!("graff_merkle_root_for_file open error={}", e));
            PyErr::new::<exceptions::PyFileNotFoundError, _>(e.to_string())
        })?;
    let mut reader = BufReader::new(file);
    let leaves = match leaves_from_reader(&mut reader, chunk_size) {
        Ok(v) => v,
        Err(e) => {
            log_warning(&format!("graff_merkle_root_for_file error={}", e));
            return Err(e);
        }
    };
    let count = leaves.len();
    let root = build_root(leaves);
    Ok((PyBytes::new(py, &root), count))
}



#[pyfunction]
pub fn graff_merkle_path_for_file<'py>(
    py: Python<'py>,
    path: &str,
    chunk_size: usize,
    index: usize,
) -> PyResult<Bound<'py, PyList>> {
    let file = File::open(path)
        .map_err(|e| {
            log_warning(&format!("graff_merkle_path_for_file open error={}", e));
            PyErr::new::<exceptions::PyFileNotFoundError, _>(e.to_string())
        })?;
    let mut reader = BufReader::new(file);
    let leaves = match leaves_from_reader(&mut reader, chunk_size) {
        Ok(v) => v,
        Err(e) => {
            log_warning(&format!("graff_merkle_path_for_file error={}", e));
            return Err(e);
        }
    };
    let path = match build_path_internal(leaves, index) {
        Ok(v) => v,
        Err(e) => {
            log_warning(&format!("graff_merkle_path_for_file error={}", e));
            return Err(e);
        }
    };
    let out = path_to_pylist(py, path)?;
    Ok(out)
}

#[pyfunction]
pub fn graff_merkle_verify(root_hex: &str, leaf_hex: &str, path_any: Bound<'_, PyAny>) -> PyResult<bool> {
    let root = match parse_hex32(root_hex) {
        Some(v) => v,
        None => {
            log_warning("graff_merkle_verify bad_root");
            return Ok(false);
        }
    };
    let mut cur = match parse_hex32(leaf_hex) {
        Some(v) => v,
        None => {
            log_warning("graff_merkle_verify bad_leaf");
            return Ok(false);
        }
    };
    let iter = match PyIterator::from_object(&path_any) {
        Ok(v) => v,
        Err(_) => {
            log_warning("graff_merkle_verify bad_path_iter");
            return Ok(false);
        }
    };
    for item in iter {
        let obj = match item {
            Ok(v) => v,
            Err(_) => {
                log_warning("graff_merkle_verify bad_path_item");
                return Ok(false);
            }
        };
        let dict = match obj.cast::<PyDict>() {
            Ok(d) => d,
            Err(_) => {
                log_warning("graff_merkle_verify bad_path_dict");
                return Ok(false);
            }
        };
        let side_obj = match dict.get_item("side") {
            Ok(v) => v,
            Err(_) => {
                log_warning("graff_merkle_verify missing_side");
                return Ok(false);
            }
        };
        let hash_obj = match dict.get_item("hash") {
            Ok(v) => v,
            Err(_) => {
                log_warning("graff_merkle_verify missing_hash");
                return Ok(false);
            }
        };
        let side: String = match side_obj {
            Some(v) => match v.extract() {
                Ok(s) => s,
                Err(_) => {
                    log_warning("graff_merkle_verify bad_side");
                    return Ok(false);
                }
            },
            None => {
                log_warning("graff_merkle_verify bad_side_none");
                return Ok(false);
            }
        };
        let hash_hex: String = match hash_obj {
            Some(v) => match v.extract() {
                Ok(s) => s,
                Err(_) => {
                    log_warning("graff_merkle_verify bad_hash");
                    return Ok(false);
                }
            },
            None => {
                log_warning("graff_merkle_verify bad_hash_none");
                return Ok(false);
            }
        };
        let sib = match parse_hex32(&hash_hex) {
            Some(v) => v,
            None => {
                log_warning("graff_merkle_verify bad_hash_hex");
                return Ok(false);
            }
        };
        match side.trim().to_uppercase().as_str() {
            "L" => cur = hash_pair(&sib, &cur),
            "R" => cur = hash_pair(&cur, &sib),
            _ => {
                log_warning("graff_merkle_verify bad_side_value");
                return Ok(false);
            }
        }
    }
    let ok = cur == root;
    Ok(ok)
}
