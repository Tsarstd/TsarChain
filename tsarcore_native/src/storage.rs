// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE and TRADEMARKS.md
// Refs: LMDB; Atomic JSON; serde_json; pyo3

use libc::size_t;
use lmdb::{Cursor, Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use lmdb_sys as ffi;
use parking_lot::Mutex;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use hex;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::raw::c_uint;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;
use tempfile::NamedTempFile;

const DEFAULT_LMDB_MAP_INIT: usize = 4 * 1024 * 1024; // 4 MB
const DEFAULT_LMDB_MAP_MAX: u64 = 64 * 1024 * 1024 * 1024; // 64 GB
const DEFAULT_MAX_DBS: u32 = 16;

fn map_err(context: &str, err: impl std::fmt::Display) -> PyErr {
    PyErr::new::<PyRuntimeError, _>(format!("{context}: {err}"))
}

fn log_py(level: &str, msg: &str) {
    Python::attach(|py| {
        if let Ok(logging) = py.import("logging") {
            if let Ok(logger) = logging.call_method1("getLogger", ("tsarchain.native",)) {
                let _ = logger.call_method1(level, (msg,));
            }
        }
    });
}

//#[inline]
//fn log_debug(msg: &str) {
//    log_py("debug", msg);
//} Note: Database creation log removed for performance/cleanliness

// #[inline]
// fn log_info(msg: &str) {
//     log_py("info", msg);
// }

#[inline]
fn log_warning(msg: &str) {
    log_py("warning", msg);
}

// ===== Raw JSON file helpers (compatible with existing on-disk JSON) =====

fn ensure_parent(path: &Path) -> PyResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| map_err("json mkdir", e))?;
        }
    }
    Ok(())
}

#[pyfunction]
pub fn json_read_file(path: &str) -> PyResult<Option<String>> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(None);
    }
    let f = fs::File::open(p).map_err(|e| map_err("json_read_file open", e))?;
    let mut reader = BufReader::new(f);
    let mut buf = String::new();
    reader
        .read_to_string(&mut buf)
        .map_err(|e| map_err("json_read_file read", e))?;
    Ok(Some(buf))
}

#[pyfunction]
#[pyo3(signature = (path, data, pretty=true))]
pub fn json_write_file(path: &str, data: &str, pretty: bool) -> PyResult<()> {
    let p = Path::new(path);
    ensure_parent(p)?;
    // Optional pretty formatting (reformat for consistency)
    let payload = if pretty {
        match serde_json::from_str::<JsonValue>(data) {
            Ok(val) => {
                let mut s = serde_json::to_string_pretty(&val).unwrap_or_else(|_| data.to_string());
                if !s.ends_with('\n') {
                    s.push('\n');
                }
                s
            }
            Err(_) => data.to_string(),
        }
    } else {
        data.to_string()
    };

    let tmp = NamedTempFile::new_in(p.parent().unwrap_or(Path::new(".")))
        .map_err(|e| map_err("json_write_file tmp", e))?;
    {
        let mut writer = BufWriter::new(tmp.as_file());
        writer
            .write_all(payload.as_bytes())
            .map_err(|e| map_err("json_write_file write", e))?;
        writer
            .flush()
            .map_err(|e| map_err("json_write_file flush", e))?;
    }
    tmp.persist(p)
        .map_err(|e| map_err("json_write_file persist", e.error))?;
    Ok(())
}

// ============================
// LMDB backend
// ============================

#[derive(Clone)]
struct LmdbBackend {
    env: Arc<Environment>,
    map_size_max: usize,
}

impl LmdbBackend {
    fn new(path: &Path, map_size_init: usize, map_size_max: usize) -> PyResult<Self> {
        if map_size_init == 0 {
            return Err(PyValueError::new_err("map_size_init must be > 0"));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| map_err("lmdb mkdir", e))?;
        }
        fs::create_dir_all(path).map_err(|e| map_err("lmdb mkdir", e))?;

        let mut builder = Environment::new();
        builder.set_max_dbs(DEFAULT_MAX_DBS);
        let _ = builder.set_map_size(map_size_init);
        let env = builder.open(path).map_err(|e| map_err("lmdb open", e))?;

        Ok(Self {
            env: Arc::new(env),
            map_size_max,
        })
    }

    fn grow_to_max(&self) -> PyResult<()> {
        if self.map_size_max == 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "map_size_max not configured for growth",
            ));
        }

        // Inspect current map size
        let mut info: ffi::MDB_envinfo = unsafe { std::mem::zeroed() };
        let rc_info = unsafe { ffi::mdb_env_info(self.env.env(), &mut info) };
        if rc_info != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "lmdb env_info failed rc={rc_info}"
            )));
        }
        let current = info.me_mapsize as usize;
        let target = {
            let doubled = current.saturating_mul(2);
            let max_allowed = self.map_size_max;
            let next = std::cmp::min(doubled.max(current + 1), max_allowed);
            if next <= current {
                max_allowed
            } else {
                next
            }
        };
        if target <= current {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "lmdb map already at or above configured max",
            ));
        }

        let rc = unsafe { ffi::mdb_env_set_mapsize(self.env.env(), target as size_t) };
        if rc != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "lmdb set_mapsize failed rc={rc}"
            )));
        }
        log_warning(&format!(
            "[lmdb] map size increased from {} to {} bytes (max={})",
            current, target, self.map_size_max
        ));
        Ok(())
    }

    fn open_db(&self, name: &str) -> PyResult<Database> {
        match self.env.open_db(Some(name)) {
            Ok(db) => Ok(db),
            Err(lmdb::Error::NotFound) => self
                .env
                .create_db(Some(name), DatabaseFlags::default())
                .map_err(|e| map_err("lmdb create_db", e)),
                //.inspect(|_| log_info(&format!("[lmdb] created db '{}'", name))),   Note: Database creation log removed for performance/cleanliness
            Err(e) => Err(map_err("lmdb open_db", e)),
        }
    }

    fn put(&self, db_name: &str, key: &[u8], val: &[u8]) -> PyResult<()> {
        let db = self.open_db(db_name)?;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
        match txn.put(db, &key, &val, WriteFlags::empty()) {
            Ok(_) => txn.commit().map_err(|e| map_err("lmdb commit", e)),
            Err(lmdb::Error::MapFull) => {
                log_warning(&format!(
                    "[lmdb] map full on put db={} key_len={} val_len={}, trying grow_to_max",
                    db_name,
                    key.len(),
                    val.len()
                ));
                drop(txn);
                self.grow_to_max()?;
                let mut retry_txn = self
                    .env
                    .begin_rw_txn()
                    .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
                retry_txn
                    .put(db, &key, &val, WriteFlags::empty())
                    .map_err(|e| map_err("lmdb put retry", e))?;
                retry_txn.commit().map_err(|e| map_err("lmdb commit", e))
            }
            Err(e) => Err(map_err("lmdb put", e)),
        }
    }

    fn delete(&self, db_name: &str, key: &[u8]) -> PyResult<bool> {
        let db = self.open_db(db_name)?;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
        match txn.del(db, &key, None) {
            Ok(_) => {
                txn.commit().map_err(|e| map_err("lmdb commit", e))?;
                Ok(true)
            }
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(lmdb::Error::MapFull) => {
                log_warning(&format!(
                    "[lmdb] map full on delete db={} key_len={}, trying grow_to_max",
                    db_name,
                    key.len()
                ));
                drop(txn);
                self.grow_to_max()?;
                let mut retry = self
                    .env
                    .begin_rw_txn()
                    .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
                let result = retry
                    .del(db, &key, None)
                    .map(|_| true)
                    .or_else(|err| match err {
                        lmdb::Error::NotFound => Ok(false),
                        other => Err(map_err("lmdb delete", other)),
                    })?;
                retry.commit().map_err(|e| map_err("lmdb commit", e))?;
                Ok(result)
            }
            Err(e) => Err(map_err("lmdb delete", e)),
        }
    }

    fn get(&self, db_name: &str, key: &[u8]) -> PyResult<Option<Vec<u8>>> {
        let db = self.open_db(db_name)?;
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| map_err("lmdb begin_ro_txn", e))?;
        let out = match txn.get(db, &key) {
            Ok(bytes) => Some(bytes.to_vec()),
            Err(lmdb::Error::NotFound) => None,
            Err(e) => return Err(map_err("lmdb get", e)),
        };
        Ok(out)
    }

    fn iter_prefix(&self, db_name: &str, prefix: &[u8]) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let db = self.open_db(db_name)?;
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| map_err("lmdb begin_ro_txn", e))?;
        let mut cursor = txn
            .open_ro_cursor(db)
            .map_err(|e| map_err("lmdb cursor", e))?;
        let mut items = Vec::new();
        for (k, v) in cursor.iter() {
            if k.starts_with(prefix) {
                items.push((k.to_vec(), v.to_vec()));
            } else if !prefix.is_empty() && k > prefix {
                // keys are ordered; once passed prefix range we can stop
                break;
            }
        }
        //log_debug(&format!(
        //    "[lmdb] iter_prefix db={} prefix_len={} items={}",
        //    db_name,
        //    prefix.len(),
        //    items.len()
        //));  Note: Database creation log removed for performance/cleanliness
        Ok(items)
    }

    fn iter_prefix_chunk(
        &self,
        db_name: &str,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        limit: usize,
    ) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let db = self.open_db(db_name)?;
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| map_err("lmdb begin_ro_txn", e))?;
        let mut cursor = txn
            .open_ro_cursor(db)
            .map_err(|e| map_err("lmdb cursor", e))?;

        let mut items = Vec::with_capacity(limit);
        let start_after = start_after.map(|s| s.to_vec());
        for (k, v) in cursor.iter() {
            if !prefix.is_empty() && !k.starts_with(prefix) {
                if k > prefix {
                    break;
                }
                continue;
            }
            if let Some(ref after) = start_after {
                if k <= &after[..] {
                    continue;
                }
            }
            items.push((k.to_vec(), v.to_vec()));
            if items.len() >= limit {
                break;
            }
        }
        Ok(items)
    }

    fn put_batch(&self, db_name: &str, ops: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> PyResult<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let db = self.open_db(db_name)?;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
        let mut map_full = false;
        for (k, maybe_v) in ops.iter() {
            let res = match maybe_v {
                Some(v) => txn.put(db, &k, &v, WriteFlags::empty()),
                None => txn.del(db, &k, None),
            };
            match res {
                Ok(_) => {}
                Err(lmdb::Error::MapFull) => {
                    map_full = true;
                    break;
                }
                Err(e) => return Err(map_err("lmdb put_batch", e)),
            }
        }
        if map_full {
            drop(txn);
            self.grow_to_max()?;
            let db_retry = self.open_db(db_name)?;
            let mut txn2 = self
                .env
                .begin_rw_txn()
                .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
            for (k, maybe_v) in ops {
                let res = match maybe_v {
                    Some(v) => txn2.put(db_retry, &k, &v, WriteFlags::empty()),
                    None => txn2.del(db_retry, &k, None),
                };
                res.map_err(|e| map_err("lmdb put_batch retry", e))?;
            }
            txn2
                .commit()
                .map_err(|e| map_err("lmdb commit batch", e))
        } else {
            txn.commit()
                .map_err(|e| map_err("lmdb commit batch", e))
        }
    }

    fn clear_db(&self, db_name: &str) -> PyResult<u64> {
        let db = self.open_db(db_name)?;
        let mut txn = self
            .env
            .begin_rw_txn()
            .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
        txn.clear_db(db).map_err(|e| map_err("lmdb clear_db", e))?;
        // No stat available; removed count is unknown here.
        txn.commit().map_err(|e| map_err("lmdb commit", e))?;
        Ok(0)
    }

    fn copy_env(&self, dest: &str, compact: bool) -> PyResult<()> {
        let path = Path::new(dest);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| map_err("lmdb copy mkdir", e))?;
        }
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| map_err("lmdb copy path", e))?;
        let flags: c_uint = if compact {
            ffi::MDB_CP_COMPACT as c_uint
        } else {
            0
        };
        let rc = unsafe { ffi::mdb_env_copy2(self.env.env(), c_path.as_ptr(), flags) };
        if rc != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "lmdb copy failed rc={rc}"
            )));
        }
        //log_info(&format!(
        //    "[lmdb] copy env -> {} (compact={})",
        //    path.display(),
        //    compact
        //)); Note: Database creation log removed for performance/cleanliness
        Ok(())
    }
}

// ============================
// JSON backend (atomic file)
// ============================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", content = "value")]
enum JsonEntry {
    #[serde(rename = "bytes")]
    Bytes(String), // hex-encoded
    #[serde(rename = "json")]
    Json(JsonValue),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct JsonSnapshot {
    #[serde(default = "json_format_v1")]
    format: String,
    #[serde(default)]
    entries: HashMap<String, JsonEntry>, // key hex -> entry
}

fn json_format_v1() -> String {
    "native_storage_v1".to_string()
}

impl Default for JsonSnapshot {
    fn default() -> Self {
        Self {
            format: json_format_v1(),
            entries: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct JsonBackend {
    root: PathBuf,
    pretty: bool,
    lock: Arc<Mutex<()>>,
}

impl JsonBackend {
    fn new(root: PathBuf, pretty: bool) -> Self {
        Self {
            root,
            pretty,
            lock: Arc::new(Mutex::new(())),
        }
    }

    fn path_for(&self, db: &str) -> PathBuf {
        if db.to_lowercase().ends_with(".json") {
            PathBuf::from(&self.root).join(db)
        } else {
            PathBuf::from(&self.root).join(format!("{db}.json"))
        }
    }

    fn load(&self, db: &str) -> PyResult<JsonSnapshot> {
        let path = self.path_for(db);
        if !path.exists() {
            return Ok(JsonSnapshot::default());
        }
        let file = fs::File::open(&path).map_err(|e| map_err("json open", e))?;
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| map_err("json read", e))?;
        let snap: JsonSnapshot =
            serde_json::from_slice(&buf).map_err(|e| map_err("json parse", e))?;
        Ok(snap)
    }

    fn persist(&self, db: &str, snap: &JsonSnapshot) -> PyResult<()> {
        let path = self.path_for(db);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| map_err("json mkdir", e))?;
        }
        let tmp = NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))
            .map_err(|e| map_err("json tmp", e))?;
        {
            let file = tmp.as_file();
            let mut writer = BufWriter::new(file);
            if self.pretty {
                serde_json::to_writer_pretty(&mut writer, snap)
                    .map_err(|e| map_err("json write", e))?;
            } else {
                serde_json::to_writer(&mut writer, snap).map_err(|e| map_err("json write", e))?;
            }
            writer.flush().map_err(|e| map_err("json flush", e))?;
        }
        tmp.persist(&path)
            .map_err(|e| map_err("json persist", e.error))?;
        Ok(())
    }

    fn serialize_json_bytes(val: &JsonValue) -> PyResult<Vec<u8>> {
        serde_json::to_vec(val).map_err(|e| map_err("json encode", e))
    }

    fn get(&self, db: &str, key: &[u8]) -> PyResult<Option<Vec<u8>>> {
        let _guard = self.lock.lock();
        let snap = self.load(db)?;
        let key_hex = hex::encode(key);
        if let Some(entry) = snap.entries.get(&key_hex) {
            match entry {
                JsonEntry::Bytes(data_hex) => {
                    let v = hex::decode(data_hex).map_err(|e| map_err("json decode hex", e))?;
                    return Ok(Some(v));
                }
                JsonEntry::Json(j) => {
                    let v = Self::serialize_json_bytes(j)?;
                    return Ok(Some(v));
                }
            }
        }
        Ok(None)
    }

    fn put_bytes(&self, db: &str, key: &[u8], val: &[u8]) -> PyResult<()> {
        let _guard = self.lock.lock();
        let mut snap = self.load(db)?;
        let key_hex = hex::encode(key);
        snap.entries
            .insert(key_hex, JsonEntry::Bytes(hex::encode(val)));
        self.persist(db, &snap)
    }

    fn put_json_text(&self, db: &str, key: &[u8], json_text: &str) -> PyResult<()> {
        let val: JsonValue =
            serde_json::from_str(json_text).map_err(|e| map_err("json parse input", e))?;
        let _guard = self.lock.lock();
        let mut snap = self.load(db)?;
        snap.entries.insert(hex::encode(key), JsonEntry::Json(val));
        self.persist(db, &snap)
    }

    fn delete(&self, db: &str, key: &[u8]) -> PyResult<bool> {
        let _guard = self.lock.lock();
        let mut snap = self.load(db)?;
        let removed = snap.entries.remove(&hex::encode(key)).is_some();
        if removed {
            self.persist(db, &snap)?;
        }
        Ok(removed)
    }

    fn clear_db(&self, db: &str) -> PyResult<u64> {
        let _guard = self.lock.lock();
        let mut snap = self.load(db)?;
        let removed = snap.entries.len() as u64;
        snap.entries.clear();
        self.persist(db, &snap)?;
        Ok(removed)
    }

    fn iter_prefix(&self, db: &str, prefix: &[u8]) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let _guard = self.lock.lock();
        let snap = self.load(db)?;
        let prefix_hex = hex::encode(prefix);
        let mut rows: Vec<(Vec<u8>, Vec<u8>)> = snap
            .entries
            .iter()
            .filter_map(|(k, v)| {
                if !k.starts_with(&prefix_hex) {
                    return None;
                }
                let key_bytes = match hex::decode(k) {
                    Ok(b) => b,
                    Err(_) => return None,
                };
                let val_bytes = match v {
                    JsonEntry::Bytes(h) => hex::decode(h).ok(),
                    JsonEntry::Json(j) => Self::serialize_json_bytes(j).ok(),
                }?;
                Some((key_bytes, val_bytes))
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(rows)
    }

    fn get_json_string(&self, db: &str, key: &[u8]) -> PyResult<Option<String>> {
        let _guard = self.lock.lock();
        let snap = self.load(db)?;
        let key_hex = hex::encode(key);
        if let Some(entry) = snap.entries.get(&key_hex) {
            match entry {
                JsonEntry::Json(v) => {
                    return serde_json::to_string(v)
                        .map(Some)
                        .map_err(|e| map_err("json encode", e));
                }
                JsonEntry::Bytes(raw_hex) => {
                    let bytes = hex::decode(raw_hex).map_err(|e| map_err("json decode hex", e))?;
                    if let Ok(text) = str::from_utf8(&bytes) {
                        if let Ok(val) = serde_json::from_str::<JsonValue>(text) {
                            return serde_json::to_string(&val)
                                .map(Some)
                                .map_err(|e| map_err("json encode", e));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

// ============================
// Fused storage exposed to Python
// ============================

#[derive(Clone)]
enum Backend {
    Lmdb(LmdbBackend),
    Json(JsonBackend),
}

#[pyclass(name = "NativeStorage")]
pub struct NativeStorage {
    backend: Backend,
    backend_name: String,
    base_path: String,
}

// Backend components are thread-safe (LMDB env is Send + Sync, JSON guarded by Mutex),
// so it is safe to allow cross-thread transfer.
unsafe impl Send for NativeStorage {}

#[pymethods]
impl NativeStorage {
    #[new]
    #[pyo3(
        signature = (backend, path, map_size_init=None, map_size_max=None, pretty_json=true)
    )]
    fn new(
        backend: &str,
        path: &str,
        map_size_init: Option<usize>,
        map_size_max: Option<usize>,
        pretty_json: bool,
    ) -> PyResult<Self> {
        let backend_norm = backend.to_lowercase();
        let path_buf = PathBuf::from(path);
        let base_path = path_buf
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| path.to_string());

        match backend_norm.as_str() {
            "lmdb" => {
                let init = map_size_init.unwrap_or(DEFAULT_LMDB_MAP_INIT);
                let default_max = usize::try_from(DEFAULT_LMDB_MAP_MAX).unwrap_or(usize::MAX);
                let max = map_size_max.unwrap_or(default_max);
                let lmdb = LmdbBackend::new(&path_buf, init, max)?;
                Ok(Self {
                    backend: Backend::Lmdb(lmdb),
                    backend_name: "lmdb".to_string(),
                    base_path,
                })
            }
            "json" => {
                let json = JsonBackend::new(path_buf, pretty_json);
                Ok(Self {
                    backend: Backend::Json(json),
                    backend_name: "json".to_string(),
                    base_path,
                })
            }
            _ => Err(PyValueError::new_err(
                "backend must be either 'lmdb' or 'json'",
            )),
        }
    }

    #[getter]
    fn backend(&self) -> String {
        self.backend_name.clone()
    }

    #[getter]
    fn path(&self) -> String {
        self.base_path.clone()
    }

    fn put_bytes(&self, db: &str, key: &[u8], value: &[u8]) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.put(db, key, value),
            Backend::Json(b) => b.put_bytes(db, key, value),
        }
    }

    fn put_json(&self, db: &str, key: &[u8], json_text: &str) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.put(db, key, json_text.as_bytes()),
            Backend::Json(b) => b.put_json_text(db, key, json_text),
        }
    }

    fn get_bytes<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        key: &[u8],
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let res = match &self.backend {
            Backend::Lmdb(b) => b.get(db, key)?,
            Backend::Json(b) => b.get(db, key)?,
        };
        Ok(res.map(|v| PyBytes::new(py, &v)))
    }

    fn get_json<'py>(&self, py: Python<'py>, db: &str, key: &[u8]) -> PyResult<Option<Py<PyAny>>>{
        let json_text_opt = match &self.backend {
            Backend::Json(b) => b.get_json_string(db, key)?,
            Backend::Lmdb(b) => {
                let raw_opt = b.get(db, key)?;
                match raw_opt {
                    Some(raw) => match str::from_utf8(&raw) {
                        Ok(txt) => Some(txt.to_string()),
                        Err(_) => None,
                    },
                    None => None,
                }
            }
        };
        if let Some(text) = json_text_opt {
            let json_mod = py.import("json")?;
            let obj = json_mod.call_method1("loads", (text,))?;
            Ok(Some(obj.unbind()))
        } else {
            Ok(None)
        }
    }

    fn delete(&self, db: &str, key: &[u8]) -> PyResult<bool> {
        match &self.backend {
            Backend::Lmdb(b) => b.delete(db, key),
            Backend::Json(b) => b.delete(db, key),
        }
    }

    fn clear_db(&self, db: &str) -> PyResult<u64> {
        match &self.backend {
            Backend::Lmdb(b) => b.clear_db(db),
            Backend::Json(b) => b.clear_db(db),
        }
    }

    #[pyo3(signature = (db, prefix, limit=1000, start_after=None))]
    fn iter_prefix_chunk<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        prefix: &[u8],
        limit: usize,
        start_after: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<(Vec<u8>, Vec<u8>)> = match &self.backend {
            Backend::Lmdb(b) => b.iter_prefix_chunk(db, prefix, start_after, limit)?,
            Backend::Json(b) => b.iter_prefix(db, prefix)?,
        };
        let out = PyList::empty(py);
        for (k, v) in items {
            out.append((PyBytes::new(py, &k), PyBytes::new(py, &v)))?;
        }
        Ok(out)
    }

    fn put_batch(&self, db: &str, ops: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.put_batch(db, ops),
            Backend::Json(b) => {
                for (k, maybe_v) in ops {
                    if let Some(v) = maybe_v {
                        b.put_bytes(db, &k, &v)?;
                    } else {
                        b.delete(db, &k)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn apply_utxo_ops(
        &self,
        ops: Vec<(String, Option<u64>, Option<Vec<u8>>, Option<bool>, Option<i64>)>,
    ) -> PyResult<(u64, u64)> {
        match &self.backend {
            Backend::Json(_) => Err(PyErr::new::<PyRuntimeError, _>(
                "apply_utxo_ops only supported for LMDB backend",
            )),
            Backend::Lmdb(b) => {
                let mut batch_ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(ops.len());
                let mut put_count: u64 = 0;
                let mut del_count: u64 = 0;

                for (key_str, amount_opt, spk_opt, is_cb_opt, h_opt) in ops {
                    if amount_opt.is_none() {
                        batch_ops.push((key_str.into_bytes(), None));
                        del_count = del_count.saturating_add(1);
                        continue;
                    }
                    let amount = amount_opt.unwrap_or(0);
                    let spk_hex = spk_opt.as_ref().map(|b| hex::encode(b));
                    let payload = serde_json::json!({
                        "tx_out": {
                            "amount": amount,
                            "script_pubkey": spk_hex,
                        },
                        "is_coinbase": is_cb_opt.unwrap_or(false),
                        "block_height": h_opt.unwrap_or(0),
                    });
                    let bytes = serde_json::to_vec(&payload)
                        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("utxo json encode: {e}")))?;
                    batch_ops.push((key_str.into_bytes(), Some(bytes)));
                    put_count = put_count.saturating_add(1);
                }
                b.put_batch("utxo", batch_ops)?;
                Ok((put_count, del_count))
            }
        }
    }

    fn copy(&self, dest: &str, compact: bool) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.copy_env(dest, compact),
            Backend::Json(_b) => Err(PyErr::new::<PyRuntimeError, _>(
                "copy not supported for json backend",
            )),
        }
    }

    fn iter_prefix<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        prefix: &[u8],
    ) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<(Vec<u8>, Vec<u8>)> = match &self.backend {
            Backend::Lmdb(b) => b.iter_prefix(db, prefix)?,
            Backend::Json(b) => b.iter_prefix(db, prefix)?,
        };
        let out = PyList::empty(py);
        for (k, v) in items {
            out.append((PyBytes::new(py, &k), PyBytes::new(py, &v)))?;
        }
        Ok(out)
    }
}

#[pyfunction]
#[pyo3(signature = (backend, path, map_size_init=None, map_size_max=None, pretty_json=true))]
pub fn open_storage(
    backend: &str,
    path: &str,
    map_size_init: Option<usize>,
    map_size_max: Option<usize>,
    pretty_json: bool,
) -> PyResult<NativeStorage> {
    NativeStorage::new(backend, path, map_size_init, map_size_max, pretty_json)
}
