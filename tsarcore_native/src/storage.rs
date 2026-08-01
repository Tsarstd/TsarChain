// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE
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
// Smart Drive Type Detection
// ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    Hdd,
    Ssd,
    Nvme,
}

impl DriveType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DriveType::Hdd => "hdd",
            DriveType::Ssd => "ssd",
            DriveType::Nvme => "nvme",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "hdd" => Some(DriveType::Hdd),
            "ssd" => Some(DriveType::Ssd),
            "nvme" => Some(DriveType::Nvme),
            _ => None,
        }
    }
}

pub fn detect_drive_type_from_path(path: &Path) -> DriveType {
    // 1. Check environment variable override
    if let Ok(env_val) = std::env::var("TSAR_STORAGE_DRIVE_TYPE") {
        if let Some(dt) = DriveType::parse(&env_val) {
            return dt;
        }
    }

    // 2. Perform OS-specific drive detection
    if let Some(dt) = detect_os_drive_type(path) {
        return dt;
    }

    // 3. Fallback to SSD profile (safe default)
    DriveType::Ssd
}

#[cfg(target_os = "windows")]
fn detect_os_drive_type(path: &Path) -> Option<DriveType> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let abs_path = path.canonicalize().ok().unwrap_or_else(|| path.to_path_buf());
    let path_str = abs_path.to_str()?;

    let drive_letter = if path_str.len() >= 2 && &path_str[1..2] == ":" {
        &path_str[0..2]
    } else if path_str.starts_with(r"\\?\") && path_str.len() >= 6 && &path_str[5..6] == ":" {
        &path_str[4..6]
    } else {
        return None;
    };

    let device_path = format!(r"\\.\{}", drive_letter);
    let wide_path: Vec<u16> = OsStr::new(&device_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = ffi_win::CreateFileW(
            wide_path.as_ptr(),
            0,
            ffi_win::FILE_SHARE_READ | ffi_win::FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            ffi_win::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );

        if handle == ffi_win::INVALID_HANDLE_VALUE {
            return None;
        }

        struct HandleGuard(ffi_win::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe { ffi_win::CloseHandle(self.0); }
            }
        }
        let _guard = HandleGuard(handle);

        let mut query = ffi_win::STORAGE_PROPERTY_QUERY {
            PropertyId: 7, // StorageDeviceSeekPenaltyProperty
            QueryType: 0,  // PropertyStandardQuery
            AdditionalParameters: [0; 1],
        };
        let mut seek_desc = ffi_win::DEVICE_SEEK_PENALTY_DESCRIPTOR {
            Version: 0,
            Size: 0,
            IncurrsSeekPenalty: 0,
        };
        let mut bytes_returned: u32 = 0;

        let res = ffi_win::DeviceIoControl(
            handle,
            ffi_win::IOCTL_STORAGE_QUERY_PROPERTY,
            &mut query as *mut _ as *mut _,
            std::mem::size_of::<ffi_win::STORAGE_PROPERTY_QUERY>() as u32,
            &mut seek_desc as *mut _ as *mut _,
            std::mem::size_of::<ffi_win::DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        );

        if res != 0 && seek_desc.IncurrsSeekPenalty != 0 {
            return Some(DriveType::Hdd);
        }

        let mut query_dev = ffi_win::STORAGE_PROPERTY_QUERY {
            PropertyId: 0, // StorageDeviceProperty
            QueryType: 0,
            AdditionalParameters: [0; 1],
        };
        let mut dev_desc = ffi_win::STORAGE_DEVICE_DESCRIPTOR::default();
        let res_dev = ffi_win::DeviceIoControl(
            handle,
            ffi_win::IOCTL_STORAGE_QUERY_PROPERTY,
            &mut query_dev as *mut _ as *mut _,
            std::mem::size_of::<ffi_win::STORAGE_PROPERTY_QUERY>() as u32,
            &mut dev_desc as *mut _ as *mut _,
            std::mem::size_of::<ffi_win::STORAGE_DEVICE_DESCRIPTOR>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        );

        if res_dev != 0 && dev_desc.BusType == 17 { // BusTypeNvme = 17 (0x11)
            return Some(DriveType::Nvme);
        }

        Some(DriveType::Ssd)
    }
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case, dead_code)]
mod ffi_win {
    pub type HANDLE = *mut std::ffi::c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const FILE_SHARE_READ: DWORD = 0x00000001;
    pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
    pub const OPEN_EXISTING: DWORD = 3;
    pub const IOCTL_STORAGE_QUERY_PROPERTY: DWORD = 0x002D1400;

    #[repr(C)]
    pub struct STORAGE_PROPERTY_QUERY {
        pub PropertyId: i32,
        pub QueryType: i32,
        pub AdditionalParameters: [u8; 1],
    }

    #[repr(C)]
    pub struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
        pub Version: u32,
        pub Size: u32,
        pub IncurrsSeekPenalty: u8,
    }

    #[repr(C)]
    pub struct STORAGE_DEVICE_DESCRIPTOR {
        pub Version: u32,
        pub Size: u32,
        pub DeviceType: u8,
        pub DeviceTypeModifier: u8,
        pub RemovableMedia: u8,
        pub CommandQueueing: u8,
        pub VendorIdOffset: u32,
        pub ProductIdOffset: u32,
        pub ProductRevisionOffset: u32,
        pub SerialNumberOffset: u32,
        pub BusType: i32,
        pub RawPropertiesLength: u32,
        pub RawDeviceProperties: [u8; 1],
    }

    impl Default for STORAGE_DEVICE_DESCRIPTOR {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    extern "system" {
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *mut std::ffi::c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;

        pub fn DeviceIoControl(
            hDevice: HANDLE,
            dwIoControlCode: DWORD,
            lpInBuffer: *mut std::ffi::c_void,
            nInBufferSize: DWORD,
            lpOutBuffer: *mut std::ffi::c_void,
            nOutBufferSize: DWORD,
            lpBytesReturned: *mut DWORD,
            lpOverlapped: *mut std::ffi::c_void,
        ) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    }
}

#[cfg(target_os = "linux")]
fn detect_os_drive_type(path: &Path) -> Option<DriveType> {
    let canonical = path.canonicalize().ok().unwrap_or_else(|| path.to_path_buf());
    let path_str = canonical.to_str()?;

    if path_str.contains("nvme") {
        return Some(DriveType::Nvme);
    }

    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let dev_name = entry.file_name();
            let dev_str = dev_name.to_string_lossy();
            if path_str.contains(dev_str.as_ref()) {
                let rot_path = entry.path().join("queue/rotational");
                if let Ok(val) = fs::read_to_string(&rot_path) {
                    if val.trim() == "1" {
                        return Some(DriveType::Hdd);
                    } else if dev_str.starts_with("nvme") {
                        return Some(DriveType::Nvme);
                    } else {
                        return Some(DriveType::Ssd);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn detect_os_drive_type(_path: &Path) -> Option<DriveType> {
    None
}

// ============================
// LMDB backend
// ============================

#[derive(Clone)]
struct LmdbBackend {
    env: Arc<Environment>,
    map_size_max: usize,
    #[allow(dead_code)]
    drive_type: DriveType,
}

impl LmdbBackend {
    fn new(path: &Path, map_size_init: usize, map_size_max: usize, drive_type: DriveType) -> PyResult<Self> {
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

        match drive_type {
            DriveType::Hdd => {
                let flags = lmdb::EnvironmentFlags::NO_SYNC
                    | lmdb::EnvironmentFlags::WRITE_MAP
                    | lmdb::EnvironmentFlags::MAP_ASYNC
                    | lmdb::EnvironmentFlags::NO_READAHEAD
                    | lmdb::EnvironmentFlags::NO_MEM_INIT;
                builder.set_flags(flags);
                log_warning(&format!(
                    "[lmdb] HDD profile applied for path='{}': NOSYNC | WRITEMAP | MAPASYNC | NORDAHEAD | NOMEMINIT",
                    path.display()
                ));
            }
            DriveType::Ssd => {
                let flags = lmdb::EnvironmentFlags::NO_META_SYNC
                    | lmdb::EnvironmentFlags::NO_MEM_INIT;
                builder.set_flags(flags);
                log_warning(&format!(
                    "[lmdb] SSD profile applied for path='{}': NOMETASYNC | NOMEMINIT",
                    path.display()
                ));
            }
            DriveType::Nvme => {
                log_warning(&format!(
                    "[lmdb] NVME profile applied for path='{}': standard sync",
                    path.display()
                ));
            }
        }

        let env = builder.open(path).map_err(|e| map_err("lmdb open", e))?;

        Ok(Self {
            env: Arc::new(env),
            map_size_max,
            drive_type,
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
        loop {
            let mut txn = self
                .env
                .begin_rw_txn()
                .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
            match txn.put(db, &key, &val, WriteFlags::empty()) {
                Ok(_) => {
                    return txn.commit().map_err(|e| map_err("lmdb commit", e));
                }
                Err(lmdb::Error::MapFull) => {
                    log_warning(&format!(
                        "[lmdb] map full on put db={} key_len={} val_len={}, trying grow_to_max",
                        db_name,
                        key.len(),
                        val.len()
                    ));
                    drop(txn);
                    self.grow_to_max()?;
                }
                Err(e) => return Err(map_err("lmdb put", e)),
            }
        }
    }

    fn delete(&self, db_name: &str, key: &[u8]) -> PyResult<bool> {
        let db = self.open_db(db_name)?;
        loop {
            let mut txn = self
                .env
                .begin_rw_txn()
                .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
            match txn.del(db, &key, None) {
                Ok(_) => {
                    txn.commit().map_err(|e| map_err("lmdb commit", e))?;
                    return Ok(true);
                }
                Err(lmdb::Error::NotFound) => return Ok(false),
                Err(lmdb::Error::MapFull) => {
                    log_warning(&format!(
                        "[lmdb] map full on delete db={} key_len={}, trying grow_to_max",
                        db_name,
                        key.len()
                    ));
                    drop(txn);
                    self.grow_to_max()?;
                }
                Err(e) => return Err(map_err("lmdb delete", e)),
            }
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

    fn get_bytes_range(&self, db_name: &str, key: &[u8], offset: usize, length: usize) -> PyResult<Option<Vec<u8>>> {
        let db = self.open_db(db_name)?;
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| map_err("lmdb begin_ro_txn", e))?;
        match txn.get(db, &key) {
            Ok(bytes) => {
                if offset >= bytes.len() {
                    Ok(Some(Vec::new()))
                } else {
                    let end = std::cmp::min(offset.saturating_add(length), bytes.len());
                    Ok(Some(bytes[offset..end].to_vec()))
                }
            },
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(map_err("lmdb get", e)),
        }
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
        loop {
            let mut txn = self
                .env
                .begin_rw_txn()
                .map_err(|e| map_err("lmdb begin_rw_txn", e))?;
            let mut map_full = false;
            for (k, maybe_v) in ops.iter() {
                let res = match maybe_v {
                    Some(v) => txn.put(db, &k, &v, WriteFlags::empty()),
                    None => match txn.del(db, &k, None) {
                        Ok(_) => Ok(()),
                        Err(lmdb::Error::NotFound) => Ok(()),
                        Err(e) => Err(e),
                    },
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
            } else {
                return txn.commit().map_err(|e| map_err("lmdb commit batch", e));
            }
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

    fn get_bytes_range(&self, db: &str, key: &[u8], offset: usize, length: usize) -> PyResult<Option<Vec<u8>>> {
        let full_opt = self.get(db, key)?;
        match full_opt {
            Some(v) => {
                if offset >= v.len() {
                    Ok(Some(Vec::new()))
                } else {
                    let end = std::cmp::min(offset.saturating_add(length), v.len());
                    Ok(Some(v[offset..end].to_vec()))
                }
            }
            None => Ok(None),
        }
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
    detected_drive_type: String,
}

// Backend components are thread-safe (LMDB env is Send + Sync, JSON guarded by Mutex),
// so it is safe to allow cross-thread transfer.
unsafe impl Send for NativeStorage {}

#[pymethods]
impl NativeStorage {
    #[new]
    #[pyo3(
        signature = (backend, path, map_size_init=None, map_size_max=None, pretty_json=true, drive_type=None)
    )]
    fn new(
        backend: &str,
        path: &str,
        map_size_init: Option<usize>,
        map_size_max: Option<usize>,
        pretty_json: bool,
        drive_type: Option<&str>,
    ) -> PyResult<Self> {
        let backend_norm = backend.to_lowercase();
        let path_buf = PathBuf::from(path);
        let base_path = path_buf
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| path.to_string());

        let dt = match drive_type {
            Some(dt_str) => DriveType::parse(dt_str).unwrap_or_else(|| detect_drive_type_from_path(&path_buf)),
            None => detect_drive_type_from_path(&path_buf),
        };

        match backend_norm.as_str() {
            "lmdb" => {
                let init = map_size_init.unwrap_or(DEFAULT_LMDB_MAP_INIT);
                let default_max = usize::try_from(DEFAULT_LMDB_MAP_MAX).unwrap_or(usize::MAX);
                let max = map_size_max.unwrap_or(default_max);
                let lmdb = LmdbBackend::new(&path_buf, init, max, dt)?;
                Ok(Self {
                    backend: Backend::Lmdb(lmdb),
                    backend_name: "lmdb".to_string(),
                    base_path,
                    detected_drive_type: dt.as_str().to_string(),
                })
            }
            "json" => {
                let json = JsonBackend::new(path_buf, pretty_json);
                Ok(Self {
                    backend: Backend::Json(json),
                    backend_name: "json".to_string(),
                    base_path,
                    detected_drive_type: dt.as_str().to_string(),
                })
            }
            _ => Err(PyValueError::new_err(
                "backend must be either 'lmdb' or 'json'",
            )),
        }
    }

    #[getter]
    pub fn backend(&self) -> String {
        self.backend_name.clone()
    }

    #[getter]
    pub fn path(&self) -> String {
        self.base_path.clone()
    }

    #[getter]
    pub fn drive_type(&self) -> String {
        self.detected_drive_type.clone()
    }

    pub fn sync(&self, force: bool) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.env.sync(force).map_err(|e| map_err("lmdb sync", e)),
            Backend::Json(_) => Ok(()),
        }
    }

    pub fn put_bytes(&self, db: &str, key: &[u8], value: &[u8]) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.put(db, key, value),
            Backend::Json(b) => b.put_bytes(db, key, value),
        }
    }

    pub fn put_json(&self, db: &str, key: &[u8], json_text: &str) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.put(db, key, json_text.as_bytes()),
            Backend::Json(b) => b.put_json_text(db, key, json_text),
        }
    }

    pub fn get_bytes<'py>(
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

    /// Retrieve a slice of bytes from the database. 
    /// This optimization is specifically intended for chunked downloads of large graffiti files,
    /// avoiding full allocations. It is not generally used for small blockchain or UTXO payloads.
    pub fn get_bytes_range<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        key: &[u8],
        offset: usize,
        length: usize,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let res = match &self.backend {
            Backend::Lmdb(b) => b.get_bytes_range(db, key, offset, length)?,
            Backend::Json(b) => b.get_bytes_range(db, key, offset, length)?,
        };
        Ok(res.map(|v| PyBytes::new(py, &v)))
    }

    /// Retrieve a merkle path for a specific chunk index directly from the database memory mapping.
    /// This optimization is specifically intended for graffiti files to avoid full allocations in STOR_PROOF_RUN.
    pub fn get_merkle_path<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        key: &[u8],
        chunk_size: usize,
        index: usize,
    ) -> PyResult<Option<Bound<'py, PyList>>> {
        match &self.backend {
            Backend::Lmdb(b) => {
                let db_handle = b.open_db(db)?;
                let txn = b.env.begin_ro_txn().map_err(|e| map_err("lmdb ro_txn", e))?;
                match txn.get(db_handle, &key) {
                    Ok(bytes) => {
                        let leaves = crate::graff_merkle::leaves_from_bytes_internal(bytes, chunk_size)?;
                        let path = crate::graff_merkle::build_path_internal(leaves, index)?;
                        let out = crate::graff_merkle::path_to_pylist(py, path)?;
                        Ok(Some(out))
                    },
                    Err(lmdb::Error::NotFound) => Ok(None),
                    Err(e) => Err(map_err("lmdb get", e)),
                }
            },
            Backend::Json(b) => {
                let bytes_opt = b.get(db, key)?;
                match bytes_opt {
                    Some(bytes) => {
                        let leaves = crate::graff_merkle::leaves_from_bytes_internal(&bytes, chunk_size)?;
                        let path = crate::graff_merkle::build_path_internal(leaves, index)?;
                        let out = crate::graff_merkle::path_to_pylist(py, path)?;
                        Ok(Some(out))
                    },
                    None => Ok(None),
                }
            }
        }
    }

    pub fn get_json<'py>(&self, py: Python<'py>, db: &str, key: &[u8]) -> PyResult<Option<Py<PyAny>>>{
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

    pub fn delete(&self, db: &str, key: &[u8]) -> PyResult<bool> {
        match &self.backend {
            Backend::Lmdb(b) => b.delete(db, key),
            Backend::Json(b) => b.delete(db, key),
        }
    }

    pub fn clear_db(&self, db: &str) -> PyResult<u64> {
        match &self.backend {
            Backend::Lmdb(b) => b.clear_db(db),
            Backend::Json(b) => b.clear_db(db),
        }
    }

    #[pyo3(signature = (db, prefix, limit=1000, start_after=None))]
    pub fn iter_prefix_chunk<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        prefix: &[u8],
        limit: usize,
        start_after: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<(Vec<u8>, Vec<u8>)> = match &self.backend {
            Backend::Lmdb(b) => b.iter_prefix_chunk(db, prefix, start_after, limit)?,
            Backend::Json(b) => {
                let mut all = b.iter_prefix(db, prefix)?;
                if let Some(after) = start_after {
                    all.retain(|(k, _)| k.as_slice() > after);
                }
                all.truncate(limit);
                all
            }
        };
        let out = PyList::empty(py);
        for (k, v) in items {
            out.append((PyBytes::new(py, &k), PyBytes::new(py, &v)))?;
        }
        Ok(out)
    }

    pub fn put_batch(&self, db: &str, ops: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> PyResult<()> {
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

    pub fn apply_utxo_ops(
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

    pub fn copy(&self, dest: &str, compact: bool) -> PyResult<()> {
        match &self.backend {
            Backend::Lmdb(b) => b.copy_env(dest, compact),
            Backend::Json(_b) => Err(PyErr::new::<PyRuntimeError, _>(
                "copy not supported for json backend",
            )),
        }
    }

    pub fn iter_prefix<'py>(
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
#[pyo3(signature = (backend, path, map_size_init=None, map_size_max=None, pretty_json=true, drive_type=None))]
pub fn open_storage(
    backend: &str,
    path: &str,
    map_size_init: Option<usize>,
    map_size_max: Option<usize>,
    pretty_json: bool,
    drive_type: Option<&str>,
) -> PyResult<NativeStorage> {
    NativeStorage::new(backend, path, map_size_init, map_size_max, pretty_json, drive_type)
}

#[pyfunction]
pub fn detect_drive_type(path: &str) -> PyResult<String> {
    let p = Path::new(path);
    let dt = detect_drive_type_from_path(p);
    Ok(dt.as_str().to_string())
}

