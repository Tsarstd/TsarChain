// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain - see LICENSE
// Refs: LMDB; Atomic JSON; serde_json; pyo3

use libc::size_t;
use lmdb::{Cursor, Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use lmdb_sys as ffi;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use std::ffi::CString;
use std::fs;
use std::os::raw::c_uint;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;

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
                let flags = lmdb::EnvironmentFlags::NO_META_SYNC
                    | lmdb::EnvironmentFlags::NO_MEM_INIT;
                builder.set_flags(flags);
            }
            DriveType::Ssd => {
                let flags = lmdb::EnvironmentFlags::NO_META_SYNC
                    | lmdb::EnvironmentFlags::NO_MEM_INIT;
                builder.set_flags(flags);
            }
            DriveType::Nvme => {}
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
                Ok(_) => match txn.commit() {
                    Ok(_) => return Ok(()),
                    Err(lmdb::Error::MapFull) => {
                        log_warning(&format!(
                            "[lmdb] map full on commit db={} key_len={} val_len={}, trying grow_to_max",
                            db_name,
                            key.len(),
                            val.len()
                        ));
                        self.grow_to_max()?;
                    }
                    Err(e) => return Err(map_err("lmdb commit", e)),
                },
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
                Ok(_) => match txn.commit() {
                    Ok(_) => return Ok(true),
                    Err(lmdb::Error::MapFull) => {
                        log_warning(&format!(
                            "[lmdb] map full on commit delete db={} key_len={}, trying grow_to_max",
                            db_name,
                            key.len()
                        ));
                        self.grow_to_max()?;
                    }
                    Err(e) => return Err(map_err("lmdb commit", e)),
                },
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

        if prefix.is_empty() {
            for (k, v) in cursor.iter() {
                items.push((k.to_vec(), v.to_vec()));
            }
            return Ok(items);
        }

        match cursor.get(Some(prefix), None, ffi::MDB_SET_RANGE) {
            Ok((Some(first_k), first_v)) => {
                if first_k.starts_with(prefix) {
                    items.push((first_k.to_vec(), first_v.to_vec()));
                    while let Ok((Some(k), v)) = cursor.get(None, None, ffi::MDB_NEXT) {
                        if k.starts_with(prefix) {
                            items.push((k.to_vec(), v.to_vec()));
                        } else {
                            break;
                        }
                    }
                }
            }
            Ok((None, _)) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(map_err("lmdb iter_prefix seek", e)),
        }

        Ok(items)
    }

    fn iter_prefix_chunk(
        &self,
        db_name: &str,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        limit: usize,
    ) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let db = self.open_db(db_name)?;
        let txn = self
            .env
            .begin_ro_txn()
            .map_err(|e| map_err("lmdb begin_ro_txn", e))?;
        let cursor = txn
            .open_ro_cursor(db)
            .map_err(|e| map_err("lmdb cursor", e))?;

        let mut items = Vec::with_capacity(limit);
        let seek_key = start_after.unwrap_or(prefix);

        let first = if seek_key.is_empty() {
            cursor.get(None, None, ffi::MDB_FIRST)
        } else {
            cursor.get(Some(seek_key), None, ffi::MDB_SET_RANGE)
        };

        match first {
            Ok((Some(mut k), mut v)) => {
                loop {
                    let is_after = match start_after {
                        Some(after) => k > after,
                        None => true,
                    };
                    if is_after {
                        if !prefix.is_empty() && !k.starts_with(prefix) {
                            break;
                        }
                        items.push((k.to_vec(), v.to_vec()));
                        if items.len() >= limit {
                            break;
                        }
                    }
                    match cursor.get(None, None, ffi::MDB_NEXT) {
                        Ok((Some(next_k), next_v)) => {
                            k = next_k;
                            v = next_v;
                        }
                        _ => break,
                    }
                }
            }
            Ok((None, _)) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(map_err("lmdb iter_prefix_chunk seek", e)),
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
                match txn.commit() {
                    Ok(_) => return Ok(()),
                    Err(lmdb::Error::MapFull) => {
                        log_warning(&format!(
                            "[lmdb] map full on batch commit db={}, trying grow_to_max",
                            db_name
                        ));
                        self.grow_to_max()?;
                    }
                    Err(e) => return Err(map_err("lmdb commit batch", e)),
                }
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
// Native storage exposed to Python
// ============================

#[pyclass(name = "NativeStorage")]
pub struct NativeStorage {
    lmdb: LmdbBackend,
    backend_name: String,
    base_path: String,
    detected_drive_type: String,
}

// Backend components are thread-safe (LMDB env is Send + Sync)
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
        let _ = pretty_json;
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
                    lmdb,
                    backend_name: "lmdb".to_string(),
                    base_path,
                    detected_drive_type: dt.as_str().to_string(),
                })
            }
            _ => Err(PyValueError::new_err(
                "backend must be 'lmdb'",
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
        self.lmdb.env.sync(force).map_err(|e| map_err("lmdb sync", e))
    }

    pub fn put_bytes(&self, db: &str, key: &[u8], value: &[u8]) -> PyResult<()> {
        self.lmdb.put(db, key, value)
    }

    pub fn put_json(&self, db: &str, key: &[u8], json_text: &str) -> PyResult<()> {
        self.lmdb.put(db, key, json_text.as_bytes())
    }

    pub fn get_bytes<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        key: &[u8],
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let res = self.lmdb.get(db, key)?;
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
        let res = self.lmdb.get_bytes_range(db, key, offset, length)?;
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
        let db_handle = self.lmdb.open_db(db)?;
        let txn = self.lmdb.env.begin_ro_txn().map_err(|e| map_err("lmdb ro_txn", e))?;
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
    }

    pub fn get_json<'py>(&self, py: Python<'py>, db: &str, key: &[u8]) -> PyResult<Option<Py<PyAny>>>{
        let raw_opt = self.lmdb.get(db, key)?;
        if let Some(raw) = raw_opt {
            if let Ok(text) = str::from_utf8(&raw) {
                let json_mod = py.import("json")?;
                let obj = json_mod.call_method1("loads", (text,))?;
                return Ok(Some(obj.unbind()));
            }
        }
        Ok(None)
    }

    pub fn delete(&self, db: &str, key: &[u8]) -> PyResult<bool> {
        self.lmdb.delete(db, key)
    }

    pub fn clear_db(&self, db: &str) -> PyResult<u64> {
        self.lmdb.clear_db(db)
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
        let items: Vec<(Vec<u8>, Vec<u8>)> = self.lmdb.iter_prefix_chunk(db, prefix, start_after, limit)?;
        let out = PyList::empty(py);
        for (k, v) in items {
            out.append((PyBytes::new(py, &k), PyBytes::new(py, &v)))?;
        }
        Ok(out)
    }

    pub fn put_batch(&self, db: &str, ops: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> PyResult<()> {
        self.lmdb.put_batch(db, ops)
    }

    pub fn apply_utxo_ops(
        &self,
        ops: Vec<(String, Option<u64>, Option<Vec<u8>>, Option<bool>, Option<i64>)>,
    ) -> PyResult<(u64, u64)> {
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
            let spk = spk_opt.unwrap_or_default();
            let is_cb = is_cb_opt.unwrap_or(false);
            let h = h_opt.unwrap_or(0);

            // Binary compact UTXO format:
            // amount (u64, 8B LE) + is_coinbase (u8, 1B) + block_height (i64, 8B LE) + spk_len (u16, 2B LE) + spk_bytes
            let mut bytes = Vec::with_capacity(8 + 1 + 8 + 2 + spk.len());
            bytes.extend_from_slice(&amount.to_le_bytes());
            bytes.push(if is_cb { 1 } else { 0 });
            bytes.extend_from_slice(&h.to_le_bytes());
            let spk_len = spk.len() as u16;
            bytes.extend_from_slice(&spk_len.to_le_bytes());
            bytes.extend_from_slice(&spk);

            batch_ops.push((key_str.into_bytes(), Some(bytes)));
            put_count = put_count.saturating_add(1);
        }
        self.lmdb.put_batch("utxo", batch_ops)?;
        Ok((put_count, del_count))
    }

    pub fn copy(&self, dest: &str, compact: bool) -> PyResult<()> {
        self.lmdb.copy_env(dest, compact)
    }

    pub fn iter_prefix<'py>(
        &self,
        py: Python<'py>,
        db: &str,
        prefix: &[u8],
    ) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<(Vec<u8>, Vec<u8>)> = self.lmdb.iter_prefix(db, prefix)?;
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

