// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Tsar Studio
// Part of TsarChain — see LICENSE and TRADEMARKS.md
// Refs: RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyBytes, PyDict, PyDictMethods},
    Bound,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Role {
    Client,
    Server,
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn join_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push(b'|');
        }
        out.extend_from_slice(part);
    }
    out
}

fn parse_hex(input: &str) -> PyResult<Vec<u8>> {
    hex::decode(input).map_err(|_| PyValueError::new_err("invalid hex input"))
}

fn get_required<'py, T: FromPyObject<'py>>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<T> {
    dict.get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("missing {}", key)))?
        .extract()
}

fn parse_secret_key_bytes(hex_str: &str) -> PyResult<[u8; 32]> {
    let bytes = parse_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "node_priv must be 32 bytes (64 hex chars)",
        ));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("failed to parse node_priv bytes"))?;
    Ok(arr)
}

fn decode_pubkey(hex_str: &str) -> PyResult<[u8; 32]> {
    let bytes = parse_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "node_pub must be 32 bytes (64 hex chars)",
        ));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("invalid node_pub bytes"))?;
    Ok(arr)
}

fn derive_node_id(pub_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(pub_bytes);
    hex::encode(h.finalize())
}

fn seq_to_nonce(seq: u64, nonce_len: usize) -> PyResult<Vec<u8>> {
    if nonce_len == 0 || nonce_len > 16 {
        return Err(PyValueError::new_err("unsupported nonce size"));
    }
    let mut out = vec![0u8; nonce_len];
    let mut value = seq;
    for idx in 0..nonce_len {
        let offset = nonce_len - 1 - idx;
        out[offset] = (value & 0xFF) as u8;
        value >>= 8;
    }
    if value != 0 {
        return Err(PyValueError::new_err("sequence number overflow"));
    }
    Ok(out)
}

fn hkdf_derive(shared: &[u8], salt: &[u8], info: &[u8], key_len: usize) -> PyResult<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = vec![0u8; key_len];
    hk.expand(info, &mut okm)
        .map_err(|_| PyValueError::new_err("HKDF derive failed"))?;
    Ok(okm)
}

#[pyclass]
pub struct SecureChannelNative {
    role: Role,
    net_id: String,
    aad: Vec<u8>,
    session_ttl: f64,
    session_max_msg: u64,
    key_len: usize,
    nonce_len: usize,
    node_id: String,
    node_pub_hex: String,
    node_pub_bytes: [u8; 32],
    node_pub_key: PublicKey,
    node_priv: Option<[u8; 32]>,
    peer_node_id: Option<String>,
    peer_node_pub: Option<Vec<u8>>,
    aes: Option<Aes256Gcm>,
    send_ctr: u64,
    recv_ctr: i64,
    msg_count: u64,
    established_at: f64,
    client_eph: Option<StaticSecret>,
    client_salt: Option<[u8; 16]>,
}

#[pymethods]
impl SecureChannelNative {
    #[new]
    #[pyo3(signature = (role, net_id, node_id, node_pub_hex, session_ttl, session_max_msg, key_bytes=32, nonce_bytes=12, node_priv_hex=None, aad_prefix=None))]
    pub fn new(
        role: &str,
        net_id: &str,
        node_id: &str,
        node_pub_hex: &str,
        session_ttl: f64,
        session_max_msg: u64,
        key_bytes: usize,
        nonce_bytes: usize,
        node_priv_hex: Option<&str>,
        aad_prefix: Option<&[u8]>,
    ) -> PyResult<Self> {
        let role = match role.to_lowercase().as_str() {
            "client" => Role::Client,
            "server" => Role::Server,
            _ => return Err(PyValueError::new_err("role must be 'client' or 'server'")),
        };

        if key_bytes != 32 {
            return Err(PyValueError::new_err("only 256-bit keys are supported"));
        }
        if nonce_bytes != 12 {
            return Err(PyValueError::new_err("nonce length must be 12 bytes"));
        }

        let node_pub_bytes = decode_pubkey(node_pub_hex)?;
        let node_pub_key = PublicKey::from_bytes(&node_pub_bytes)
            .map_err(|_| PyValueError::new_err("invalid node_pub material"))?;
        let node_priv_bytes = if let Some(sk_hex) = node_priv_hex {
            Some(parse_secret_key_bytes(sk_hex)?)
        } else {
            None
        };

        if matches!(role, Role::Server) && node_priv_bytes.is_none() {
            return Err(PyValueError::new_err(
                "server role requires node_priv to sign responses",
            ));
        }

        if let Some(bytes) = node_priv_bytes.as_ref() {
            let secret = SecretKey::from_bytes(bytes)
                .map_err(|_| PyValueError::new_err("invalid node_priv material"))?;
            let derived = PublicKey::from(&secret);
            if derived != node_pub_key {
                return Err(PyValueError::new_err("node_priv/pub mismatch"));
            }
        }

        let mut aad = aad_prefix.unwrap_or(&[]).to_vec();
        aad.extend_from_slice(net_id.as_bytes());

        let inst = Self {
            role,
            net_id: net_id.to_string(),
            aad,
            session_ttl,
            session_max_msg,
            key_len: key_bytes,
            nonce_len: nonce_bytes,
            node_id: node_id.to_string(),
            node_pub_hex: node_pub_hex.to_string(),
            node_pub_bytes,
            node_pub_key,
            node_priv: node_priv_bytes,
            peer_node_id: None,
            peer_node_pub: None,
            aes: None,
            send_ctr: 0,
            recv_ctr: -1,
            msg_count: 0,
            established_at: 0.0,
            client_eph: None,
            client_salt: None,
        };
        Ok(inst)
    }

    pub fn client_build_hs1(&mut self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        if self.role != Role::Client {
            return Err(PyValueError::new_err("only client role can build HS1"));
        }
        let keypair = self.signing_keypair()?;

        let mut rng = OsRng;
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = X25519PublicKey::from(&eph);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let to_sign = join_parts(&[
            b"HS1",
            self.net_id.as_bytes(),
            eph_pub.as_bytes(),
            &salt,
            self.node_id.as_bytes(),
            &self.node_pub_bytes,
        ]);
        let signature = keypair.sign(&to_sign);

        self.client_eph = Some(eph);
        self.client_salt = Some(salt);

        let dict = PyDict::new_bound(py);
        dict.set_item("type", "P2P_HS1")?;
        dict.set_item("net", &self.net_id)?;
        dict.set_item("eph_pub", hex::encode(eph_pub.as_bytes()))?;
        dict.set_item("salt", hex::encode(salt))?;
        dict.set_item("node_id", &self.node_id)?;
        dict.set_item("node_pub", &self.node_pub_hex)?;
        dict.set_item("sig", hex::encode(signature.to_bytes()))?;
        Ok(dict.unbind())
    }

    #[pyo3(signature = (hs2, pinned=None))]
    pub fn client_accept_hs2<'py>(
        &mut self,
        hs2: Bound<'py, PyDict>,
        pinned: Option<&str>,
    ) -> PyResult<(String, String)> {
        if self.role != Role::Client {
            return Err(PyValueError::new_err("only client role can accept HS2"));
        }
        let eph = self
            .client_eph
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("HS1 must be sent before HS2 processing"))?;
        let salt1 = self
            .client_salt
            .ok_or_else(|| PyValueError::new_err("missing client salt state"))?;

        let msg_type: String = get_required(&hs2, "type")?;
        if msg_type != "P2P_HS2" {
            return Err(PyValueError::new_err("unexpected handshake type"));
        }
        let net: String = get_required(&hs2, "net")?;
        if net != self.net_id {
            return Err(PyValueError::new_err("wrong network id"));
        }

        let peer_node_id: String = get_required(&hs2, "node_id")?;
        let peer_node_pub_hex: String = get_required(&hs2, "node_pub")?;
        let peer_node_pub = decode_pubkey(&peer_node_pub_hex)?;

        let derived_id = derive_node_id(&peer_node_pub);
        if derived_id != peer_node_id {
            return Err(PyValueError::new_err("node_id/pubkey mismatch"));
        }

        if let Some(pinned_hex) = pinned {
            let normalized = pinned_hex.trim().to_lowercase();
            if !normalized.is_empty() && normalized != peer_node_pub_hex.to_lowercase() {
                return Err(PyValueError::new_err("peer key mismatch (pinned)"));
            }
        }

        let peer_eph_hex: String = get_required(&hs2, "eph_pub")?;
        let peer_eph_bytes = parse_hex(&peer_eph_hex)?;
        if peer_eph_bytes.len() != 32 {
            return Err(PyValueError::new_err("invalid peer eph_pub"));
        }
        let peer_eph_arr: [u8; 32] = peer_eph_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PyValueError::new_err("invalid peer eph_pub"))?;
        let peer_eph = X25519PublicKey::from(peer_eph_arr);

        let salt2_hex: String = get_required(&hs2, "salt")?;
        let salt2_vec = parse_hex(&salt2_hex)?;
        if salt2_vec.len() != 16 {
            return Err(PyValueError::new_err("invalid salt length"));
        }
        let mut salt2 = [0u8; 16];
        salt2.copy_from_slice(&salt2_vec);

        let sig_hex: String = get_required(&hs2, "sig")?;
        let sig_bytes = parse_hex(&sig_hex)?;
        if sig_bytes.len() != 64 {
            return Err(PyValueError::new_err("invalid signature length"));
        }

        let client_eph_pub = X25519PublicKey::from(eph);

        let to_verify = join_parts(&[
            b"HS2",
            self.net_id.as_bytes(),
            peer_eph.as_bytes(),
            &salt2,
            client_eph_pub.as_bytes(),
            &salt1,
            peer_node_id.as_bytes(),
            &peer_node_pub,
        ]);
        let verifying_key = PublicKey::from_bytes(&peer_node_pub)
            .map_err(|_| PyValueError::new_err("invalid peer node_pub"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("invalid signature length"))?;
        let signature = Signature::from_bytes(&sig_arr)
            .map_err(|_| PyValueError::new_err("invalid signature bytes"))?;
        verifying_key
            .verify(&to_verify, &signature)
            .map_err(|_| PyValueError::new_err("bad HS2 signature"))?;

        let shared = eph.diffie_hellman(&peer_eph);
        let salt_concat = [salt1.as_slice(), &salt2].concat();
        let info = join_parts(&[
            b"P2Pv1",
            self.net_id.as_bytes(),
            client_eph_pub.as_bytes(),
            &salt1,
            peer_eph.as_bytes(),
            &salt2,
        ]);
        let key = hkdf_derive(shared.as_bytes(), &salt_concat, &info, self.key_len)?;
        let aes = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| PyValueError::new_err("invalid AES key"))?;

        self.aes = Some(aes);
        self.peer_node_id = Some(peer_node_id.clone());
        self.peer_node_pub = Some(peer_node_pub.to_vec());
        self.send_ctr = 0;
        self.recv_ctr = -1;
        self.msg_count = 0;
        self.established_at = now_seconds();

        Ok((peer_node_id, peer_node_pub_hex))
    }

    #[pyo3(signature = (hs1, pinned=None))]
    pub fn server_accept_hs1<'py>(
        &mut self,
        py: Python<'_>,
        hs1: Bound<'py, PyDict>,
        pinned: Option<&str>,
    ) -> PyResult<(Py<PyDict>, String, String)> {
        if self.role != Role::Server {
            return Err(PyValueError::new_err("only server role can accept HS1"));
        }
        let keypair = self.signing_keypair()?;

        let msg_type: String = get_required(&hs1, "type")?;
        if msg_type != "P2P_HS1" {
            return Err(PyValueError::new_err("unexpected handshake type"));
        }
        let net: String = get_required(&hs1, "net")?;
        if net != self.net_id {
            return Err(PyValueError::new_err("wrong network id"));
        }

        let peer_node_id: String = get_required(&hs1, "node_id")?;
        let peer_node_pub_hex: String = get_required(&hs1, "node_pub")?;
        let peer_node_pub = decode_pubkey(&peer_node_pub_hex)?;
        let derived_id = derive_node_id(&peer_node_pub);
        if derived_id != peer_node_id {
            return Err(PyValueError::new_err("node_id/pubkey mismatch"));
        }

        if let Some(pinned_hex) = pinned {
            let normalized = pinned_hex.trim().to_lowercase();
            if !normalized.is_empty() && normalized != peer_node_pub_hex.to_lowercase() {
                return Err(PyValueError::new_err("peer key mismatch (pinned)"));
            }
        }

        let peer_eph_hex: String = get_required(&hs1, "eph_pub")?;
        let peer_eph_bytes = parse_hex(&peer_eph_hex)?;
        if peer_eph_bytes.len() != 32 {
            return Err(PyValueError::new_err("invalid peer eph_pub"));
        }
        let peer_eph_arr: [u8; 32] = peer_eph_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PyValueError::new_err("invalid peer eph_pub"))?;
        let peer_eph = X25519PublicKey::from(peer_eph_arr);

        let salt1_hex: String = get_required(&hs1, "salt")?;
        let salt1_vec = parse_hex(&salt1_hex)?;
        if salt1_vec.len() != 16 {
            return Err(PyValueError::new_err("invalid salt length"));
        }
        let mut salt1 = [0u8; 16];
        salt1.copy_from_slice(&salt1_vec);

        let sig_hex: String = get_required(&hs1, "sig")?;
        let sig_bytes = parse_hex(&sig_hex)?;
        if sig_bytes.len() != 64 {
            return Err(PyValueError::new_err("invalid signature length"));
        }
        let verifying_key = PublicKey::from_bytes(&peer_node_pub)
            .map_err(|_| PyValueError::new_err("invalid peer node_pub"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("invalid signature length"))?;
        let signature = Signature::from_bytes(&sig_arr)
            .map_err(|_| PyValueError::new_err("invalid signature bytes"))?;
        let to_verify = join_parts(&[
            b"HS1",
            self.net_id.as_bytes(),
            peer_eph.as_bytes(),
            &salt1,
            peer_node_id.as_bytes(),
            &peer_node_pub,
        ]);
        verifying_key
            .verify(&to_verify, &signature)
            .map_err(|_| PyValueError::new_err("bad HS1 signature"))?;

        let mut rng = OsRng;
        let eph = StaticSecret::random_from_rng(&mut rng);
        let eph_pub = X25519PublicKey::from(&eph);
        let mut salt2 = [0u8; 16];
        rng.fill_bytes(&mut salt2);

        let shared = eph.diffie_hellman(&peer_eph);
        let salt_concat = [salt1.as_slice(), &salt2].concat();
        let info = join_parts(&[
            b"P2Pv1",
            self.net_id.as_bytes(),
            peer_eph.as_bytes(),
            &salt1,
            eph_pub.as_bytes(),
            &salt2,
        ]);
        let key = hkdf_derive(shared.as_bytes(), &salt_concat, &info, self.key_len)?;
        let aes = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| PyValueError::new_err("invalid AES key"))?;

        let to_sign = join_parts(&[
            b"HS2",
            self.net_id.as_bytes(),
            eph_pub.as_bytes(),
            &salt2,
            peer_eph.as_bytes(),
            &salt1,
            self.node_id.as_bytes(),
            &self.node_pub_bytes,
        ]);
        let signature = keypair.sign(&to_sign);

        let dict = PyDict::new_bound(py);
        dict.set_item("type", "P2P_HS2")?;
        dict.set_item("net", &self.net_id)?;
        dict.set_item("eph_pub", hex::encode(eph_pub.as_bytes()))?;
        dict.set_item("salt", hex::encode(salt2))?;
        dict.set_item("node_id", &self.node_id)?;
        dict.set_item("node_pub", &self.node_pub_hex)?;
        dict.set_item("sig", hex::encode(signature.to_bytes()))?;

        self.aes = Some(aes);
        self.peer_node_id = Some(peer_node_id.clone());
        self.peer_node_pub = Some(peer_node_pub.to_vec());
        self.send_ctr = 0;
        self.recv_ctr = -1;
        self.msg_count = 0;
        self.established_at = now_seconds();

        Ok((dict.unbind(), peer_node_id, peer_node_pub_hex))
    }

    pub fn encrypt<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
    ) -> PyResult<(u64, Bound<'py, PyBytes>)> {
        self.ensure_ready()?;
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("secure channel not established"))?;
        let seq = self
            .send_ctr
            .checked_add(1)
            .ok_or_else(|| PyValueError::new_err("sequence overflow"))?;
        let nonce_bytes = seq_to_nonce(seq, self.nonce_len)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = aes
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| PyValueError::new_err("encryption failed"))?;
        self.send_ctr = seq;
        self.msg_count += 1;

        Ok((seq, PyBytes::new_bound(py, &ciphertext)))
    }

    pub fn decrypt<'py>(
        &mut self,
        py: Python<'py>,
        seq: u64,
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.ensure_ready()?;
        if seq as i64 <= self.recv_ctr {
            return Err(PyValueError::new_err("replayed/out-of-order seq"));
        }
        let aes = self
            .aes
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("secure channel not established"))?;
        let nonce_bytes = seq_to_nonce(seq, self.nonce_len)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = aes
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| PyValueError::new_err("decryption failed"))?;
        self.recv_ctr = seq as i64;
        self.msg_count += 1;

        Ok(PyBytes::new_bound(py, &plaintext))
    }

    fn ensure_ready(&mut self) -> PyResult<()> {
        if self.aes.is_none() {
            return Err(PyValueError::new_err("secure channel not established"));
        }
        let now = now_seconds();
        if now - self.established_at > self.session_ttl {
            return Err(PyValueError::new_err("secure channel expired (TTL)"));
        }
        if self.msg_count >= self.session_max_msg {
            return Err(PyValueError::new_err("secure channel expired (MSG)"));
        }
        Ok(())
    }
}

impl SecureChannelNative {
    fn signing_keypair(&self) -> PyResult<Keypair> {
        let secret = self
            .node_priv
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("node_priv unavailable"))?;
        let secret_key = SecretKey::from_bytes(secret)
            .map_err(|_| PyValueError::new_err("invalid node_priv material"))?;
        Ok(Keypair {
            secret: secret_key,
            public: self.node_pub_key,
        })
    }
}
