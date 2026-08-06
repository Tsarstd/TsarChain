# Security Policy

## 🛡️ Supported Versions

We take security seriously at **Graffiti Protocol**. As a decentralized protocol managing cryptography, PoW consensus, and UTXO ledgers, security vulnerabilities are handled with top priority.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main`           | :white_check_mark: |
| Development      | :white_check_mark: |

---

## 🔒 Reporting a Vulnerability

If you discover a potential security vulnerability in Graffiti Protocol (including consensus logic, mempool validation, Kremlin wallet cryptography, or P2P network implementation), **please do NOT report it in a public GitHub Issue.**

### How to Report Responsibly:
1. **GitHub Security Advisory (Preferred):**
   Submit a private report via [GitHub Security Advisories](https://github.com/Tsarstd/Graffiti-Protocol/security/advisories/new).
2. **Direct Contact:**
   Contact the core maintainer directly via GitHub [@Tsarstd](https://github.com/Tsarstd).

### What to Include in Your Report:
- A clear description of the vulnerability and potential impact.
- Step-by-step instructions or Proof of Concept (PoC) script to reproduce the issue.
- Affected components (e.g., `tsarcore_native`, `tsarchain/consensus`, `kremlin/security`).

---

## ⏱️ Response & Disclosure Timeline

- **Acknowledgement:** We aim to acknowledge receipt of security reports within **24–48 hours**.
- **Assessment & Fix:** We will work on a fix in a private branch and coordinate a release.
- **Public Disclosure:** Once a security patch is deployed to `main`, we will credit the reporter (unless anonymity is requested) and issue a release advisory.

Thank you for helping keep Graffiti Protocol safe and resilient!
