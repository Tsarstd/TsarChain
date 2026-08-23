import { useState } from "react";
import LegalLayout from "./LegalLayout";
import { 
  RiFileCopyLine, 
  RiCheckLine, 
  RiScales3Line, 
  RiShieldCheckLine, 
  RiCodeSSlashLine,
  RiExternalLinkLine
} from "react-icons/ri";

const MIT_LICENSE_TEXT = `MIT License

Copyright (c) 2025-2026 Tsar Studio (Caesar Dwi)

This software includes an independent implementation of 
end-to-end encryption protocols based on published 
technical specifications of:

- X3DH Key Agreement Protocol
- Double Ratchet Algorithm

These implementations were developed through clean-room 
engineering processes without reference to or derivation 
from any AGPL-licensed source code.

Cryptographic primitives use standard libraries and 
well-established algorithms (X25519, HKDF, AES-GCM).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

const THIRD_PARTY_COMPONENTS = [
  {
    name: "RandomX",
    license: "BSD 3-Clause",
    author: "tevador / Monero Project",
    desc: "Proof-of-work algorithm optimized for general-purpose CPUs with memory-hard execution."
  },
  {
    name: "LMDB (Lightning Memory-Mapped Database)",
    license: "OpenLDAP Public License",
    author: "Symas Corporation / Howard Chu",
    desc: "Ultra-fast zero-copy key-value storage engine used for blockchain state and UTXO indices."
  },
  {
    name: "PyO3",
    license: "Apache 2.0 / MIT",
    author: "PyO3 Project and Contributors",
    desc: "Rust bindings for the Python interpreter enabling high-performance native acceleration."
  },
  {
    name: "secp256k1 & rust-secp256k1",
    license: "CC0 / MIT / Apache 2.0",
    author: "Pieter Wuille & Rust-Bitcoin developers",
    desc: "Elliptic curve cryptography for signature verification (ECDSA/Schnorr) and key derivation."
  },
  {
    name: "React & React DOM",
    license: "MIT",
    author: "Meta Platforms, Inc.",
    desc: "Declarative UI library powering the TsarChain web explorer and interactive documentation."
  },
  {
    name: "Tailwind CSS & Motion",
    license: "MIT",
    author: "Tailwind Labs & Framer / Motion Contributors",
    desc: "Utility-first styling system and declarative animation library for fluid web transitions."
  }
];

const LicensePage = () => {
  const [copied, setCopied] = useState(false);

  const handleCopyLicense = () => {
    navigator.clipboard.writeText(MIT_LICENSE_TEXT);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <LegalLayout
      badge="Open Source License"
      badgeType="green"
      title="Software License & Attributions"
      subtitle="Complete licensing terms for TsarChain, Graffiti Protocol, Kremlin Wallet, and tsarcore_native."
      effectiveDate="18 August 2026"
      summaryTitle="Permissive Open Source Freedom"
      summaryText="Graffiti Protocol is free, open-source software licensed under the MIT License. You are free to inspect, fork, modify, compile, and distribute this codebase for educational, personal, or commercial purposes, provided that the original copyright notice is retained."
    >
      {/* Clause 1: Official MIT License Text Box */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 01</div>
        <h2 className="legal-clause__title">Official MIT License</h2>
        <div className="legal-clause__content">
          <p>
            The canonical license text applicable to all source repositories within the TsarChain & Graffiti Protocol monorepo.
          </p>

          <div className="legal-code-box">
            <div className="legal-code-header">
              <div className="legal-code-title">
                <RiScales3Line size={16} />
                <span>LICENSE</span>
              </div>
              <button 
                type="button" 
                className="legal-action-btn" 
                onClick={handleCopyLicense}
                aria-label="Copy raw license text"
              >
                {copied ? <RiCheckLine size={14} color="#22c55e" /> : <RiFileCopyLine size={14} />}
                <span>{copied ? "Copied!" : "Copy License"}</span>
              </button>
            </div>
            <pre className="legal-code-pre">
              <code>{MIT_LICENSE_TEXT}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Clause 2: Clean-Room Cryptography Disclosures */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 02</div>
        <h2 className="legal-clause__title">Clean-Room Cryptographic Implementation</h2>
        <div className="legal-clause__content">
          <p>
            The Kremlin wallet incorporates end-to-end encrypted messaging designed around published technical specifications:
          </p>
          <ul>
            <li><strong>X3DH (Extended Triple Diffie-Hellman):</strong> Implemented independently for mutual asynchronous key agreement.</li>
            <li><strong>Double Ratchet Algorithm:</strong> Implemented independently for forward secrecy and break-in recovery.</li>
          </ul>
          <div className="legal-alert legal-alert--info">
            <RiShieldCheckLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Clean-Room Integrity:</strong> All cryptographic modules were engineered from the ground up from public mathematical papers and RFC specifications without referencing, incorporating, or deriving from any AGPL-licensed codebases.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 3: Upstream & Third-Party Dependencies */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 03</div>
        <h2 className="legal-clause__title">Third-Party & Upstream Open Source Acknowledgements</h2>
        <div className="legal-clause__content">
          <p>
            TsarChain stands on the shoulders of giants in the open-source and cryptographic research communities. 
            We gratefully acknowledge the following core components and their authors:
          </p>

          <div className="legal-table-wrapper">
            <table className="legal-table">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>License</th>
                  <th>Author / Project</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {THIRD_PARTY_COMPONENTS.map((item) => (
                  <tr key={item.name}>
                    <td><strong>{item.name}</strong></td>
                    <td><span className="legal-badge">{item.license}</span></td>
                    <td>{item.author}</td>
                    <td>{item.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Clause 4: Contribution & Governance */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 04</div>
        <h2 className="legal-clause__title">Contributing & Rights Grant</h2>
        <div className="legal-clause__content">
          <p>
            We welcome contributions from developers, designers, and researchers globally:
          </p>
          <ul>
            <li>
              <strong>Inbound Rights:</strong> By submitting a Pull Request to our repository, you agree to license your contributions under the terms of the MIT License.
            </li>
            <li>
              <strong>Code Ownership:</strong> Security-critical paths (such as <code>tsarcore_native</code>, consensus rules, and cryptographic engines) are governed by repository maintainer <strong>@Tsarstd</strong> under the <code>CODEOWNERS</code> policy to maintain network consensus integrity.
            </li>
            <li>
              <strong>Guidelines:</strong> Please review our{" "}
              <a 
                href="https://github.com/Tsarstd/Graffiti-Protocol/blob/main/CONTRIBUTING.md" 
                target="_blank" 
                rel="noopener noreferrer"
                className="legal-link-inline"
              >
                <span>Contributing Guidelines</span>
                <RiExternalLinkLine size={13} />
              </a>{" "}
              before opening a pull request.
            </li>
          </ul>
          <div className="legal-alert legal-alert--info">
            <RiCodeSSlashLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Forking & Experimentation:</strong> You are free to fork this project, run custom testnets, and explore new algorithms. Happy hacking!
            </div>
          </div>
        </div>
      </section>
    </LegalLayout>
  );
};

export default LicensePage;
