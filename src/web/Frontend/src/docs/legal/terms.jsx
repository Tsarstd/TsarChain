import LegalLayout from "./LegalLayout";
import { RiAlertLine, RiShieldCheckLine, RiInformationLine } from "react-icons/ri";

const TermsOfService = () => {
  return (
    <LegalLayout
      badge="Terms of Service"
      badgeType="accent"
      title="Terms of Service"
      subtitle="Please read these terms carefully before accessing or using the TsarChain Web Explorer, Kremlin Wallet, or Graffiti Protocol infrastructure."
      effectiveDate="18 August 2026"
      summaryTitle="Summary of Key Terms"
      summaryText="TsarChain and Graffiti Protocol are experimental, open-source, non-custodial software systems developed by solo creator Caesar Dwi under Tsar Studio. You are solely responsible for your own cryptographic keys, content submitted to the blockchain, and interactions with the decentralized network. The software is provided 'AS IS' without warranty."
    >
      {/* Clause 1 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 01</div>
        <h2 className="legal-clause__title">Introduction & Project Nature</h2>
        <div className="legal-clause__content">
          <p>
            Welcome to <strong>TsarChain / Graffiti Protocol</strong> (the "Protocol", "Network", or "Platform"). 
            This ecosystem consists of an experimental Proof-of-Work blockchain, native acceleration bindings (<code>tsarcore_native</code>), 
            a non-custodial light wallet (<strong>Kremlin</strong>), decentralized storage nodes (<strong>Archivist</strong>), and a web-based block explorer.
          </p>
          <p>
            This project is an <strong>independent, open-source experimental software project</strong> conceived and developed by solo developer 
            <strong> Caesar Dwi</strong> under the indie graphic design brand <strong>Tsar Studio</strong>. By accessing our web interface, downloading 
            the repository, running nodes, or interacting with the network, you acknowledge and agree to be bound by these Terms of Service.
          </p>
          <div className="legal-alert legal-alert--info">
            <RiInformationLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Open-Source Freedom:</strong> The entire source code is released under the permissive <strong>MIT License</strong>. You are encouraged to audit, fork, test, and contribute through our public GitHub repository.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 2 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 02</div>
        <h2 className="legal-clause__title">Non-Custodial Architecture & Cryptographic Keys</h2>
        <div className="legal-clause__content">
          <p>
            TsarChain operates on a strictly <strong>non-custodial</strong> and decentralized paradigm:
          </p>
          <ul>
            <li>
              <strong>No Key Custody:</strong> Neither Tsar Studio, Caesar Dwi, nor the Web Explorer possesses access to your mnemonic passphrases, private keys, or wallet seed data.
            </li>
            <li>
              <strong>User Responsibility:</strong> You are exclusively responsible for backing up, securing, and safeguarding your cryptographic keys (Bech32 <code>tsar1...</code> addresses and secp256k1 keys).
            </li>
            <li>
              <strong>Loss of Keys:</strong> If you lose your private key or mnemonic phrase, your assets, identity, and associated graffiti permissions cannot be restored or recovered by anyone.
            </li>
          </ul>
          <div className="legal-alert legal-alert--important">
            <RiShieldCheckLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Critical Security Notice:</strong> We will never ask for your private key or seed phrase. Never share your credentials with any third party or unverified application.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 3 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 03</div>
        <h2 className="legal-clause__title">Voice Sovereignty & User-Generated Content</h2>
        <div className="legal-clause__content">
          <p>
            The core ethos of Graffiti Protocol is <strong>Voice Sovereignty</strong> — preserving cultural memory, digital art, and testimonies 
            by anchoring cryptographic hashes directly to RandomX block headers and distributed Archivist storage nodes.
          </p>
          <ul>
            <li>
              <strong>User-Generated Content:</strong> All artworks, messages, comments, metadata, and files uploaded through the Graffiti Protocol are created and broadcasted solely by network participants.
            </li>
            <li>
              <strong>No Pre-Moderation or Central Curation:</strong> Tsar Studio does not screen, filter, alter, or curate content broadcasted to the peer-to-peer network.
            </li>
            <li>
              <strong>Content Liability:</strong> You retain full legal responsibility for any content you publish to the chain. You agree not to anchor content that infringes upon copyright, violates privacy, or breaches applicable laws.
            </li>
          </ul>
        </div>
      </section>

      {/* Clause 4 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 04</div>
        <h2 className="legal-clause__title">Blockchain Immutability & Irreversibility</h2>
        <div className="legal-clause__content">
          <p>
            You acknowledge that decentralized blockchain ledgers are inherently <strong>immutable and irreversible</strong>:
          </p>
          <ol>
            <li>
              Once a transaction, block reward, or graffiti post is validated and included in a confirmed block on TsarChain, it cannot be canceled, refunded, rolled back, or erased.
            </li>
            <li>
              Neither Tsar Studio nor any individual node operator has administrative backdoor privileges or master keys to alter the ledger history.
            </li>
            <li>
              Always verify destination addresses (<code>tsar1...</code>), transaction amounts, and attached graffiti data before broadcasting transactions.
            </li>
          </ol>
        </div>
      </section>

      {/* Clause 5 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 05</div>
        <h2 className="legal-clause__title">Experimental Status & No Financial Advice</h2>
        <div className="legal-clause__content">
          <p>
            TsarChain is active on an <strong>experimental Developer Network (Devnet: <code>gulag-net</code>)</strong>:
          </p>
          <ul>
            <li>
              <strong>Zero Monetary Value:</strong> Devnet tokens, mining test rewards, and protocol balances carry <strong>no intrinsic monetary, financial, or commercial value</strong>.
            </li>
            <li>
              <strong>No Investment Scheme:</strong> There has been no Initial Coin Offering (ICO), presale, or token fundraising. Nothing within the software, website, or documentation constitutes investment, financial, or tax advice.
            </li>
            <li>
              <strong>Network Resets:</strong> As an experimental testing ground, the devnet may undergo hard forks, difficulty resets, or state migrations as protocol development progresses.
            </li>
          </ul>
          <div className="legal-alert legal-alert--warning">
            <RiAlertLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Vibe Coding & Experimental Code:</strong> This codebase was built as a passion-driven learning journey. Do not use this software in production financial environments.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 6 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 06</div>
        <h2 className="legal-clause__title">Prohibited Conduct & Network Integrity</h2>
        <div className="legal-clause__content">
          <p>
            When utilizing public RPC nodes, web explorer interfaces, or P2P network discovery, you agree NOT to:
          </p>
          <ul>
            <li>Execute Distributed Denial of Service (DDoS) attacks against public seed nodes or explorer APIs.</li>
            <li>Deploy automated exploit scripts designed to bypass rate-limiting proof-of-work challenge tokens.</li>
            <li>Impersonate core maintainers or distribute malicious Trojan binaries disguised as TsarChain or Kremlin wallet software.</li>
            <li>Use the software for money laundering, terrorism financing, or any unlawful enterprise in your jurisdiction.</li>
          </ul>
        </div>
      </section>

      {/* Clause 7 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 07</div>
        <h2 className="legal-clause__title">Limitation of Liability & "AS IS" Warranty</h2>
        <div className="legal-clause__content">
          <p>
            TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE, SOURCE CODE, APIS, AND WEB EXPLORER ARE PROVIDED 
            <strong> "AS IS"</strong>, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
            MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.
          </p>
          <p>
            IN NO EVENT SHALL TSAR STUDIO, CAESAR DWI, CONTRIBUTORS, OR AFFILIATES BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
            CONSEQUENTIAL, OR PUNITIVE DAMAGES (INCLUDING LOSS OF PROFITS, DATA, CRYPTOGRAPHIC KEYS, OR HARDWARE MALFUNCTION) ARISING FROM THE 
            USE OR INABILITY TO USE THIS PROTOCOL.
          </p>
        </div>
      </section>

      {/* Clause 8 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 08</div>
        <h2 className="legal-clause__title">Modifications & Contact</h2>
        <div className="legal-clause__content">
          <p>
            As an active open-source project, these Terms may be updated periodically to reflect architectural evolutions. Continued interaction 
            with the protocol following any revisions constitutes your acceptance of the updated terms.
          </p>
          <p>
            For inquiries, technical proposals, or code reviews, please visit our official repository at{" "}
            <a href="https://github.com/Tsarstd/Graffiti-Protocol" target="_blank" rel="noopener noreferrer">
              github.com/Tsarstd/Graffiti-Protocol
            </a>.
          </p>
        </div>
      </section>
    </LegalLayout>
  );
};

export default TermsOfService;
