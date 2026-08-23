import LegalLayout from "./LegalLayout";
import { RiShieldCheckLine, RiEyeOffLine, RiLockPasswordLine } from "react-icons/ri";

const PrivacyPolicy = () => {
  return (
    <LegalLayout
      badge="Privacy Policy"
      badgeType="green"
      title="Privacy Policy"
      subtitle="Transparency, sovereignty, and zero unnecessary data collection. Discover how your data is handled across TsarChain and Graffiti Protocol."
      effectiveDate="18 August 2026"
      summaryTitle="Zero-Tracking Commitment"
      summaryText="TsarChain Web Explorer and the Graffiti Protocol do not collect personal identifiers, do not sell user data, do not require user account registration, and do not employ third-party tracking cookies or advertising pixels. What happens on your machine stays on your machine; what you broadcast to the public blockchain is auditable by everyone."
    >
      {/* Clause 1 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 01</div>
        <h2 className="legal-clause__title">Privacy Philosophy & Core Principles</h2>
        <div className="legal-clause__content">
          <p>
            At <strong>TsarChain / Graffiti Protocol</strong>, founded by Caesar Dwi under Tsar Studio, privacy is not an afterthought — it is a foundational architectural principle.
          </p>
          <p>
            Traditional web applications collect emails, IP addresses, browsing patterns, and identity documents. In contrast, our platform is built on the following tenets:
          </p>
          <ul>
            <li><strong>No Account Registration:</strong> You never need to submit a username, password, email address, or phone number to browse the explorer or use the protocol.</li>
            <li><strong>No KYC or Identity Profiling:</strong> We do not conduct Know-Your-Customer (KYC) identity checks or log user profiles.</li>
            <li><strong>Zero Data Monetization:</strong> We do not sell, rent, monetize, or broker user metadata to advertising networks or data brokers.</li>
          </ul>
          <div className="legal-alert legal-alert--info">
            <RiEyeOffLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Decentralized Non-Custodial Model:</strong> Your relationship with TsarChain is cryptographic, governed purely by mathematics and public-key cryptography.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 2 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 02</div>
        <h2 className="legal-clause__title">Public On-Chain Blockchain Data</h2>
        <div className="legal-clause__content">
          <p>
            TsarChain is a transparent, public, distributed Proof-of-Work blockchain. By design, certain data broadcasted to the network becomes permanently accessible to the public:
          </p>
          <ul>
            <li>
              <strong>Wallet Addresses:</strong> Public Bech32 addresses (prefixed with <code>tsar1...</code>) and their associated UTXO transaction history.
            </li>
            <li>
              <strong>Transaction Metadata:</strong> Transaction IDs (txid), input/output amounts, timestamps, block heights, and SegWit witness signatures.
            </li>
            <li>
              <strong>Graffiti Payloads:</strong> Art hashes, comments, tip distributions (80/10/10 split incentive mechanism), and metadata deliberately submitted to the chain or Archivist nodes.
            </li>
          </ul>
          <p>
            <em>Please note:</em> Because public blockchain data is replicated across all validating nodes globally, on-chain information is permanent and cannot be modified or deleted.
          </p>
        </div>
      </section>

      {/* Clause 3 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 03</div>
        <h2 className="legal-clause__title">Client-Side Web Storage (LocalStorage)</h2>
        <div className="legal-clause__content">
          <p>
            The TsarChain Web Explorer utilizes your browser's local storage (<code>localStorage</code>) strictly for functional UI preferences. This data remains on your local device and is never transmitted to an external analytics server:
          </p>
          <div className="legal-table-wrapper">
            <table className="legal-table">
              <thead>
                <tr>
                  <th>Storage Key</th>
                  <th>Purpose</th>
                  <th>Retention</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>tsarchain_crt_mode</code></td>
                  <td>Stores your toggle preference for the retro CRT scanline raster effect.</td>
                  <td>Persistent until cleared by user</td>
                </tr>
                <tr>
                  <td><code>tsarchain_search_history</code></td>
                  <td>Caches your recent block, address, and transaction search queries for quick dropdown access.</td>
                  <td>Persistent until cleared by user</td>
                </tr>
                <tr>
                  <td><code>tsarchain_theme_lang</code></td>
                  <td>Stores preferred documentation language selection (EN/ID).</td>
                  <td>Persistent until cleared by user</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Clause 4 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 04</div>
        <h2 className="legal-clause__title">Kremlin Wallet & Encrypted P2P Communications</h2>
        <div className="legal-clause__content">
          <p>
            The <strong>Kremlin</strong> GUI wallet incorporates advanced cryptographic privacy for its peer-to-peer messaging system:
          </p>
          <ul>
            <li>
              <strong>End-to-End Encryption (E2EE):</strong> Private chats utilize the <strong>X3DH (Extended Triple Diffie-Hellman)</strong> key agreement protocol and the <strong>Double Ratchet Algorithm</strong>.
            </li>
            <li>
              <strong>Forward Secrecy & Break-in Recovery:</strong> Every individual message uses ephemeral ratcheted keys, ensuring that past and future messages remain secure even in the event of a temporary key compromise.
            </li>
            <li>
              <strong>No Central Chat Servers:</strong> Messages are exchanged directly between peer nodes; Tsar Studio operates no centralized chat relay or plaintext message log.
            </li>
          </ul>
          <div className="legal-alert legal-alert--important">
            <RiLockPasswordLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Clean-Room Verification:</strong> All cryptographic implementations in Kremlin and <code>tsarcore_native</code> were built clean-room from public RFC specifications (X25519, HKDF, AES-GCM, secp256k1) without third-party proprietary trackers.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 5 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 05</div>
        <h2 className="legal-clause__title">Third-Party Services & External Links</h2>
        <div className="legal-clause__content">
          <p>
            This web and documentation contain hyperlinks to external third-party platforms for community collaboration, repository hosting, or artistic portfolios:
          </p>
          <ul>
            <li><strong>GitHub:</strong> Hosting open-source repositories, release packages, and bug trackers.</li>
            <li><strong>Netlify:</strong> Tsar Studio Web Portofolio Design</li>
            <li><strong>Gumroad & Instagram:</strong> Portfolio and design assets by Tsar Studio.</li>
          </ul>
          <p>
            When you navigate to these external services, their respective privacy policies and terms apply. We encourage you to review their individual data handling practices.
          </p>
        </div>
      </section>

      {/* Clause 6 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 06</div>
        <h2 className="legal-clause__title">User Rights & Local Data Management</h2>
        <div className="legal-clause__content">
          <p>
            Because we do not maintain a centralized user database, you have complete autonomous control over your local footprint:
          </p>
          <ol>
            <li>
              <strong>Clear Local Cache:</strong> You can purge all cached searches and UI preferences at any time by clearing your browser's site data for this domain or clicking the clear history button in the search overlay.
            </li>
            <li>
              <strong>Wallet Sovereignty:</strong> You can discard, rotate, or generate new wallet addresses (<code>tsar1...</code>) whenever desired using Kremlin or CLI tools.
            </li>
          </ol>
        </div>
      </section>

      {/* Clause 7 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 07</div>
        <h2 className="legal-clause__title">Security Vulnerability Reporting</h2>
        <div className="legal-clause__content">
          <p>
            We adhere to responsible vulnerability disclosure. If you identify a potential privacy leak, mempool eavesdropping vulnerability, or cryptographic bug, please report it privately:
          </p>
          <div className="legal-alert legal-alert--warning">
            <RiShieldCheckLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Responsible Disclosure:</strong> Please do not submit confidential security exploits to public issues. Use{" "}
              <a href="https://github.com/Tsarstd/Graffiti-Protocol/security/advisories/new" target="_blank" rel="noopener noreferrer">
                GitHub Security Advisories
              </a>{" "}
              or reach out directly via {" "}
              <a href="https://github.com/Tsarstd" target="_blank" rel="noopener noreferrer">
                @Tsarstd
              </a>{" "}
            </div>
          </div>
        </div>
      </section>
    </LegalLayout>
  );
};

export default PrivacyPolicy;
