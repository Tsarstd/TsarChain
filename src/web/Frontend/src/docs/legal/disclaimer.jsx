import LegalLayout from "./LegalLayout";
import { RiAlertLine, RiCoinLine, RiCpuLine } from "react-icons/ri";

const Disclaimer = () => {
  return (
    <LegalLayout
      badge="Risk Disclosure"
      badgeType="accent"
      title="Disclaimer & Risk Disclosure"
      subtitle="Critical notices concerning experimental software, non-audited cryptography, non-financial nature, and decentralized network operations."
      effectiveDate="18 August 2026"
      summaryTitle="Important Risk Summary"
      summaryText="TsarChain and Graffiti Protocol represent experimental open-source software crafted by solo creator Caesar Dwi (Tsar Studio) for research, artistic preservation, and educational exploration. The system carries NO commercial guarantees, has not undergone institutional security audits, and does NOT offer financial returns. You interact with the protocol at your own risk."
    >
      {/* Clause 1 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 01</div>
        <h2 className="legal-clause__title">Experimental Software & Solo Developer Notice</h2>
        <div className="legal-clause__content">
          <p>
            <strong>TsarChain / Graffiti Protocol</strong> is an independent software project developed as an experimental passion project 
            by a solo engineer (<strong>Caesar Dwi</strong>) under the graphic design studio brand <strong>Tsar Studio</strong>.
          </p>
          <p>
            You expressly understand and acknowledge that:
          </p>
          <ul>
            <li><strong>No Formal Institutional Audits:</strong> The cryptographic protocols, consensus algorithms (RandomX PoW, LWMA difficulty adjustment), and Rust/C++ native bindings (<code>tsarcore_native</code>) have not undergone formal security audits by specialized cybersecurity firms.</li>
            <li><strong>Active Development & Potential Bugs:</strong> The codebase may contain defects, unhandled edge cases, consensus forks, or vulnerabilities. As stated openly in our repository: <em>this project is the result of passion-driven engineering ("vibe coding") to learn, experiment, and push boundaries.</em></li>
            <li><strong>Private Testing Recommended:</strong> If you choose to run nodes or experiment with mining, you are strongly advised to do so in controlled local environments or isolated virtual private servers (VPS).</li>
          </ul>
          <div className="legal-alert legal-alert--warning">
            <RiAlertLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Honest Disclosure:</strong> There are no promises of commercial enterprise uptime or bug-free operation. We encourage developers to inspect the source code, hunt for vulnerabilities, and submit fixes via pull requests.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 2 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 02</div>
        <h2 className="legal-clause__title">No Financial or Investment Advice</h2>
        <div className="legal-clause__content">
          <p>
            Nothing published on the TsarChain Web Explorer, Kremlin GUI wallet, documentation, whitepapers (Grungepaper), or related communication channels should be construed as financial, investment, legal, or tax advice:
          </p>
          <ul>
            <li>
              <strong>Zero Monetary Value:</strong> The native test token (<code>$TSAR</code>) on the Developer Network (<code>gulag-net</code>) has <strong>zero financial or fiat currency value</strong>. It is not traded on regulated exchanges and cannot be redeemed for legal tender.
            </li>
            <li>
              <strong>No Token Sale or ICO:</strong> There has never been an Initial Coin Offering (ICO), token presale, speculative fundraising campaign, or promise of financial enrichment.
            </li>
            <li>
              <strong>No Speculative Guarantees:</strong> Do not acquire, mine, or interact with TsarChain with any expectation of profit, appreciation, or financial gain.
            </li>
          </ul>
          <div className="legal-alert legal-alert--important">
            <RiCoinLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>No Promises of Riches:</strong> TsarChain is an infrastructure for cultural archiving and digital expression, not a speculative investment vehicle.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 3 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 03</div>
        <h2 className="legal-clause__title">Decentralized Content & Voice Sovereignty</h2>
        <div className="legal-clause__content">
          <p>
            Graffiti Protocol is architected for <strong>Voice Sovereignty</strong> — anchoring user-submitted digital art, testimonies, and cultural archives 
            onto distributed proof-of-work block headers and decentralized Archivist storage nodes.
          </p>
          <ul>
            <li>
              <strong>No Publisher or Editorial Status:</strong> Tsar Studio and Caesar Dwi act merely as software developers, NOT as publishers, editors, hosts, or moderators of content submitted by third-party network participants.
            </li>
            <li>
              <strong>Permanent Blockchain Replicas:</strong> Content broadcasted to the peer-to-peer network is replicated across independent validating nodes. Once anchored, data cannot be modified, hidden, or deleted by any centralized party.
            </li>
            <li>
              <strong>User Responsibility:</strong> Any individual broadcasting content to the chain bears sole legal, civil, and criminal liability for the legality and intellectual property rights of that material under their local jurisdiction.
            </li>
          </ul>
        </div>
      </section>

      {/* Clause 4 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 04</div>
        <h2 className="legal-clause__title">Hardware & Operational Mining Risks</h2>
        <div className="legal-clause__content">
          <p>
            Executing Proof-of-Work mining scripts (e.g. <code>cli_node_miner.py</code>) engages the RandomX algorithm, which utilizes intensive CPU, RAM, and native instruction pipelines:
          </p>
          <ul>
            <li><strong>Thermal & Hardware Stress:</strong> Continuous PoW computation generates significant heat and power consumption. You are solely responsible for monitoring your hardware temperatures, cooling systems, and electrical load.</li>
            <li><strong>Network Reorganizations:</strong> Due to fluctuating hashrates and difficulty adjustment mechanics (LWMA / EDA), block reorganizations (reorgs) or orphan blocks may occur. Mining rewards on orphaned blocks will be invalidated by consensus rules.</li>
          </ul>
          <div className="legal-alert legal-alert--info">
            <RiCpuLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Hardware Safety:</strong> Tsar Studio accepts no liability for hardware wear, thermal degradation, or electrical costs resulting from running miner processes.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 5 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 05</div>
        <h2 className="legal-clause__title">Complete Limitation of Liability & Indemnification</h2>
        <div className="legal-clause__content">
          <p>
            IN ACCORDANCE WITH THE PERMISSIVE MIT LICENSE, IN NO EVENT SHALL THE DEVELOPER (CAESAR DWI), TSAR STUDIO, OR PROJECT CONTRIBUTORS 
            BE HELD LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA, LOSS OF CRYPTOGRAPHIC ACCESS, ASSET FORFEITURE, OR OTHER LIABILITY, WHETHER IN 
            AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
            THE SOFTWARE.
          </p>
          <p>
            By using this software, you agree to indemnify, defend, and hold harmless Caesar Dwi and Tsar Studio from and against any claims, damages, 
            liabilities, and expenses arising from your use of the protocol or your violation of applicable laws.
          </p>
        </div>
      </section>

      {/* Clause 6 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 06</div>
        <h2 className="legal-clause__title">Unofficial Third-Party Builds & Forks</h2>
        <div className="legal-clause__content">
          <p>
            Because this codebase is fully open-source, third parties may create forks, unofficial binaries, or alternative clients. 
            To prevent security risks such as trojanized wallets or phishing sites:
          </p>
          <ul>
            <li>Only build software from the authentic repository: <code>https://github.com/Tsarstd/Graffiti-Protocol</code></li>
            <li>Verify file integrity, git commit signatures, and release checksums prior to running binaries.</li>
            <li>We do not provide technical support or security guarantees for modified third-party forks.</li>
          </ul>
        </div>
      </section>
    </LegalLayout>
  );
};

export default Disclaimer;
