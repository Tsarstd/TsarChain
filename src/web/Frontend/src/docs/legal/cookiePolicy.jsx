import LegalLayout from "./LegalLayout";
import { RiShieldCheckLine, RiSettings4Line, RiInformationLine } from "react-icons/ri";

const CookiePolicy = () => {
  return (
    <LegalLayout
      badge="Cookie Policy"
      badgeType="accent"
      title="Cookie & Web Storage Policy"
      subtitle="Complete transparency on how TsarChain utilizes lightweight client-side storage technologies to deliver an optimal web explorer experience."
      effectiveDate="18 August 2026"
      summaryTitle="Zero Tracking Cookies"
      summaryText="TsarChain Web Explorer does NOT use third-party tracking cookies, advertising trackers, Google Analytics, or invasive fingerprinting scripts. We only utilize your browser's native LocalStorage to save your personal UI preferences (such as CRT retro tube scanline mode and recent search history)."
    >
      {/* Clause 1 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 01</div>
        <h2 className="legal-clause__title">What Are Cookies and Web Storage?</h2>
        <div className="legal-clause__content">
          <p>
            Cookies and HTML5 Web Storage (<code>localStorage</code> and <code>sessionStorage</code>) are standard browser technologies 
            that allow websites to store small amounts of data locally on your computer or mobile device.
          </p>
          <p>
            While many commercial websites use HTTP cookies to follow users across the web for targeted behavioral advertising, 
            <strong> TsarChain Web Explorer</strong> adheres to a strict privacy-first philosophy, minimizing client-side storage to only what is strictly necessary for your user experience.
          </p>
          <div className="legal-alert legal-alert--info">
            <RiInformationLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Client-Side Isolation:</strong> Data stored in your browser's <code>localStorage</code> remains entirely on your device and is never automatically transmitted in HTTP request headers to remote tracking servers.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 2 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 02</div>
        <h2 className="legal-clause__title">No Third-Party Tracking or Profiling</h2>
        <div className="legal-clause__content">
          <p>
            We take pride in building software that respects user sovereignty. On our web explorer:
          </p>
          <ul>
            <li><strong>No Analytics Cookies:</strong> We do not integrate Google Analytics, Hotjar, Mixpanel, or similar surveillance trackers.</li>
            <li><strong>No Social Media Tracking Pixels:</strong> We do not embed Facebook Pixels, TikTok pixels, or advertising beacons.</li>
            <li><strong>No Cross-Site Profiling:</strong> We do not build user behavioral profiles or sell browsing telemetry.</li>
          </ul>
          <div className="legal-alert legal-alert--important">
            <RiShieldCheckLine className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Open Web Standards:</strong> Because our frontend is built as a static, decentralized-ready Single Page Application (SPA), all explorer data is fetched directly from public node RPC endpoints.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 3 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 03</div>
        <h2 className="legal-clause__title">Detailed Breakdown of Storage Keys</h2>
        <div className="legal-clause__content">
          <p>
            The following table details every single key utilized by the TsarChain Web Explorer inside your browser's <code>localStorage</code>:
          </p>
          <div className="legal-table-wrapper">
            <table className="legal-table">
              <thead>
                <tr>
                  <th>Item / Key</th>
                  <th>Type</th>
                  <th>Purpose</th>
                  <th>Data Content</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>tsarchain_crt_mode</code></td>
                  <td>Functional (UI)</td>
                  <td>Remembers whether you have enabled or disabled the retro CRT scanline & green raster visual shader effect.</td>
                  <td><code>true</code> or <code>false</code></td>
                </tr>
                <tr>
                  <td><code>tsarchain_search_history</code></td>
                  <td>Functional (UX)</td>
                  <td>Stores your recent search queries (e.g. block heights, Bech32 addresses, transaction IDs) so you can quickly jump back to them.</td>
                  <td>Array of recent string queries (max 10)</td>
                </tr>
                <tr>
                  <td><code>tsarchain_doc_lang</code></td>
                  <td>Functional (Preference)</td>
                  <td>Remembers your preferred language selection for technical documentation (English or Bahasa Indonesia).</td>
                  <td><code>"en"</code> or <code>"id"</code></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Clause 4 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 04</div>
        <h2 className="legal-clause__title">How to Control, Disable, or Clear Web Storage</h2>
        <div className="legal-clause__content">
          <p>
            You have total control over all local data stored by your browser. You can inspect or remove this data at any time:
          </p>
          <ol>
            <li>
              <strong>Direct UI Clearing:</strong> Click the "Clear Search History" button inside the search overlay to immediately purge cached search terms.
            </li>
            <li>
              <strong>Browser Developer Tools:</strong> Press <kbd>F12</kbd> (or <kbd>Ctrl+Shift+I</kbd> / <kbd>Cmd+Option+I</kbd>), navigate to the <em>Application</em> or <em>Storage</em> tab, select <em>Local Storage</em>, and click "Clear All".
            </li>
            <li>
              <strong>Browser Settings:</strong> You can configure your web browser (Chrome, Firefox, Brave, Safari, or Edge) to clear site cookies and local storage automatically each time you close your browser session.
            </li>
          </ol>
          <div className="legal-alert legal-alert--info">
            <RiSettings4Line className="legal-alert-icon" size={18} />
            <div className="legal-alert-text">
              <strong>Impact of Clearing Storage:</strong> If you clear your browser's local storage, the website will simply reset to default visual settings (CRT shader off, empty search history). No critical functionality will be broken.
            </div>
          </div>
        </div>
      </section>

      {/* Clause 5 */}
      <section className="legal-clause">
        <div className="legal-clause__num">Section 05</div>
        <h2 className="legal-clause__title">Policy Updates & Contact</h2>
        <div className="legal-clause__content">
          <p>
            If we introduce new non-intrusive client-side features (such as local bookmarking of graffiti artworks), this Cookie & Web Storage Policy 
            will be updated accordingly to document the exact storage keys and their technical purpose.
          </p>
          <p>
            For questions or feedback regarding our minimal storage architecture, please join the conversation on our{" "}
            <a href="https://github.com/Tsarstd/Graffiti-Protocol/discussions" target="_blank" rel="noopener noreferrer">
              GitHub Discussions
            </a>.
          </p>
        </div>
      </section>
    </LegalLayout>
  );
};

export default CookiePolicy;
