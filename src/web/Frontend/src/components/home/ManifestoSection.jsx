import { motion } from "motion/react";
import { RiCloseCircleLine, RiCheckboxCircleLine } from "react-icons/ri";

const ManifestoSection = () => {
  return (
    <section className="manifesto-section">
      <div className="section-header">
        <span className="section-tag">The Manifesto</span>
        <h2 className="section-title">Platforms Curate History. Networks Preserve It.</h2>
        <p className="section-subtitle">
          In an era where digital traces vanish at the whim of platform moderators and server outages, 
          Graffiti Protocol elevates digital art and human testimonies into first-class citizens of the blockchain.
        </p>
      </div>

      <div className="manifesto-cards-grid">
        {/* Curated / Web2 Card */}
        <motion.div 
          className="manifesto-card manifesto-card--web2"
          whileHover={{ y: -4 }}
          transition={{ duration: 0.2 }}
        >
          <span className="manifesto-card-tag">Traditional Web2 Systems</span>
          <h3 className="manifesto-card-heading">Ephemeral & Curated Memory</h3>
          <p className="manifesto-card-body">
            Centralized platforms decide which voices are boosted and which are purged. Cultural heritage 
            is held hostage by proprietary databases and opaque algorithmic feeds.
          </p>

          <ul className="manifesto-features-list">
            <li className="manifesto-feature-item">
              <RiCloseCircleLine className="manifesto-feature-icon-bad" size={18} />
              <span>Subject to unilateral censorship and shadowbans</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCloseCircleLine className="manifesto-feature-icon-bad" size={18} />
              <span>Single point of failure and fragile server lifespans</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCloseCircleLine className="manifesto-feature-icon-bad" size={18} />
              <span>Platform extracts 100% of the monetization value</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCloseCircleLine className="manifesto-feature-icon-bad" size={18} />
              <span>Metadata stripped and intellectual attribution lost</span>
            </li>
          </ul>
        </motion.div>

        {/* Sovereign / Graffiti Protocol Card */}
        <motion.div 
          className="manifesto-card manifesto-card--sovereign"
          whileHover={{ y: -4 }}
          transition={{ duration: 0.2 }}
        >
          <span className="manifesto-card-tag">Graffiti Protocol</span>
          <h3 className="manifesto-card-heading">Sovereign & Uncensorable Memory</h3>
          <p className="manifesto-card-body">
            Every block anchors culture permanently. Cryptographic proofs and distributed storage 
            guarantee that testimonies, art, and expression endure across generations.
          </p>

          <ul className="manifesto-features-list">
            <li className="manifesto-feature-item">
              <RiCheckboxCircleLine className="manifesto-feature-icon-good" size={18} />
              <span>1 Block = 1 Graffiti guaranteed quota in candidate blocks</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCheckboxCircleLine className="manifesto-feature-icon-good" size={18} />
              <span>Archivist Distributed Storage with Proof of Retention (PoR)</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCheckboxCircleLine className="manifesto-feature-icon-good" size={18} />
              <span>80/10/10 Split incentive directly rewarding creators and storage</span>
            </li>
            <li className="manifesto-feature-item">
              <RiCheckboxCircleLine className="manifesto-feature-icon-good" size={18} />
              <span>Signal-grade X3DH & Double Ratchet private P2P communications</span>
            </li>
          </ul>
        </motion.div>
      </div>
    </section>
  );
};

export default ManifestoSection;
