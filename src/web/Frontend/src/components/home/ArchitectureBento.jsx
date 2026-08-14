import { motion } from "motion/react";
import { 
  RiCpuLine, 
  RiChatPrivateLine, 
  RiHardDrive2Line, 
  RiShieldFlashLine 
} from "react-icons/ri";

const ArchitectureBento = () => {
  return (
    <section className="bento-section">
      <div className="section-header">
        <span className="section-tag">System Architecture</span>
        <h2 className="section-title">Engineered for Permanence & Sovereignty</h2>
        <p className="section-subtitle">
          A four-pillar technological stack combining native Rust cryptographic acceleration, 
          Signal-grade private messaging, and decentralized storage economics.
        </p>
      </div>

      <div className="bento-grid">
        {/* Tile 1: RandomX PoW (Large 7 cols) */}
        <motion.div 
          className="bento-card bento-card-large-1"
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <div className="bento-card-header">
            <div className="bento-card-icon">
              <RiCpuLine />
            </div>
            <span className="bento-card-chip">CONSENSUS CORE</span>
          </div>

          <div className="bento-card-content">
            <h3 className="bento-card-title">Democratic RandomX Proof-of-Work</h3>
            <p className="bento-card-desc">
              ASIC-resistant CPU mining paired with Zawy's LWMA (Linearly Weighted Moving Average) 
              difficulty algorithm ensures that block production remains distributed among citizens, 
              preventing hashrate centralization. Accelerated via Rust PyO3 native extensions.
            </p>
            <div className="bento-tech-badges">
              <span className="bento-badge">RandomX Algo</span>
              <span className="bento-badge">LWMA Difficulty</span>
              <span className="bento-badge">ASIC Resistant</span>
            </div>
          </div>
        </motion.div>

        {/* Tile 2: Kremlin Wallet & E2EE Chat (Medium 5 cols) */}
        <motion.div 
          className="bento-card bento-card-medium-1"
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <div className="bento-card-header">
            <div className="bento-card-icon">
              <RiChatPrivateLine />
            </div>
            <span className="bento-card-chip">PRIVACY & IDENTITY</span>
          </div>

          <div className="bento-card-content">
            <h3 className="bento-card-title">Kremlin Wallet & Chat</h3>
            <p className="bento-card-desc">
              Signal-protocol encrypted P2P messaging utilizing X3DH Key Agreement and the Double Ratchet 
              algorithm alongside Bech32 <code>tsar1...</code> native SegWit wallet management.
            </p>
            <div className="bento-tech-badges">
              <span className="bento-badge">Signal X3DH</span>
              <span className="bento-badge">Double Ratchet</span>
            </div>
          </div>
        </motion.div>

        {/* Tile 3: Archivist Storage Node (Medium 5 cols) */}
        <motion.div 
          className="bento-card bento-card-medium-2"
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <div className="bento-card-header">
            <div className="bento-card-icon">
              <RiHardDrive2Line />
            </div>
            <span className="bento-card-chip">STORAGE LAYER</span>
          </div>

          <div className="bento-card-content">
            <h3 className="bento-card-title">Archivist Storage Nodes</h3>
            <p className="bento-card-desc">
              Dedicated storage operators host heavy binary art & video chunks off-chain while regularly 
              fulfilling cryptographic Proof of Retention (PoR) challenges to claim epoch reward payouts.
            </p>
            <div className="bento-tech-badges">
              <span className="bento-badge">Proof of Retention</span>
              <span className="bento-badge">Epoch Payouts</span>
              <span className="bento-badge">Chunk Replication</span>
            </div>
          </div>
        </motion.div>

        {/* Tile 4: SegWit UTXO & 80/10/10 Split (Large 7 cols) */}
        <motion.div 
          className="bento-card bento-card-large-2"
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <div className="bento-card-header">
            <div className="bento-card-icon">
              <RiShieldFlashLine />
            </div>
            <span className="bento-card-chip">UTXO LEDGER</span>
          </div>

          <div className="bento-card-content">
            <h3 className="bento-card-title">SegWit Ledger & Split Economy</h3>
            <p className="bento-card-desc">
              Native SegWit (BIP-141 / BIP-143) transaction serialization with Low-S signature verification. 
              Billable comments and tipping incentives allocate value automatically: 80% to Creator, 10% to Miners, 
              and 10% to Storage Archivists.
            </p>
            <div className="bento-tech-badges">
              <span className="bento-badge">BIP-141 / 143</span>
              <span className="bento-badge">Dandelion++</span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default ArchitectureBento;
