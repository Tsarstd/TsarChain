import { useState } from "react";
import { motion } from "motion/react";
import { 
  RiUploadCloud2Line, 
  RiListOrdered2, 
  RiCpuLine, 
  RiShieldCheckLine, 
  RiCoinsLine 
} from "react-icons/ri";

const PIPELINE_STEPS = [
  {
    step: "01",
    icon: RiUploadCloud2Line,
    title: "OP_RETURN Inscription",
    desc: "Creators upload digital art or testimony via Kremlin Wallet. The payload hash is committed directly into the UTXO transaction script.",
  },
  {
    step: "02",
    icon: RiListOrdered2,
    title: "Priority Mempool",
    desc: "The node orchestrator pulls Graffiti transactions to the absolute front of candidate blocks, giving cultural archiving top priority.",
  },
  {
    step: "03",
    icon: RiCpuLine,
    title: "RandomX Anchoring",
    desc: "When mined, the block extracts the unique art_id and aggressively injects it as the Coinbase block_id (1 Block = 1 Graffiti).",
  },
  {
    step: "04",
    icon: RiShieldCheckLine,
    title: "Proof of Retention",
    desc: "Distributed Archivist nodes store the raw binary chunks off-chain and regularly answer PoR retention challenges.",
  },
  {
    step: "05",
    icon: RiCoinsLine,
    title: "Split Economy",
    desc: "Comments & tips distribute value automatically: 80% to the Creator, 10% to PoW Miners, and 10% to Archivist Storage Nodes.",
  },
];

const BlockGraffitiEngine = () => {
  const [activeStep, setActiveStep] = useState(2);

  return (
    <section className="engine-section">
      <div className="section-header">
        <span className="section-tag">Consensus Pipeline</span>
        <h2 className="section-title">1 Block = 1 Graffiti</h2>
        <p className="section-subtitle">
          How TsarChain couples lightweight on-chain UTXO execution with off-chain heavy data storage 
          to enforce the permanent immutability of cultural expression.
        </p>
      </div>

      <div className="engine-pipeline">
        {PIPELINE_STEPS.map((item, index) => {
          const Icon = item.icon;
          const isActive = activeStep === index;
          return (
            <motion.div
              key={item.step}
              className={`engine-step-card ${isActive ? "active" : ""}`}
              onClick={() => setActiveStep(index)}
              whileHover={{ y: -4 }}
              transition={{ duration: 0.2 }}
              style={{ cursor: "pointer" }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div className="engine-step-badge">{item.step}</div>
                <Icon size={20} color={isActive ? "var(--accent)" : "var(--text-muted)"} />
              </div>
              <h3 className="engine-step-title">{item.title}</h3>
              <p className="engine-step-desc">{item.desc}</p>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
};

export default BlockGraffitiEngine;
