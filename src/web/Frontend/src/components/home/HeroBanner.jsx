import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { 
  RiCompassDiscoverLine, 
  RiBrushLine,
  RiCpuLine,
  RiShieldCheckLine,
  RiLockLine
} from "react-icons/ri";
import { useScrambleText } from "../../utils/useScrambleText";

const HeroBanner = () => {
  const navigate = useNavigate();
  const { displayText: headlineText } = useScrambleText(
    "WHERE VOICE BECOMES IMMUTABLE CONSENSUS",
    { speed: 20, scrambleDuration: 800 }
  );

  return (
    <section className="hero-section hero-section--centered">
      <motion.div 
        className="hero-center"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="hero-badge-container">
          <span>Graffiti Protocol</span>
        </div>

        <h1 className="hero-title hero-title--centered">
          {headlineText.split("IMMUTABLE")[0]}
          <span className="hero-title-accent">IMMUTABLE</span>
          {headlineText.split("IMMUTABLE")[1] || " CONSENSUS"}
        </h1>

        <p className="hero-description hero-description--centered">
          A distributed Proof-of-Work UTXO system that treats cultural art and human testimonies 
          as primary transactions rather than mere footnotes. Anchored in block headers, 
          preserved across epochs by citizen-owned nodes.
        </p>

        <div className="hero-feature-pills">
          <div className="hero-pill">
            <RiBrushLine color="var(--accent)" />
            <span>1 Block = 1 Graffiti</span>
          </div>
          <div className="hero-pill">
            <RiCpuLine color="var(--accent)" />
            <span>Democratic RandomX PoW</span>
          </div>
          <div className="hero-pill">
            <RiShieldCheckLine color="var(--accent)" />
            <span>Archivist Proof of Retention</span>
          </div>
          <div className="hero-pill">
            <RiLockLine color="var(--accent)" />
            <span>Signal-Grade E2EE</span>
          </div>
        </div>

        <div className="hero-actions hero-actions--centered">
          <button 
            type="button" 
            className="btn-hero-primary"
            onClick={() => navigate("/block")}
          >
            <RiCompassDiscoverLine size={18} />
            <span>Explore Blocks</span>
          </button>

          <button 
            type="button" 
            className="btn-hero-secondary"
            onClick={() => navigate("/graffiti")}
          >
            <RiBrushLine size={18} />
            <span>Explore Graffiti</span>
          </button>
        </div>
      </motion.div>
    </section>
  );
};

export default HeroBanner;
