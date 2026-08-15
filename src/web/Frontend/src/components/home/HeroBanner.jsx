import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { useScrambleText } from "../../utils/useScrambleText";

const HEADLINE_TEXT = "WHERE VOICE BECOMES IMMUTABLE CONSENSUS";
const ACCENT_WORD = "IMMUTABLE";
const accentStart = HEADLINE_TEXT.indexOf(ACCENT_WORD);
const accentEnd = accentStart + ACCENT_WORD.length;

const HeroBanner = () => {
  const navigate = useNavigate();
  const { displayText: headlineText, isScrambling } = useScrambleText(
    HEADLINE_TEXT,
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

        <h1 className={`hero-title hero-title--centered ${isScrambling ? "hero-title--scrambling" : ""}`}>
          {headlineText.slice(0, accentStart)}
          <span className="hero-title-accent">
            {headlineText.slice(accentStart, accentEnd)}
          </span>
          {headlineText.slice(accentEnd)}
        </h1>

        <p className="hero-description hero-description--centered">
          A distributed Proof-of-Work UTXO system that treats cultural art and human testimonies 
          as primary transactions rather than mere footnotes. Anchored in block headers, 
          preserved across epochs by citizen-owned nodes.
        </p>

        <div className="hero-actions hero-actions--centered">
          <button 
            type="button" 
            className="btn-hero-primary"
            onClick={() => navigate("/block")}
          >
            <span>Explore Blocks</span>
          </button>

          <button 
            type="button" 
            className="btn-hero-secondary"
            onClick={() => navigate("/graffiti")}
          >
            <span>Explore Graffiti</span>
          </button>
        </div>
      </motion.div>
    </section>
  );
};

export default HeroBanner;
