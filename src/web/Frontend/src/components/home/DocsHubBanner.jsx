import { useNavigate } from "react-router-dom";
import { RiBookLine, RiGithubLine, RiBookOpenLine } from "react-icons/ri";

const DocsHubBanner = () => {
  const navigate = useNavigate();

  return (
    <div className="docs-hub-banner">
      <div className="docs-hub-content">
        <span className="section-tag">Decentralized Archive</span>
        <h3 className="docs-hub-title">Dive Deeper into Voice Sovereignty</h3>
        <p className="docs-hub-desc">
          Explore the mathematical proofs, RandomX difficulty adjustments, Proof of Retention 
          challenges, and cultural economics detailed in the official Grungepaper and Protocol Draft.
        </p>
        <div className="docs-hub-buttons">
          <button 
            type="button" 
            className="btn-hero-primary"
            onClick={() => navigate("/documentation")}
          >
            <RiBookLine size={18} />
            <span>Read Docs</span>
          </button>

          <a 
            href="https://github.com/Tsarstd/Graffiti-Protocol" 
            target="_blank" 
            rel="noopener noreferrer" 
            className="btn-hero-secondary"
          >
            <RiGithubLine size={18} />
            <span>GitHub Repository</span>
          </a>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
        <RiBookOpenLine size={120} color="rgba(224, 95, 50, 0.25)" />
      </div>
    </div>
  );
};

export default DocsHubBanner;
