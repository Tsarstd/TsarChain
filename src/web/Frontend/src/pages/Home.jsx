import CyberBackground from "../components/home/CyberBackground";
import HeroBanner from "../components/home/HeroBanner";
import TelemetryTicker from "../components/home/TelemetryTicker";
import ManifestoSection from "../components/home/ManifestoSection";
import BlockGraffitiEngine from "../components/home/BlockGraffitiEngine";
import ArchitectureBento from "../components/home/ArchitectureBento";
import DocsHubBanner from "../components/home/DocsHubBanner";

const Home = () => {
  return (
    <div className="home-container">
      {/* 2D Cyber Canvas Ambient Background */}
      <CyberBackground />

      {/* 1. Hero Section (Centered & Sleek Scramble Headline) */}
      <HeroBanner />

      {/* 2. Realtime Telemetry Bar */}
      <TelemetryTicker />

      {/* 3. The Manifesto (Voice Sovereignty) */}
      <ManifestoSection />

      {/* 4. The 1 Block = 1 Graffiti Consensus Engine */}
      <BlockGraffitiEngine />

      {/* 5. Architecture Bento Grid */}
      <ArchitectureBento />

      {/* 6. Documentation & Grungepaper Vault Banner */}
      <DocsHubBanner />
    </div>
  );
};

export default Home;
