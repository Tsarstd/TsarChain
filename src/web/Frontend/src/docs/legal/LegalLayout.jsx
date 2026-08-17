import { useState, useEffect, useRef, useCallback } from "react";
import PropTypes from "prop-types";
import { Link, useLocation } from "react-router-dom";
import { 
  RiFileTextLine, 
  RiShieldCheckLine, 
  RiCookieLine, 
  RiAlertLine, 
  RiScales3Line,
  RiFileCopyLine, 
  RiPrinterLine, 
  RiCheckLine,
  RiExternalLinkLine,
  RiCalendarLine,
  RiUserLine,
  RiInformationLine,
  RiArrowLeftSLine,
  RiArrowRightSLine
} from "react-icons/ri";
import { useDragScroll } from "../../utils/useDragScroll";

const LEGAL_TABS = [
  { path: "/terms", label: "Terms of Service", icon: RiFileTextLine },
  { path: "/privacyPolicy", label: "Privacy Policy", icon: RiShieldCheckLine },
  { path: "/cookiePolicy", label: "Cookie Policy", icon: RiCookieLine },
  { path: "/disclaimer", label: "Disclaimer", icon: RiAlertLine },
  { path: "/license", label: "License", icon: RiScales3Line },
];

export const LegalLayout = ({
  badge = "Legal & Compliance",
  badgeType = "accent",
  title,
  subtitle,
  effectiveDate = "18 August 2026",
  summaryTitle = "Quick Summary",
  summaryText,
  children
}) => {
  const location = useLocation();
  const [copied, setCopied] = useState(false);
  const activeTabRef = useRef(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();

  useEffect(() => {
    document.title = `${title} | TsarChain Legal`;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [title]);

  const handleCopyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  // Normalization for active tab highlighting
  const currentPath = location.pathname.toLowerCase();

  // Scroll Indicators Check
  const updateScrollState = useCallback(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const { scrollLeft, scrollWidth, clientWidth } = el;
    setCanScrollLeft(scrollLeft > 6);
    setCanScrollRight(scrollLeft < scrollWidth - clientWidth - 6);
  }, [scrollerRef]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    
    updateScrollState();
    el.addEventListener("scroll", updateScrollState, { passive: true });
    window.addEventListener("resize", updateScrollState);

    return () => {
      el.removeEventListener("scroll", updateScrollState);
      window.removeEventListener("resize", updateScrollState);
    };
  }, [updateScrollState, scrollerRef]);

  // Automatically center active tab on mount / route change
  useEffect(() => {
    if (activeTabRef.current && scrollerRef.current) {
      const activeEl = activeTabRef.current;
      const scroller = scrollerRef.current;
      const targetScroll = activeEl.offsetLeft - (scroller.clientWidth / 2) + (activeEl.clientWidth / 2);
      scroller.scrollTo({
        left: Math.max(0, targetScroll),
        behavior: "smooth",
      });
      setTimeout(updateScrollState, 350);
    }
  }, [location.pathname, scrollerRef, updateScrollState]);

  const handleScrollLeft = () => {
    if (scrollerRef.current) {
      scrollerRef.current.scrollBy({ left: -220, behavior: "smooth" });
    }
  };

  const handleScrollRight = () => {
    if (scrollerRef.current) {
      scrollerRef.current.scrollBy({ left: 220, behavior: "smooth" });
    }
  };

  return (
    <div className="legal-page-container">
      {/* 1. Header Banner */}
      <header className="legal-header">
        <div className="legal-header-top">
          <div className="legal-badge-group">
            <span className={`legal-badge ${badgeType === "accent" ? "legal-badge--accent" : "legal-badge--green"}`}>
              <RiInformationLine size={13} />
              <span>{badge}</span>
            </span>
            <span className="legal-badge">
              <span>MIT</span>
            </span>
          </div>

          <div className="legal-header-actions">
            <button 
              type="button" 
              className="legal-action-btn" 
              onClick={handleCopyLink}
              title="Copy page link"
              aria-label="Copy page link"
            >
              {copied ? <RiCheckLine size={14} color="#22c55e" /> : <RiFileCopyLine size={14} />}
              <span>{copied ? "Link Copied!" : "Share Link"}</span>
            </button>
            <button 
              type="button" 
              className="legal-action-btn" 
              onClick={handlePrint}
              title="Print document"
              aria-label="Print document"
            >
              <RiPrinterLine size={14} />
              <span>Print</span>
            </button>
          </div>
        </div>

        <h1 className="legal-title">{title}</h1>
        {subtitle && <p className="legal-subtitle">{subtitle}</p>}

        <div className="legal-meta-bar">
          <span className="legal-meta-item">
            <RiCalendarLine size={14} />
            <span>Last Updated : {effectiveDate}</span>
          </span>
          <span className="legal-meta-item">
            <RiUserLine size={14} />
            <span>Author : Tsar Studio (Caesar Dwi)</span>
          </span>
        </div>
      </header>

      {/* 2. Interactive Navigation Tab Switcher with Mobile Drag-Scroll & Arrows */}
      <div className="legal-nav-wrapper">
        {/* Left Arrow Button */}
        {canScrollLeft && (
          <button
            type="button"
            className="legal-nav-arrow legal-nav-arrow--left"
            onClick={handleScrollLeft}
            aria-label="Scroll legal tabs left"
          >
            <RiArrowLeftSLine size={18} />
          </button>
        )}

        {/* Gradient Left Edge Fade */}
        {canScrollLeft && <div className="legal-nav-fade legal-nav-fade--left" aria-hidden="true" />}

        {/* Draggable and Swipable Nav Scroller */}
        <nav 
          className={`legal-nav-switcher ${isDragging ? "is-dragging" : ""}`} 
          ref={scrollerRef}
          {...dragHandlers}
          aria-label="Legal Documents Navigation"
        >
          {LEGAL_TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentPath === tab.path.toLowerCase() || 
              (tab.path === "/cookiePolicy" && currentPath === "/coockiepolicy") ||
              (tab.path === "/privacyPolicy" && currentPath === "/privacy-policy");

            return (
              <Link
                key={tab.path}
                ref={isActive ? activeTabRef : null}
                to={tab.path}
                className={`legal-tab-btn ${isActive ? "active" : ""}`}
                draggable={false}
              >
                <Icon size={15} />
                <span>{tab.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Gradient Right Edge Fade */}
        {canScrollRight && <div className="legal-nav-fade legal-nav-fade--right" aria-hidden="true" />}

        {/* Right Arrow Button */}
        {canScrollRight && (
          <button
            type="button"
            className="legal-nav-arrow legal-nav-arrow--right"
            onClick={handleScrollRight}
            aria-label="Scroll legal tabs right"
          >
            <RiArrowRightSLine size={18} />
          </button>
        )}
      </div>

      {/* 3. Document Body Content */}
      <main className="legal-body">
        {summaryText && (
          <div className="legal-summary-card">
            <div className="legal-summary-card__title">
              <RiInformationLine size={16} />
              <span>{summaryTitle}</span>
            </div>
            <p className="legal-summary-card__text">{summaryText}</p>
          </div>
        )}

        {children}

        {/* 4. Contact & Community Inquiries Box */}
        <section className="legal-contact-box">
          <div className="legal-contact-info">
            <h4>Questions or Legal Inquiries?</h4>
            <p>
              Graffiti Protocol is an open-source public project. For questions regarding terms, security, or licensing, consult our public channels.
            </p>
          </div>
          <div className="legal-contact-links">
            <a 
              href="https://github.com/Tsarstd/Graffiti-Protocol/discussions" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="legal-contact-btn"
            >
              <span>GitHub Discussions</span>
              <RiExternalLinkLine size={13} />
            </a>
            <a 
              href="https://github.com/Tsarstd/Graffiti-Protocol/security/advisories/new" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="legal-contact-btn"
            >
              <span>Report Security</span>
              <RiExternalLinkLine size={13} />
            </a>
          </div>
        </section>
      </main>
    </div>
  );
};

LegalLayout.propTypes = {
  badge: PropTypes.string,
  badgeType: PropTypes.oneOf(["accent", "green", "default"]),
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string,
  effectiveDate: PropTypes.string,
  summaryTitle: PropTypes.string,
  summaryText: PropTypes.string,
  children: PropTypes.node.isRequired,
};

export default LegalLayout;
