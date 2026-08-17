import { Link } from "react-router-dom";
import { IoLogoGithub } from "react-icons/io";
import { FaInstagram } from "react-icons/fa";
import { SiGumroad } from "react-icons/si";

import { assets } from "../../assets/assets";

const footerSections = [
  {
    title: "Explore",
    links: [
      { text: "Block", url: "/block", isInternal: true },
      { text: "Graffiti", url: "/graffiti", isInternal: true },
      { text: "Network", url: "/network", isInternal: true },
    ]
  },
  {
    title: "Learn",
    links: [
      { text: "About", url: "/documentation", isInternal: true },
      { text: "Tutorials", url: "/documentation?doc=deployment" },
      { text: "Architecture", url: "/documentation?doc=architecture" }
    ]
  },
  {
    title: "Networks",
    links: [
      { text: "Devnet", url: "/network", isInternal: true, status: "On" },
      { text: "Mainnet", url: "#", status: "Off" },
    ]
  },
  {
    title: "Legal",
    links: [
      { text: "Privacy Policy", url: "/privacyPolicy", isInternal: true },
      { text: "Terms of Service", url: "/terms", isInternal: true },
      { text: "Cookie Policy", url: "/cookiePolicy", isInternal: true },
      { text: "Disclaimer", url: "/disclaimer", isInternal: true },
      { text: "License", url: "/license", isInternal: true },
    ]
  }
];

const socialLinks = [
  { label: "GitHub", short: <IoLogoGithub />, url: "https://github.com/Tsarstd/Graffiti-Protocol" },
  { label: "Instagram", short: <FaInstagram />, url: "https://www.instagram.com/tsar.std" },
  { label: "Gumroad", short: <SiGumroad />, url: "https://tsarstudio.gumroad.com/" },
];

const Footer = () => {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__top">
          <div className="site-footer__brand">
              <img
                src={assets.logo_footer}
                alt="TsarChain logo"
                className="site-footer__logo"
              />
            <p className="site-footer__tagline">
              Explore the full TsarChain ecosystem.
            </p>
          </div>
          
          {footerSections.map((section) => (
            <div className="site-footer__col" key={section.title}>
              <h4 className="site-footer__title">{section.title}</h4>
              <div className="site-footer__links">
                {section.links.map((link, idx) => {
                  const content = (
                    <>
                      <span className="site-footer__link-text">{link.text}</span>
                      {link.status && (
                        <span className={`site-footer__status-badge site-footer__status-badge--${link.status.toLowerCase()}`}>
                          <span className={`site-footer__status-dot site-footer__status-dot--${link.status.toLowerCase()}`} />
                          <span className="site-footer__status-label">{link.status}</span>
                        </span>
                      )}
                    </>
                  );

                  // Gunakan Link untuk rute internal, <a> untuk eksternal
                  if (link.isInternal) {
                    return (
                      <Link
                        className="site-footer__link"
                        to={link.url}
                        key={`${section.title}-${idx}`}
                      >
                        {content}
                      </Link>
                    );
                  }

                  return (
                    <a
                      className="site-footer__link"
                      href={link.url}
                      key={`${section.title}-${idx}`}
                    >
                      {content}
                    </a>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        
        <div className="site-footer__bottom">
          <div className="site-footer__socials-wrapper">
            <div className="site-footer__socials">
              {socialLinks.map((social) => (
                <a
                  className="site-footer__social"
                  href={social.url}
                  aria-label={social.label}
                  key={social.label}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {social.short}
                </a>
              ))}
            </div>
          </div>
          
          <div className="site-footer__copyright">
            an Experimental Project by -{" "}
            <a
              href="https://tsarstudio.netlify.app"
              target="_blank"
              rel="noopener noreferrer"
              className="site-footer__copyright-link"
            >
              Tsar Studio
            </a>{" "}
            {new Date().getFullYear()}
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
