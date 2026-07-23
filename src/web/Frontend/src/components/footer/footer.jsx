import { Link } from "react-router-dom";
import { IoLogoGithub } from "react-icons/io";
import { FaInstagram } from "react-icons/fa";
import { SiGumroad } from "react-icons/si";

import { assets } from "../../assets/assets";

const footerSections = [
  {
    title: "Explore",
    links: [
      { text: "Home", url: "/Graffiti", isInternal: true },
      { text: "About", url: "#" },
      { text: "Services", url: "#" },
      { text: "Contact", url: "#" }
    ]
  },
  {
    title: "Learn",
    links: [
      { text: "Documentation", url: "#" },
      { text: "Tutorials", url: "#" },
      { text: "Blog", url: "#" },
      { text: "FAQs", url: "#" }
    ]
  },
  {
    title: "Networks",
    links: [
      { text: "Devnet", url: "/Network", isInternal: true  },
      { text: "Testnet", url: "#" },
      { text: "Info", url: "#"},
    ]
  },
  {
    title: "Legal",
    links: [
      { text: "Privacy Policy", url: "#" },
      { text: "Terms of Service", url: "#" },
      { text: "Cookie Policy", url: "#" },
      { text: "Disclaimer", url: "#" }
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
                  // Gunakan Link untuk rute internal, <a> untuk eksternal
                  if (link.isInternal) {
                    return (
                      <Link
                        className="site-footer__link"
                        to={link.url}
                        key={`${section.title}-${idx}`}
                      >
                        {link.text}
                      </Link>
                    );
                  }

                  return (
                    <a
                      className="site-footer__link"
                      href={link.url}
                      key={`${section.title}-${idx}`}
                    >
                      {link.text}
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
            an Experimental Project by - Tsar Studio 2026
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
