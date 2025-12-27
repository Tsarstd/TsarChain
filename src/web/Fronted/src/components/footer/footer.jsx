import "./footer.css";
import { assets } from "../../assets/assets.js";

const footerSections = [
  { title: "Explore", count: 4 },
  { title: "Learn", count: 4 },
  { title: "Networks", count: 4 },
  { title: "Legal", count: 4 },
];

const socialLinks = [
  { label: "GitHub", short: "GH" },
  { label: "X", short: "X" },
  { label: "YouTube", short: "YT" },
  { label: "Medium", short: "MD" },
];

const Footer = () => {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__top">
          <div className="site-footer__brand">
            <img
              src={assets.logo_header}
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
                {Array.from({ length: section.count }).map((_, idx) => (
                  <a
                    className="site-footer__link"
                    href="#"
                    key={`${section.title}-${idx}`}
                  >
                    Links
                  </a>
                ))}
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
                  href="#"
                  aria-label={social.label}
                  key={social.label}
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
