import { useState, useMemo } from "react";
import PropTypes from "prop-types";
import { 
  RiInformationLine, 
  RiAlertLine, 
  RiCheckLine, 
  RiFileCopyLine, 
  RiExternalLinkLine,
  RiFlowChart,
  RiFolderLine,
  RiEyeLine,
  RiEyeOffLine,
  RiTerminalBoxLine,
  RiCommandLine,
  RiShieldCheckLine
} from "react-icons/ri";
import CollapsibleJson from "./CollapsibleJson";

const ALERT_ICONS = {
  important: <RiAlertLine size={20} color="var(--color-tsar-orange)" />,
  warning: <RiAlertLine size={20} color="#f59e0b" />,
  note: <RiInformationLine size={20} color="var(--color-tsar-cream)" />,
  tip: <RiCheckLine size={20} color="#22c55e" />,
};

// Lightweight Syntax Highlighter Tokenizer
const highlightCodeSyntax = (codeStr, lang = "text") => {
  if (!codeStr || typeof codeStr !== "string") return codeStr;

  const lines = codeStr.split("\n");
  return lines.map((line, lineIdx) => {
    // 1. Comment line (starts with // or #)
    if (/^\s*(\/\/|#)/.test(line)) {
      return (
        <span key={`line-${lineIdx}`} className="syn-line">
          <span className="syn-comment">{line}</span>
          {"\n"}
        </span>
      );
    }

    // 2. CLI Prompt line ($ command)
    if (/^\s*\$\s+/.test(line)) {
      const parts = line.split(/^\s*\$\s+/);
      return (
        <span key={`line-${lineIdx}`} className="syn-line">
          <span className="syn-prompt">$ </span>
          <span className="syn-command">{parts[1]}</span>
          {"\n"}
        </span>
      );
    }

    // 3. Tokenize strings, numbers, keywords
    const tokens = [];
    let remaining = line;
    let keyIdx = 0;

    const regex = /(".*?"|'.*?'|\b(fn|let|pub|struct|impl|const|return|async|await|match|enum|mut|type|self|Self|true|false|null|import|from|def|class|cargo|python|node|tsarchain|kremlin|archivist)\b|--?[a-zA-Z0-9_-]+|\b\d+\b)/g;
    let match;
    let lastIndex = 0;

    while ((match = regex.exec(line)) !== null) {
      if (match.index > lastIndex) {
        tokens.push(line.substring(lastIndex, match.index));
      }

      const matchStr = match[0];
      if (matchStr.startsWith('"') || matchStr.startsWith("'")) {
        tokens.push(<span key={`tok-${lineIdx}-${keyIdx++}`} className="syn-string">{matchStr}</span>);
      } else if (matchStr.startsWith("-")) {
        tokens.push(<span key={`tok-${lineIdx}-${keyIdx++}`} className="syn-flag">{matchStr}</span>);
      } else if (/^\d+$/.test(matchStr)) {
        tokens.push(<span key={`tok-${lineIdx}-${keyIdx++}`} className="syn-number">{matchStr}</span>);
      } else {
        tokens.push(<span key={`tok-${lineIdx}-${keyIdx++}`} className="syn-keyword">{matchStr}</span>);
      }
      lastIndex = regex.lastIndex;
    }

    if (lastIndex < line.length) {
      tokens.push(line.substring(lastIndex));
    }

    return (
      <span key={`line-${lineIdx}`} className="syn-line">
        {tokens.length > 0 ? tokens : line}
        {"\n"}
      </span>
    );
  });
};

// Format inline markdown (code, bold, italic)
const formatInlineMarkdown = (text) => {
  if (!text || typeof text !== "string") return text;
  
  const tokens = [];
  let tokenCounter = 0;
  
  const parts = text.split(/(`[^`]+`)/g);
  for (const part of parts) {
    if (part.startsWith("`") && part.endsWith("`")) {
      tokens.push({
        id: `tok-${tokenCounter++}`,
        type: "code",
        content: part.slice(1, -1)
      });
      continue;
    }

    const boldParts = part.split(/(\*\*[^*]+\*\*)/g);
    for (const bPart of boldParts) {
      if (bPart.startsWith("**") && bPart.endsWith("**")) {
        tokens.push({
          id: `tok-${tokenCounter++}`,
          type: "strong",
          content: bPart.slice(2, -2)
        });
        continue;
      }

      const italicParts = bPart.split(/(\*[^*]+\*)/g);
      for (const iPart of italicParts) {
        if (iPart.startsWith("*") && iPart.endsWith("*") && !iPart.startsWith("**")) {
          tokens.push({
            id: `tok-${tokenCounter++}`,
            type: "em",
            content: iPart.slice(1, -1)
          });
        } else if (iPart) {
          tokens.push({
            id: `tok-${tokenCounter++}`,
            type: "text",
            content: iPart
          });
        }
      }
    }
  }

  return tokens.map((token) => {
    if (token.type === "code") {
      return (
        <code key={token.id} className="doc-inline-code">
          {token.content}
        </code>
      );
    }
    if (token.type === "strong") {
      return <strong key={token.id}>{token.content}</strong>;
    }
    if (token.type === "em") {
      return <em key={token.id}>{token.content}</em>;
    }
    return token.content;
  });
};

// Terminal Console Output Window
const TerminalWindow = ({ title = "CLI Output", status = "Completed", output }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderedSyntax = useMemo(() => highlightCodeSyntax(output, "terminal"), [output]);

  return (
    <div className="doc-terminal-window">
      <div className="doc-terminal-titlebar">
        <div className="doc-terminal-controls">
          <span className="doc-terminal-dot doc-terminal-dot--red" />
          <span className="doc-terminal-dot doc-terminal-dot--yellow" />
          <span className="doc-terminal-dot doc-terminal-dot--green" />
        </div>
        <div className="doc-terminal-title">
          <RiCommandLine size={14} />
          <span>{title}</span>
        </div>
        <div className="doc-terminal-actions">
          {status && <span className="doc-terminal-status-badge">{status}</span>}
          <button 
            type="button" 
            className="doc-btn-copy doc-btn-copy--terminal" 
            onClick={handleCopy}
            title="Copy terminal output"
            aria-label="Copy terminal output"
          >
            {copied ? <RiCheckLine size={13} color="#22c55e" /> : <RiFileCopyLine size={13} />}
            <span>{copied ? "Copied!" : "Copy"}</span>
          </button>
        </div>
      </div>
      <div className="doc-terminal-body">
        <pre className="doc-terminal-pre">
          <code>{renderedSyntax}</code>
        </pre>
      </div>
    </div>
  );
};

TerminalWindow.propTypes = {
  title: PropTypes.string,
  status: PropTypes.string,
  output: PropTypes.string.isRequired,
};

// Standalone Command Card Box
const CommandCard = ({ command, title = "Command", comment }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="doc-command-card">
      <div className="doc-command-header">
        <div className="doc-command-title-wrap">
          <span className="doc-command-prompt">$</span>
          <span className="doc-command-title">{title}</span>
        </div>
        <button type="button" className="doc-btn-copy" onClick={handleCopy} aria-label="Copy command">
          {copied ? <RiCheckLine size={14} color="#22c55e" /> : <RiFileCopyLine size={14} />}
          <span>{copied ? "Copied!" : "Copy"}</span>
        </button>
      </div>
      <div className="doc-command-content">
        <div className="doc-command-line">
          <span className="doc-command-prefix">$</span>
          <code className="doc-command-text">{command}</code>
        </div>
        {comment && <div className="doc-command-comment">{comment}</div>}
      </div>
    </div>
  );
};

CommandCard.propTypes = {
  command: PropTypes.string.isRequired,
  title: PropTypes.string,
  comment: PropTypes.string,
};

// Code Snippet Box with Syntax Highlights
const CodeSnippet = ({ code, lang = "bash", title }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderedSyntax = useMemo(() => highlightCodeSyntax(code, lang), [code, lang]);

  return (
    <div className="doc-code-snippet-wrap">
      <div className="doc-code-header">
        <div className="doc-code-title">
          <RiTerminalBoxLine size={15} />
          <span>{title || lang.toUpperCase()}</span>
        </div>
        <button type="button" className="doc-btn-copy" onClick={handleCopy} aria-label="Copy code snippet">
          {copied ? <RiCheckLine size={14} color="#22c55e" /> : <RiFileCopyLine size={14} />}
          <span>{copied ? "Copied!" : "Copy"}</span>
        </button>
      </div>
      <pre className="doc-code-block">
        <code>{renderedSyntax}</code>
      </pre>
    </div>
  );
};

CodeSnippet.propTypes = {
  code: PropTypes.string.isRequired,
  lang: PropTypes.string,
  title: PropTypes.string,
};

// Code Tabs Component
const CodeTabs = ({ tabs = [] }) => {
  const [activeTabIdx, setActiveTabIdx] = useState(0);
  const activeTab = tabs[activeTabIdx] || tabs[0];
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!activeTab) return;
    navigator.clipboard.writeText(activeTab.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderedSyntax = useMemo(() => {
    return activeTab ? highlightCodeSyntax(activeTab.code, activeTab.lang || "text") : null;
  }, [activeTab]);

  return (
    <div className="doc-code-tabs-wrap">
      <div className="doc-tabs-nav-row">
        <div className="doc-tabs-pills">
          {tabs.map((tab, idx) => (
            <button
              key={tab.label}
              type="button"
              className={`doc-tab-pill ${idx === activeTabIdx ? "active" : ""}`}
              onClick={() => setActiveTabIdx(idx)}
              aria-label={`Switch to tab ${tab.label}`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <button type="button" className="doc-btn-copy" onClick={handleCopy} aria-label="Copy active tab code">
          {copied ? <RiCheckLine size={14} color="#22c55e" /> : <RiFileCopyLine size={14} />}
          <span>{copied ? "Copied!" : "Copy"}</span>
        </button>
      </div>
      <pre className="doc-code-block">
        <code>{renderedSyntax}</code>
      </pre>
    </div>
  );
};

CodeTabs.propTypes = {
  tabs: PropTypes.arrayOf(
    PropTypes.shape({
      label: PropTypes.string.isRequired,
      code: PropTypes.string.isRequired,
      lang: PropTypes.string,
    })
  ),
};

// Comprehensive Markdown Block Parser (Supports code blocks, quotes, lists, headings)
const FormattedMarkdownContent = ({ content }) => {
  if (!content) return null;

  // Split by code fences ```lang\ncode```
  const fenceRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
  const blocks = [];
  let lastIndex = 0;
  let blockCounter = 0;
  let match;

  while ((match = fenceRegex.exec(content)) !== null) {
    const textBefore = content.substring(lastIndex, match.index);
    if (textBefore.trim()) {
      blocks.push({ id: `block-text-${blockCounter++}`, type: "text", content: textBefore });
    }
    const lang = match[1] || "text";
    const code = match[2].trim();
    blocks.push({ id: `block-code-${blockCounter++}`, type: "code", lang, code });
    lastIndex = fenceRegex.lastIndex;
  }

  const textAfter = content.substring(lastIndex);
  if (textAfter.trim()) {
    blocks.push({ id: `block-text-${blockCounter}`, type: "text", content: textAfter });
  }

  return (
    <div className="doc-markdown-blocks">
      {blocks.map((block) => {
        if (block.type === "code") {
          // If code is CLI output / terminal log
          if (block.lang === "text" || block.lang === "console" || block.lang === "output" || block.code.includes("==> Mining") || block.code.includes("Genesis Block created")) {
            return (
              <TerminalWindow 
                key={block.id}
                title="CLI Output — Genesis Lock Summary"
                status="LMDB Locked"
                output={block.code}
              />
            );
          }
          return (
            <CodeSnippet
              key={block.id}
              code={block.code}
              lang={block.lang}
            />
          );
        }

        // Render plain text paragraphs, headers, and lists
        const parsedParas = block.content
          .split("\n\n")
          .map((p, idx) => ({ id: `${block.id}-p-${idx}`, text: p.trim() }))
          .filter((p) => p.text.length > 0);

        return (
          <div key={block.id} className="doc-paragraph-group">
            {parsedParas.map((para) => {
              const trimmed = para.text;

              // Subheading H3
              if (trimmed.startsWith("### ")) {
                return (
                  <h3 key={para.id} className="doc-subheading-h3">
                    {formatInlineMarkdown(trimmed.replace(/^###\s+/, ""))}
                  </h3>
                );
              }

              // Subheading H4
              if (trimmed.startsWith("#### ")) {
                return (
                  <h4 key={para.id} className="doc-subheading-h4">
                    {formatInlineMarkdown(trimmed.replace(/^####\s+/, ""))}
                  </h4>
                );
              }

              // Bullet list
              if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                const items = trimmed.split("\n").filter((l) => l.trim().startsWith("- ") || l.trim().startsWith("* "));
                return (
                  <ul key={para.id} className="doc-bullet-list">
                    {items.map((item) => {
                      const itemText = item.replace(/^[-*]\s+/, "");
                      return (
                        <li key={`${para.id}-${itemText}`}>
                          {formatInlineMarkdown(itemText)}
                        </li>
                      );
                    })}
                  </ul>
                );
              }

              // Ordered list
              if (/^\d+\.\s/.test(trimmed)) {
                const items = trimmed.split("\n").filter((l) => /^\d+\.\s/.test(l.trim()));
                return (
                  <ol key={para.id} className="doc-ordered-list">
                    {items.map((item) => {
                      const itemText = item.replace(/^\d+\.\s+/, "");
                      return (
                        <li key={`${para.id}-${itemText}`}>
                          {formatInlineMarkdown(itemText)}
                        </li>
                      );
                    })}
                  </ol>
                );
              }

              // Quote
              if (trimmed.startsWith("> ")) {
                return (
                  <blockquote key={para.id} className="doc-quote">
                    {formatInlineMarkdown(trimmed.replace(/^>\s*/gm, ""))}
                  </blockquote>
                );
              }

              // Standard Paragraph
              return (
                <p key={para.id} className="doc-paragraph">
                  {formatInlineMarkdown(trimmed)}
                </p>
              );
            })}
          </div>
        );
      })}
    </div>
  );
};

FormattedMarkdownContent.propTypes = {
  content: PropTypes.string,
};

// Main DocContentRenderer
const DocContentRenderer = ({ docData, activeLang }) => {
  const [treeOpen, setTreeOpen] = useState(false);

  if (!docData) return null;

  const getDocumentContent = () => {
    if (docData.type === "about") {
      return activeLang === "id" ? docData.data.id_lang : docData.data.en;
    }
    return docData.data;
  };

  const content = getDocumentContent();

  return (
    <article className="doc-content-body">
      {/* Optional Architecture Diagram */}
      {content.diagram && (
        <div className="doc-diagram-container">
          <div className="doc-diagram-header">
            <div className="doc-diagram-title">
              <RiFlowChart size={18} color="var(--accent)" />
              <span>Graffiti Protocol Transactions & Data Flow Diagram</span>
            </div>
            <a 
              href={content.diagram} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="doc-diagram-ext-btn"
              title="Open full diagram in new tab"
              aria-label="Open full SVG diagram in new window"
            >
              <RiExternalLinkLine size={16} />
              <span>View Full SVG</span>
            </a>
          </div>
          <div className="doc-diagram-wrapper">
            <img 
              src={content.diagram} 
              alt="Graffiti Protocol Architecture Flow" 
              className="doc-diagram-img" 
            />
          </div>
        </div>
      )}

      {/* Sections rendering */}
      {content.sections?.map((section) => (
        <section key={section.id} id={section.id} className="doc-section">
          <h2 className="doc-section-title">
            <a href={`#${section.id}`} className="doc-section-anchor">#</a>
            {section.title}
          </h2>

          {/* Section Quote */}
          {section.quote && (
            <blockquote className="doc-section-quote">
              {section.quote}
            </blockquote>
          )}

          {/* Alert Callout */}
          {section.alert && (
            <div className={`doc-alert-box doc-alert-box--${section.alert.type || "note"}`}>
              <div className="doc-alert-icon">
                {ALERT_ICONS[section.alert.type] || <RiInformationLine size={20} />}
              </div>
              <div className="doc-alert-content">
                {section.alert.title && (
                  <div className="doc-alert-title">{section.alert.title}</div>
                )}
                <div className="doc-alert-text">{section.alert.text}</div>
              </div>
            </div>
          )}

          {/* Markdown Content */}
          {section.content && <FormattedMarkdownContent content={section.content} />}

          {/* Standalone Command */}
          {section.command && (
            <CommandCard
              command={section.command.code || section.command}
              title={section.command.title}
              comment={section.command.comment}
            />
          )}

          {/* Standalone Terminal Output */}
          {section.terminalOutput && (
            <TerminalWindow
              title={section.terminalOutput.title}
              status={section.terminalOutput.status}
              output={section.terminalOutput.output || section.terminalOutput}
            />
          )}

          {/* Code Snippet */}
          {section.code && <CodeSnippet code={section.code} />}

          {/* Code Tabs */}
          {section.codeTabs && <CodeTabs tabs={section.codeTabs} />}

          {/* Interactive Step Cards (for Deployment & Guides) */}
          {section.steps && (
            <div className="doc-steps-stack">
              {section.steps.map((step) => (
                <div key={step.title || step.step} className="doc-step-card">
                  <div className="doc-step-card-header">
                    <div className="doc-step-number-badge">{step.step}</div>
                    <div className="doc-step-card-title-group">
                      <h3 className="doc-step-card-title">{step.title}</h3>
                      {step.subtitle && <span className="doc-step-card-subtitle">{step.subtitle}</span>}
                    </div>
                  </div>

                  <div className="doc-step-card-body">
                    {step.desc && (
                      <p className="doc-step-card-desc">
                        {formatInlineMarkdown(step.desc)}
                      </p>
                    )}

                    {step.command && (
                      <CommandCard
                        command={typeof step.command === "string" ? step.command : step.command.code}
                        title={step.command.title || "Run Command"}
                        comment={step.command.comment}
                      />
                    )}

                    {step.terminalOutput && (
                      <TerminalWindow
                        title={step.terminalOutput.title || "CLI Output"}
                        status={step.terminalOutput.status || "Success"}
                        output={typeof step.terminalOutput === "string" ? step.terminalOutput : step.terminalOutput.output}
                      />
                    )}

                    {step.note && (
                      <div className="doc-step-note">
                        <RiShieldCheckLine size={16} color="var(--accent)" />
                        <span>{formatInlineMarkdown(step.note)}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Features cards */}
          {section.features && (
            <div className="doc-features-grid">
              {section.features.map((feature) => (
                <div key={feature.title} className="doc-feature-card">
                  <h4 className="doc-feature-title">{feature.title}</h4>
                  <p className="doc-feature-desc">{feature.desc}</p>
                </div>
              ))}
            </div>
          )}

          {/* Items key-value list */}
          {section.items && (
            <div className="doc-items-list">
              {section.items.map((item) => (
                <div key={item.label} className="doc-item-row">
                  <div className="doc-item-label">{item.label}</div>
                  <div className="doc-item-text">{item.text}</div>
                </div>
              ))}
            </div>
          )}

          {/* Table */}
          {section.table && (
            <div className="doc-table-wrapper">
              <table className="doc-data-table">
                <thead>
                  <tr>
                    {section.table.headers.map((header) => (
                      <th key={header}>{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {section.table.rows.map((row) => {
                    const rowKey = Array.isArray(row) ? row.join("-") : String(row);
                    return (
                      <tr key={`row-${rowKey}`}>
                        {row.map((cell, cellIdx) => {
                          const colHeader = section.table.headers?.[cellIdx] || `col-${cellIdx}`;
                          return (
                            <td key={`cell-${colHeader}-${cell}`}>
                              {formatInlineMarkdown(cell)}
                            </td>
                          );
                        })}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Interactive Collapsible Project Tree */}
          {section.collapsibleTree && (
            <div className="doc-collapsible-tree-wrap">
              <button 
                type="button"
                className="doc-collapsible-tree-header" 
                onClick={() => setTreeOpen((prev) => !prev)}
                aria-expanded={treeOpen}
                aria-label="Toggle file tree visualization"
              >
                <div className="doc-collapsible-tree-title">
                  <RiFolderLine size={18} color="var(--accent)" />
                  <span>{section.collapsibleTree.title}</span>
                </div>
                <div className="doc-toggle-badge">
                  {treeOpen ? <RiEyeOffLine size={15} /> : <RiEyeLine size={15} />}
                  <span>{treeOpen ? "Hide Map" : "View Map"}</span>
                </div>
              </button>
              {treeOpen && (
                <pre className="doc-code-block doc-tree-block">
                  <code>{section.collapsibleTree.code}</code>
                </pre>
              )}
            </div>
          )}

          {/* Interactive Collapsible JSON Data Structures */}
          {section.dataStructures && (
            <div className="doc-data-structures-stack">
              {section.dataStructures.map((ds) => (
                <CollapsibleJson
                  key={ds.id}
                  title={ds.title}
                  subtitle={ds.subtitle}
                  code={ds.code}
                  defaultOpen={false}
                />
              ))}
            </div>
          )}

          {/* Reference Links Cards */}
          {section.links && (
            <div className="doc-links-grid">
              {section.links.map((link) => (
                <a
                  key={link.url || link.title}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="doc-link-card"
                  aria-label={`Open reference link ${link.title}`}
                >
                  <div className="doc-link-card-header">
                    <span className="doc-link-title">{link.title}</span>
                    <RiExternalLinkLine size={16} className="doc-link-icon" />
                  </div>
                  <p className="doc-link-desc">{link.desc}</p>
                </a>
              ))}
            </div>
          )}
        </section>
      ))}
    </article>
  );
};

DocContentRenderer.propTypes = {
  docData: PropTypes.shape({
    type: PropTypes.string.isRequired,
    data: PropTypes.object.isRequired,
  }),
  activeLang: PropTypes.string.isRequired,
};

export default DocContentRenderer;
