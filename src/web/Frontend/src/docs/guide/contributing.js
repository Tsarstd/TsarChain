export const contributing = {
  id: "contributing",
  title: "Contributing to Graffiti Protocol",
  subtitle: "Development Guidelines & Testing Workflow",
  category: "Guides",
  badge: "Open Source",
  toc: [
    { id: "development-setup", label: "1. Development Setup" },
    { id: "running-unit-tests", label: "2. Running Unit Tests Locally" },
    { id: "pull-request-workflow", label: "3. Pull Request (PR) Workflow" },
    { id: "code-ownership", label: "4. Code Ownership & Guarded Files" },
    { id: "community-questions", label: "5. Community & Questions" },
  ],
  sections: [
    {
      id: "development-setup",
      title: "1. Development Setup",
      content: `Thank you for your interest in contributing to **Graffiti Protocol / TsarChain**! We welcome contributions from developers, researchers, and open-source enthusiasts.

To ensure a smooth collaboration process and maintain repository integrity, please review the following guidelines.

Graffiti Protocol is a hybrid project written in **Rust** (performance core & cryptography) and **Python** (chain logic, node orchestrator, & wallet UI).

### Prerequisites
- **Python**: 3.11+ (Python 3.14 recommended for tests)
- **Rust**: Latest stable toolchain (\`rustc\`, \`cargo\`)
- **Maturin**: Build tool for Rust/Python bindings

### Local Setup

1. **Clone the repository:**
\`\`\`bash
git clone https://github.com/Tsarstd/Graffiti-Protocol.git
cd Graffiti-Protocol
\`\`\`

2. **Create a virtual environment:**
\`\`\`bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# Linux/macOS:
source .venv/bin/activate
\`\`\`

3. **Install dependencies & build native Rust module:**
\`\`\`bash
pip install --upgrade pip maturin
pip install ./tsarcore_native
pip install -r requirements.txt
pip install pytest pytest-mock
\`\`\``
    },
    {
      id: "running-unit-tests",
      title: "2. Running Unit Tests Locally",
      content: `Before submitting a Pull Request, make sure all tests pass locally.

### 1. Run Rust Core Tests
\`\`\`bash
cd tsarcore_native
cargo test
cd ..
\`\`\`

### 2. Run Python Unit Tests
\`\`\`bash
# On Linux / WSL:
xvfb-run -a env PYTHONPATH=src pytest

# On Windows (Powershell):
$env:PYTHONPATH="src"; pytest
\`\`\``
    },
    {
      id: "pull-request-workflow",
      title: "3. Pull Request (PR) Workflow",
      content: `1. **Fork the Repository**: Create your feature branch from \`main\` (\`git checkout -b feature/my-cool-feature\`).
2. **Commit Your Changes**: Keep commits atomic and descriptive (\`git commit -m "feat(mempool): add orphan tx cleanup policy"\`).
3. **Ensure Tests Pass**: Verify all Rust & Python unit tests pass locally.
4. **Open a Pull Request**: Submit your PR targeting \`main\`.`
    },
    {
      id: "code-ownership",
      title: "4. Code Ownership & Guarded Files (CODEOWNERS)",
      alert: {
        type: "important",
        title: "PROTECTED PROTOCOL PATHS",
        text: "Files in .github/, tests/, tsarcore_native/tests/, src/tsarchain/consensus/, and src/kremlin/security/ are protected by CODEOWNERS. Any PR modifying these directories requires explicit review and approval from @Tsarstd."
      },
      content: `To protect protocol integrity and security:


- Files in \`.github/\`, \`tests/\`, \`tsarcore_native/tests/\`, \`src/tsarchain/consensus/\`, and \`src/kremlin/security/\` are protected by \`CODEOWNERS\`.
- Any PR modifying these directories requires explicit review and approval from \`@Tsarstd\`.
- Do **not** modify unit tests to force a failing feature to pass. PRs attempting to tamper with unit tests will be flagged by CI.`
    },
    {
      id: "community-questions",
      title: "5. Community & Questions",
      content: `If you have questions, architectural proposals, or feedback, feel free to open a Discussion or Issue.`,
      links: [
        {
          title: "GitHub Discussions",
          desc: "Join community discussions, ask architecture questions, or propose protocol improvements.",
          url: "https://github.com/Tsarstd/Graffiti-Protocol/discussions"
        },
        {
          title: "GitHub Issues",
          desc: "Submit bug reports, feature requests, or track active development tasks.",
          url: "https://github.com/Tsarstd/Graffiti-Protocol/issues"
        }
      ]
    }
  ]
};
