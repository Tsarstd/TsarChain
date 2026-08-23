export const contributing = {
  id: "contributing",
  title: "Contributing to Graffiti Protocol",
  subtitle: "Development Guidelines, Branching Strategy & PR Workflow",
  category: "Guides",
  badge: "Open Source",
  toc: [
    { id: "branching-strategy", label: "1. Branching Strategy" },
    { id: "development-setup", label: "2. Development Setup" },
    { id: "running-unit-tests", label: "3. Testing & Verification" },
    { id: "pull-request-workflow", label: "4. Pull Request (PR) Workflow" },
    { id: "code-ownership", label: "5. Code Ownership & Guarded Files" },
    { id: "community-questions", label: "6. Community & Questions" },
  ],
  sections: [
    {
      id: "branching-strategy",
      title: "1. Branching Strategy",
      alert: {
        type: "important",
        title: "PROTECTED MAIN BRANCH",
        text: "The main branch is restricted to Code Owners (@Tsarstd). All external contributions and Pull Requests must be branched from and targeted to the dev branch."
      },
      content: `Our repository follows a dual-branch development model:

- **\`main\` (Protected)**: Represents verified, stable, production-ready releases. Direct commits and external Pull Requests to \`main\` are not accepted.
- **\`dev\` (Default for Contributions)**: The active development and staging branch where new features, enhancements, and bugfixes are merged and tested.

> **Rule for External Contributors**: Always branch off \`dev\` and submit your Pull Request targeting \`dev\`.`
    },
    {
      id: "development-setup",
      title: "2. Development Setup",
      content: `Graffiti Protocol is a hybrid project written in **Rust** (performance core, cryptography, and PoW) and **Python** (chain logic, node orchestrator, & wallet UI).

### Prerequisites
- **Python**: 3.11+
- **Rust**: Latest stable toolchain (\`rustc\`, \`cargo\`, \`rustup\`)
- **Maturin**: Build tool for PyO3 Rust/Python bindings
- **Node.js** (Optional): 18+ (only for web frontend contributions)

### Local Environment Setup

1. **Fork and clone the repository:**
\`\`\`bash
git clone https://github.com/<your-username>/Graffiti-Protocol.git
cd Graffiti-Protocol
\`\`\`

2. **Set up upstream remote and track the \`dev\` branch:**
\`\`\`bash
git remote add upstream https://github.com/Tsarstd/Graffiti-Protocol.git
git fetch upstream
git checkout -b dev upstream/dev
\`\`\`

3. **Create a virtual environment:**
\`\`\`bash
python -m venv .venv

# On Windows (PowerShell):
.\\.venv\\Scripts\\Activate.ps1

# On Linux / macOS:
source .venv/bin/activate
\`\`\`

4. **Install dependencies & compile the Rust native module:**
\`\`\`bash
pip install --upgrade pip maturin
pip install -r requirements.txt
pip install pytest pytest-mock
\`\`\`

> 💡 **Tip for Rust development:** Use \`maturin develop\` inside \`tsarcore_native\` to automatically compile and install the native extension into your active virtual environment:
\`\`\`bash
cd tsarcore_native
maturin develop
cd ..
\`\`\``
    },
    {
      id: "running-unit-tests",
      title: "3. Testing & Verification",
      content: `Before submitting a Pull Request, make sure all tests and linters pass locally.

### 1. Run Rust Core Tests
\`\`\`bash
cd tsarcore_native
cargo test
cd ..
\`\`\`

### 2. Run Python Unit Tests
\`\`\`bash
# On Linux / macOS / WSL (headless X server for GUI/Wallet tests):
xvfb-run -a env PYTHONPATH=src pytest

# On Windows (PowerShell):
$env:PYTHONPATH="src"; pytest
\`\`\`

### 3. Code Formatting & Linting
- **Rust**:
\`\`\`bash
cd tsarcore_native
cargo fmt --check
cargo clippy
cd ..
\`\`\`
- **Python**: Adhere to [PEP 8](https://peps.python.org/pep-0008/) style standards.`
    },
    {
      id: "pull-request-workflow",
      title: "4. Pull Request (PR) Workflow",
      content: `1. **Discuss First (Issues/RFC)**: For major features or architectural changes, please open an Issue or Discussion first.
2. **Create a Feature Branch off \`dev\`**:
\`\`\`bash
git checkout dev
git pull upstream dev
git checkout -b feat/my-cool-feature
\`\`\`
3. **Commit Your Changes**: Follow Conventional Commits (\`feat:\`, \`fix:\`, \`docs:\`, \`refactor:\`, \`test:\`):
\`\`\`bash
git commit -m "feat(mempool): add orphan tx cleanup policy"
\`\`\`
4. **Include Tests**: Add unit tests in \`tests/\` or \`tsarcore_native/tests/\` for any new functionality.
5. **Open a Pull Request**: Submit your PR targeting the **\`dev\`** branch (\`Tsarstd/Graffiti-Protocol:dev\` $\\leftarrow$ \`your-username:feat/my-cool-feature\`).`
    },
    {
      id: "code-ownership",
      title: "5. Code Ownership & Guarded Files (CODEOWNERS)",
      alert: {
        type: "important",
        title: "PROTECTED PROTOCOL PATHS",
        text: "Files in .github/, tests/, tsarcore_native/tests/, src/tsarchain/consensus/, and src/kremlin/security/ are protected by CODEOWNERS. Any PR modifying these directories requires explicit review and approval from @Tsarstd."
      },
      content: `To protect protocol integrity, determinism, and security:

- Files in \`.github/\`, \`tests/\`, \`tsarcore_native/tests/\`, \`src/tsarchain/consensus/\`, and \`src/kremlin/security/\` are protected by \`CODEOWNERS\`.
- Any PR modifying these directories requires explicit review and approval from \`@Tsarstd\`.
- **Test Integrity Policy**: Do **not** modify or delete existing unit test assertions to force a failing feature to pass. PRs attempting to tamper with unit tests will be rejected. New tests should always be added.`
    },
    {
      id: "community-questions",
      title: "6. Community & Questions",
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
