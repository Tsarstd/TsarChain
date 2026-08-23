# Contributing to Graffiti Protocol

Thank you for your interest in contributing to **Graffiti Protocol / TsarChain**! We welcome contributions from developers, researchers, and open-source enthusiasts.

To maintain repository integrity, code quality, and security, please review the following guidelines before submitting your contributions.

---

## 🌳 Branching Strategy

Our repository uses a dual-branch model:

- **`main` (Protected)**: Represents stable, production-ready releases.
  > **Note**: Direct commits and Pull Requests to `main` are restricted to Code Owners (`@Tsarstd`). Any external PR opened against `main` will be automatically requested to re-target `dev`.
- **`dev` (Default for Contributions)**: The active development and staging branch where new features, refactors, and bugfixes are integrated.
  > **All external Pull Requests must target the `dev` branch.**

---

## 🛠️ Development Setup

Graffiti Protocol is a hybrid system built with **Rust** (performance core, cryptography, and PoW algorithm) and **Python** (chain logic, node orchestrator, RPC, and wallet UI).

### Prerequisites
- **Python**: 3.11+
- **Rust**: Latest stable toolchain (`rustup`, `rustc`, `cargo`)
- **Maturin**: Build tool for PyO3 Rust/Python bindings
- **Node.js** (Optional): 18+ (only if contributing to `src/web/Frontend`)

### Local Environment Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/Graffiti-Protocol.git
   cd Graffiti-Protocol
   ```

2. **Set up the upstream remote and checkout `dev`:**
   ```bash
   git remote add upstream https://github.com/Tsarstd/Graffiti-Protocol.git
   git fetch upstream
   git checkout -b dev upstream/dev
   ```

3. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv .venv

   # On Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1

   # On Linux / macOS:
   source .venv/bin/activate
   ```

4. **Install dependencies & build Rust native extension:**
   ```bash
   pip install --upgrade pip maturin
   pip install -r requirements.txt
   pip install pytest pytest-mock
   ```

   > 💡 **Tip for Rust development:** Use `maturin develop` inside `tsarcore_native` to automatically compile and install the native extension into your active virtual environment:
   > ```bash
   > cd tsarcore_native
   > maturin develop
   > cd ..
   > ```

---

## 🧪 Testing & Verification

Before opening a Pull Request, verify that all unit tests pass locally.

### 1. Run Rust Core Unit Tests
```bash
cd tsarcore_native
cargo test
cd ..
```

### 2. Run Python Unit Tests
- **Linux / macOS / WSL (headless X server for GUI/Wallet tests):**
  ```bash
  xvfb-run -a env PYTHONPATH=src pytest
  ```
- **Windows (PowerShell):**
  ```powershell
  $env:PYTHONPATH="src"; pytest
  ```

### 3. Code Formatting & Linting
Ensure your code adheres to standard conventions:
- **Rust**:
  ```bash
  cd tsarcore_native
  cargo fmt --check
  cargo clippy
  cd ..
  ```
- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/) style standards.

---

## 🚀 Step-by-Step Contribution Workflow

1. **Discuss First (RFC / Issues)**:
   For major architectural changes, consensus logic updates, or new cryptographic features, please [open an Issue](https://github.com/Tsarstd/Graffiti-Protocol/issues) or [start a Discussion](https://github.com/Tsarstd/Graffiti-Protocol/discussions) before implementing to ensure alignment with the project roadmap.

2. **Create a Feature Branch off `dev`**:
   Always branch off the latest `dev` branch:
   ```bash
   git checkout dev
   git pull upstream dev
   git checkout -b feat/your-feature-name
   ```
   *Branch naming conventions:*
   - `feat/feature-name` for new features
   - `fix/bug-description` for bug fixes
   - `docs/topic-name` for documentation updates
   - `refactor/scope` for code refactoring

3. **Commit Your Changes**:
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat(mempool): implement orphan transaction eviction policy"
   git commit -m "fix(wallet): resolve balance calculation discrepancy on sync"
   ```

4. **Write and Update Tests**:
   - Whenever you add a new feature or fix a bug, include corresponding unit tests in `tests/` or `tsarcore_native/tests/`.
   - Ensure all existing and new tests pass cleanly.

5. **Push and Open a Pull Request**:
   - Push your branch to your fork:
     ```bash
     git push origin feat/your-feature-name
     ```
   - Open a Pull Request on GitHub.
   - **Target branch MUST be `dev`** (e.g., `Tsarstd/Graffiti-Protocol:dev` $\leftarrow$ `your-username:feat/your-feature-name`).
   - Fill out the PR description with context, rationale, and testing steps.

---

## 🛡️ Code Ownership & Guarded Files (`CODEOWNERS`)

To protect protocol security, consensus stability, and consensus determinism:
- Core directories (`src/tsarchain/consensus/`, `src/kremlin/security/`, `tsarcore_native/`, `.github/`, and `tests/`) are guarded by **`CODEOWNERS`**.
- Modifications to these critical paths require explicit review and approval from **`@Tsarstd`**.
- **Test Integrity Policy**: Modifying or deleting existing unit test assertions to force a failing feature to pass is strictly prohibited and will be flagged during PR review. Always add new tests or adjust implementation to meet existing protocol constraints.

---

## 💬 Community & Support

Have questions, suggestions, or need help getting started?
- [GitHub Discussions](https://github.com/Tsarstd/Graffiti-Protocol/discussions) — Architecture proposals, Q&A, and ideas.
- [GitHub Issues](https://github.com/Tsarstd/Graffiti-Protocol/issues) — Bug reports and feature requests.
- [Security Policy](SECURITY.md) — For reporting responsible disclosure of security vulnerabilities.
