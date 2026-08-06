# Contributing to Graffiti Protocol

Thank you for your interest in contributing to **Graffiti Protocol / TsarChain**! We welcome contributions from developers, researchers, and open-source enthusiasts.

To ensure a smooth collaboration process and maintain repository integrity, please review the following guidelines.

---

## 🛠️ Development Setup

Graffiti Protocol is a hybrid project written in **Rust** (performance core & cryptography) and **Python** (chain logic, node orchestrator, & wallet UI).

### Prerequisites
- **Python**: 3.11+ (Python 3.14 recommended for tests)
- **Rust**: Latest stable toolchain (`rustc`, `cargo`)
- **Maturin**: Build tool for Rust/Python bindings

### Local Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Tsarstd/Graffiti-Protocol.git
   cd Graffiti-Protocol
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies & build native Rust module:**
   ```bash
   pip install --upgrade pip maturin
   pip install ./tsarcore_native
   pip install -r requirements.txt
   pip install pytest pytest-mock
   ```

---

## 🧪 Running Unit Tests Locally

Before submitting a Pull Request, make sure all tests pass locally.

### 1. Run Rust Core Tests
```bash
cd tsarcore_native
cargo test
cd ..
```

### 2. Run Python Unit Tests
```bash
# On Linux / WSL:
xvfb-run -a env PYTHONPATH=src pytest

# On Windows (Powershell):
$env:PYTHONPATH="src"; pytest
```

---

## 🚀 Pull Request (PR) Workflow

1. **Fork the Repository**: Create your feature branch from `main` (`git checkout -b feature/my-cool-feature`).
2. **Commit Your Changes**: Keep commits atomic and descriptive (`git commit -m "feat(mempool): add orphan tx cleanup policy"`).
3. **Ensure Tests Pass**: Verify all Rust & Python unit tests pass locally.
4. **Open a Pull Request**: Submit your PR targeting `main`.

### 🛡️ Code Ownership & Guarded Files (`CODEOWNERS`)
To protect protocol integrity and security:
- Files in `.github/`, `tests/`, `tsarcore_native/tests/`, `src/tsarchain/consensus/`, and `src/kremlin/security/` are protected by **`CODEOWNERS`**.
- Any PR modifying these directories requires explicit review and approval from **`@Tsarstd`**.
- Do **not** modify unit tests to force a failing feature to pass. PRs attempting to tamper with unit tests will be flagged by CI.

---

## 💬 Community & Questions
If you have questions, architectural proposals, or feedback, feel free to open a [GitHub Discussion](https://github.com/Tsarstd/Graffiti-Protocol/discussions) or Issue.
