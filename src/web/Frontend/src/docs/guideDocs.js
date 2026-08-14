export const GUIDE_DOCS = {
  deployment: {
    id: "deployment",
    title: "Deployment & Genesis Guide",
    subtitle: "Network Deployment, Genesis Lock & Node Operations",
    category: "Guides",
    badge: "Network",
    toc: [
      { id: "environment-setup", label: "1. Environment Setup" },
      { id: "network-genesis-setup", label: "2. Network Genesis Setup (--init-genesis)" },
      { id: "running-nodes-network", label: "3. Running Nodes & Joining Network" },
      { id: "production-checkpoints", label: "4. Production Checkpoints" },
      { id: "maintenance-reset", label: "5. Maintenance & Resetting Testnets" },
    ],
    sections: [
      {
        id: "environment-setup",
        title: "1. Environment Setup",
        content: `Before running any node or miner, ensure all dependencies (**Rust, CMake, Python 3.12, Node.js, and Native Extensions**) are installed using the automated bootstrap scripts:`,
        codeTabs: [
          {
            lang: "bash",
            label: "Linux / macOS (Bash)",
            code: `# 1. Run automated setup script
./setup.sh

# 2. Activate virtual environment
source activate_env.sh`
          },
          {
            lang: "powershell",
            label: "Windows (PowerShell)",
            code: `# 1. Run automated setup script
.\\setup.ps1

# 2. Activate virtual environment (Note the leading dot for dot-sourcing)
. .\\activate_env.ps1`
          }
        ]
      },
      {
        id: "network-genesis-setup",
        title: "2. Network Genesis Setup (--init-genesis)",
        alert: {
          type: "important",
          title: "GENESIS LOCK POLICY",
          text: "In TsarChain, Block 0 (Genesis Block) is mined once by the first Bootstrap Node. Once mined, Block 0 is stored directly in the local LMDB database (data/node), which acts as the immutable Genesis Lock. Automatic genesis creation is 100% disabled by default on normal startup and must be explicitly triggered via --init-genesis."
        },
        steps: [
          {
            step: "01",
            title: "Run the Genesis Initialization Command",
            subtitle: "Bootstrap Server Initializer",
            desc: "Run the `--init-genesis` command on the initial bootstrap server. The interactive CLI prompt will ask for your miner reward address and desired CPU cores for mining.",
            command: {
              code: "python apps/cli_node_miner.py --init-genesis",
              title: "Genesis Initialization",
              comment: "# Step 1: Input your reward address (create address in Kremlin wallet first)\n# Step 2: Tune CPU cores (recommended 2 CPU cores for Genesis Block 0)"
            }
          },
          {
            step: "02",
            title: "CLI Mines Block 0 & Locks State in LMDB",
            subtitle: "Automated Genesis Verification",
            desc: "The CLI will compute the RandomX PoW for Block 0, commit it to LMDB, print the network summary, and exit cleanly:",
            terminalOutput: {
              title: "CLI Output — Genesis Block 0 Locked",
              status: "LMDB Lock Active",
              output: `==> Mining Genesis Block (Block 0) for address 'tsar1qakf...' with 2 core(s)...
================================================================
Genesis Block created & locked in LMDB successfully!
Hash      : 000fbaf94a24b16f5c0713b6b3513b758652e927e616bb52ecae31d214625759
Height    : 0
PrevHash  : 0000000000000000000000000000000000000000000000000000000000000000
Nonce     : 109
Timestamp : Sun Jul 26 20:40:57 2026
================================================================
Environment ready! You can now start the node or miner in normal mode.`
            }
          },
          {
            step: "03",
            title: "Re-run Protection Mechanism",
            subtitle: "Idempotent Safety Guard",
            desc: "If `--init-genesis` is executed again on an existing database, the CLI detects the LMDB Genesis Lock, displays the existing Genesis Hash, and exits safely without corrupting or re-mining the blockchain.",
            note: "Safe for automated deployment pipelines: existing LMDB state is preserved automatically."
          },
          {
            step: "04",
            title: "Launch the Archivist Node (Storage Node)",
            subtitle: "Decentralized Graffiti Replicas",
            desc: "Run the Archivist node in a separate CLI / terminal environment. You must run this node for the Graffiti permanent preservation feature in TsarChain. Otherwise, the network will only accept standard UTXO transfers without off-chain media archiving.",
            command: {
              code: "python apps/cli_archivist.py",
              title: "Start Storage Node",
              comment: "# Replicates cultural art archives, listens for P2P chunks, and submits PoR proofs"
            }
          }
        ]
      },
      {
        id: "running-nodes-network",
        title: "3. Running Nodes & Joining the Network",
        content: `After the Genesis Block is initialized on the bootstrap node, other nodes and miners can join the network:`,
        features: [
          {
            title: "A. Regular Miner Mode (Bootstrap or Peer Miner)",
            desc: "To start mining Block 1 and subsequent blocks on the network:\n\n`python apps/cli_node_miner.py`\n\nRuns full P2P validation, connects to peers, and computes RandomX Proof-of-Work."
          },
          {
            title: "B. Full Node-Only Mode (Relay / RPC Server)",
            desc: "To run an always-on full validator node without mining overhead:\n\n`python apps/cli_node_miner.py --node-only`\n\nIdeal for explorer backends, wallet API gateways, and RPC servers."
          },
          {
            title: "C. Joining as a Peer Node (New Machine)",
            desc: "New machines joining an existing network DO NOT run `--init-genesis`. Simply start:\n\n`python apps/cli_node_miner.py` (choose '0 mining mode').\n\nThe node connects to the bootstrap peer, downloads Block 0 over P2P sync, and stores it into its local LMDB database automatically."
          }
        ]
      },
      {
        id: "production-checkpoints",
        title: "4. Production Checkpoints (Optional)",
        content: `For official production or testnet releases, the committed Genesis Hash can optionally be hardcoded in \`src/tsarchain/utils/config.py\`:

\`\`\`python
# src/tsarchain/utils/config.py
GENESIS_HASH_HEX = "000fbaf94a24b16f5c0713b6b3513b758652e927e616bb52ecae31d214625759"
\`\`\`

When \`GENESIS_HASH_HEX\` is set:
- Incoming P2P blocks and snapshot downloads (\`bootstrap.py\`) will validate against this hardcoded hash checkpoint.
- If \`GENESIS_HASH_HEX = ""\` (default), node integrity relies on the local LMDB Genesis state.`
      },
      {
        id: "maintenance-reset",
        title: "5. Maintenance & Resetting Testnets",
        content: `If you need to wipe local chain data to restart a private testnet:

1. Stop all running nodes, miners, and storage nodes.
2. Remove the local data directory:
\`\`\`bash
rm -rf data
\`\`\`
3. Re-initialize Genesis on the bootstrap node using \`--init-genesis\`.`
      }
    ]
  },

  "install-native": {
    id: "install-native",
    title: "Install Native Module",
    subtitle: "tsarcore_native Rust + PyO3 Acceleration Module",
    category: "Guides",
    badge: "Rust / C++",
    toc: [
      { id: "consensus-note", label: "Consensus Note: Single Native Path" },
      { id: "prerequisites", label: "1. Prerequisites" },
      { id: "installation-options", label: "2. Installation Options" },
      { id: "building-from-source", label: "3. Building from Source (maturin)" },
      { id: "verifying-installation", label: "4. Verifying Installation" },
      { id: "troubleshooting", label: "5. Troubleshooting" },
    ],
    sections: [
      {
        id: "consensus-note",
        title: "Consensus Note: Single Native Path",
        alert: {
          type: "warning",
          title: "MANDATORY NATIVE MODULE",
          text: "For deterministic consensus across platforms/architectures, every node runs the exact same Rust implementation shipped in tsarcore_native for operations such as merkle_root, sighash_bip143, sigops counting, and block validation. Python fallback implementations have been removed to eliminate consensus divergence."
        },
        content: `\`tsarcore_native\` is the Rust + PyO3 native acceleration module for **TsarChain**. TsarChain requires this module for all consensus-critical and high-throughput cryptographic operations.`
      },
      {
        id: "prerequisites",
        title: "1. Prerequisites",
        items: [
          { label: "Python", text: "3.10 – 3.14 (64-bit)" },
          { label: "Rust Toolchain", text: "Latest stable via rustup (rustc, cargo)" },
          { label: "Maturin", text: "Build tool: pip install maturin" },
          { label: "CMake", text: "CMake 3.24+ (required for compiling vendored RandomX C++ sources)" }
        ],
        content: `**Platform Notes:**
- **Windows**: Install Visual Studio Build Tools (C++ workload). Rust target must be **MSVC** (default).
- **macOS**: \`xcode-select --install\` for Command Line Tools. Apple Silicon (ARM64) and Intel (x86_64) are fully supported.
- **Linux (Debian/Ubuntu)**: \`sudo apt update && sudo apt install -y build-essential python3-dev cmake\`.`
      },
      {
        id: "installation-options",
        title: "2. Installation Options",
        codeTabs: [
          {
            lang: "bash",
            label: "Option A: pip install",
            code: `# Navigate to repository root
cd Graffiti-Protocol

# Install directly via pip/maturin
pip install ./tsarcore_native`
          },
          {
            lang: "bash",
            label: "Option B: maturin develop",
            code: `# Develop mode (creates bindings directly in virtual environment)
cd tsarcore_native
maturin develop --release`
          }
        ]
      },
      {
        id: "building-from-source",
        title: "3. Building from Source (maturin)",
        content: `To build a standalone wheel or compile release binaries:

\`\`\`bash
cd tsarcore_native
maturin build --release
pip install target/wheels/tsarcore_native*.whl --force-reinstall
\`\`\``
      },
      {
        id: "verifying-installation",
        title: "4. Verifying Installation",
        content: `Run a quick Python verification snippet to assert that the native C/Rust bindings are functioning:

\`\`\`python
import tsarcore_native as tc

# 1. Test SHA256 double hash
digest = tc.hash256(b"TsarChain Voice Sovereignty")
print(f"Hash256: {digest.hex()}")

# 2. Test SigOps counter
assert tc.count_sigops(b"\\xac") == 1  # OP_CHECKSIG

# 3. Test RandomX light verification hash
seed = b"test-seed-epoch-0"
header80 = b"\\x00" * 80
rx_hash = tc.randomx_pow_hash(header80, seed, full_mem=False)
print(f"RandomX Hash: {rx_hash.hex()}")
print("All native bindings verified successfully!")
\`\`\``
      },
      {
        id: "troubleshooting",
        title: "5. Troubleshooting",
        content: `- **Architecture Mismatch**: Ensure Python (e.g. 64-bit) matches your Rust target.
- **CMake Not Found**: Ensure CMake is on your system \`PATH\` and version is 3.24+.
- **MSVC Error on Windows**: Install the C++ Desktop Development workload from Visual Studio Installer.`
      }
    ]
  },

  contributing: {
    id: "contributing",
    title: "Contributing to Graffiti Protocol",
    subtitle: "Development Guidelines & Testing Workflow",
    category: "Guides",
    badge: "Open Source",
    toc: [
      { id: "development-setup", label: "1. Development Setup" },
      { id: "running-unit-tests", label: "2. Running Unit Tests Locally" },
      { id: "code-style-standards", label: "3. Code Style & Standards" },
      { id: "git-pull-requests", label: "4. Pull Request Workflow" },
    ],
    sections: [
      {
        id: "development-setup",
        title: "1. Development Setup",
        content: `Graffiti Protocol is a hybrid project written in **Rust** (performance core & cryptography) and **Python** (chain logic, node orchestrator, & wallet UI).

\`\`\`bash
# 1. Clone the repository
git clone https://github.com/Tsarstd/Graffiti-Protocol.git
cd Graffiti-Protocol

# 2. Create virtual environment
python -m venv .venv

# Windows:
.venv\\Scripts\\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Install dependencies & build native module
pip install --upgrade pip maturin
pip install ./tsarcore_native
pip install -r requirements.txt
pip install pytest pytest-mock
\`\`\``
      },
      {
        id: "running-unit-tests",
        title: "2. Running Unit Tests Locally",
        content: `Before submitting a Pull Request, ensure that all test suites pass cleanly:`,
        codeTabs: [
          {
            lang: "bash",
            label: "1. Rust Core Unit Tests",
            code: `cd tsarcore_native
cargo test
cd ..`
          },
          {
            lang: "bash",
            label: "2. Python Core & Consensus Tests",
            code: `pytest tests/ -v`
          },
          {
            lang: "bash",
            label: "3. Frontend Explorer Tests",
            code: `cd src/web/Frontend
npm run build
cd ../../..`
          }
        ]
      },
      {
        id: "code-style-standards",
        title: "3. Code Style & Standards",
        items: [
          { label: "Rust Formatting", text: "Run `cargo fmt` and ensure `cargo clippy -- -D warnings` passes without errors." },
          { label: "Python Style", text: "Follow PEP 8, utilize type annotations, and maintain clear modular boundaries." },
          { label: "Deterministic Consensus", text: "Never introduce platform-dependent floating point arithmetic or non-deterministic hash iteration into consensus validation." },
          { label: "Documentation", text: "Keep docstrings updated and add markdown documentation for new RPC categories or protocol parameters." }
        ]
      },
      {
        id: "git-pull-requests",
        title: "4. Pull Request Workflow",
        content: `1. Fork the repository and create your feature branch: \`git checkout -b feature/amazing-feature\`.
2. Commit your changes with clear, descriptive commit messages.
3. Push to your fork: \`git push origin feature/amazing-feature\`.
4. Open a Pull Request on GitHub against the \`main\` branch. Provide a concise summary of changes and validation logs.`
      }
    ]
  }
};
