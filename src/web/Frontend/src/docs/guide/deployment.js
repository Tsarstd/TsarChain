export const deployment = {
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

- Stop all running nodes, miners, and storage nodes.
- Remove the local data directory:
\`\`\`bash
rm -rf data
\`\`\`
- Re-initialize Genesis on the bootstrap node using \`--init-genesis\`.`
    }
  ]
};
