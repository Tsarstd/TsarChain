export const DOC_CATEGORIES = [
  {
    id: "about",
    title: "About",
    description: "Foundational manifesto, cultural economics, and core Graffiti protocol specifications.",
    items: [
      {
        id: "grungepaper",
        title: "Grungepaper",
        subtitle: "The Voice Sovereignty Monetary System",
        category: "about",
        hasMultilingual: true,
        defaultLang: "en",
        badge: "Manifesto",
        summary: "A digital sovereignty monetary network for cultural memory and creativity. The founding manifesto of TsarChain.",
        keywords: ["grungepaper", "manifesto", "voice sovereignty", "sovereignty", "culture", "munir", "preservation"]
      },
      {
        id: "graffiti-protocol",
        title: "Graffiti Protocol",
        subtitle: "Draft Specification v0.1",
        category: "about",
        hasMultilingual: true,
        defaultLang: "en",
        badge: "Draft v0.1",
        summary: "Decentralized, uncensorable digital monuments anchored to RandomX block headers with fair creator royalties.",
        keywords: ["graffiti", "protocol", "draft", "royalty", "storage node", "archivist", "proof of retention", "comments"]
      }
    ]
  },
  {
    id: "guides",
    title: "Guides",
    description: "Operational deployment procedures, environment setup, and contribution guidelines.",
    items: [
      {
        id: "deployment",
        title: "Deployment",
        subtitle: "Network Deployment & Genesis Lock",
        category: "guides",
        hasMultilingual: false,
        badge: "Network",
        summary: "Step-by-step guide for bootstrapping a new TsarChain network, mining Genesis Block 0, and running nodes.",
        keywords: ["deployment", "genesis", "init-genesis", "bootstrap", "network", "node", "miner", "linux", "windows"]
      },
      {
        id: "install-native",
        title: "Install Native",
        subtitle: "tsarcore_native Acceleration Module",
        category: "guides",
        hasMultilingual: false,
        badge: "Rust / C++",
        summary: "Mandatory Rust + PyO3 native acceleration module build and setup instructions across Windows, macOS, and Linux.",
        keywords: ["install", "native", "rust", "pyo3", "maturin", "cmake", "randomx", "msvc", "build"]
      },
      {
        id: "contributing",
        title: "Contributing",
        subtitle: "Development Setup & Testing Workflow",
        category: "guides",
        hasMultilingual: false,
        badge: "Open Source",
        summary: "Guidelines for open-source contributors, setting up local virtual environments, and running Rust & Python unit tests.",
        keywords: ["contributing", "git", "tests", "pytest", "cargo test", "devnet", "pull request", "standards"]
      }
    ]
  },
  {
    id: "tsarchain",
    title: "Tsarchain",
    description: "Technical architecture, RPC sockets, performance benchmarks, and native core internals.",
    items: [
      {
        id: "architecture",
        title: "Architecture",
        subtitle: "Hybrid Consensus, Ledger & Storage",
        category: "tsarchain",
        hasMultilingual: false,
        badge: "Technical Core",
        summary: "Deep-dive into 1 Block = 1 Graffiti consensus, RandomX PoW, UTXO SegWit deltas, Archivist PoR, and LMDB data structures.",
        keywords: ["architecture", "consensus", "utxo", "coinbase", "mempool", "p2wsh", "p2wpkh", "data structure", "flowchart"]
      },
      {
        id: "api",
        title: "API & RPC",
        subtitle: "JSON-RPC over TCP Socket Protocol",
        category: "tsarchain",
        hasMultilingual: false,
        badge: "Socket RPC",
        summary: "API specification for USER, MINER, and STORAGE nodes communicating over raw TCP sockets with PoW challenges.",
        keywords: ["api", "rpc", "tcp", "socket", "ratelimit", "pow token", "get_balances", "create_tx", "explorer"]
      },
      {
        id: "performance",
        title: "Performance",
        subtitle: "Validation Benchmarks & Evidence",
        category: "tsarchain",
        hasMultilingual: false,
        badge: "Benchmarks",
        summary: "Empirical performance logs covering RandomX block validation (<25ms), sub-millisecond RPC, and wallet signing throughput.",
        keywords: ["performance", "benchmarks", "latency", "randomx", "ms", "hps", "throughput", "logs"]
      },
      {
        id: "references",
        title: "References",
        subtitle: "BIP Standards & Cryptographic Primitives",
        category: "tsarchain",
        hasMultilingual: false,
        badge: "Standards",
        summary: "Complete index of Bitcoin Improvement Proposals (BIPs 141, 143, 173, 39, 146), X3DH, Double Ratchet, and RFC specs.",
        keywords: ["references", "bip141", "bip143", "bip173", "bip39", "bip146", "x3dh", "double ratchet", "rfc"]
      },
      {
        id: "tsarcore-native",
        title: "tsarcore_native",
        subtitle: "Rust Engine, PyO3 & Storage Bindings",
        category: "tsarchain",
        hasMultilingual: false,
        badge: "Rust Crate",
        summary: "Low-level Rust crate exposing cryptographic primitives, parallel Rayon verification, zero-copy LMDB, and Merkle engines.",
        keywords: ["tsarcore_native", "rust", "pyo3", "lib.rs", "merkle", "secp256k1", "lmdb", "mining", "validation"]
      }
    ]
  }
];

export const ALL_DOCS = DOC_CATEGORIES.flatMap((category) => category.items);

export const getDocById = (id) => ALL_DOCS.find((item) => item.id === id) || ALL_DOCS[0];
