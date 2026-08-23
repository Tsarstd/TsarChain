export const references = {
  id: "references",
  title: "References & Standards",
  subtitle: "Bitcoin Improvement Proposals & Cryptographic Specifications",
  category: "Tsarchain",
  badge: "Standards",
  toc: [
    { id: "bips", label: "Bitcoin Improvement Proposals (BIPs)" },
    { id: "bitcoin-references", label: "Bitcoin Developer Reference" },
    { id: "algorithms-libraries", label: "Algorithms & Libraries" },
    { id: "secure-messaging", label: "Secure Messaging (Signal-style)" },
    { id: "cryptographic-primitives", label: "Cryptographic Primitives" },
  ],
  sections: [
    {
      id: "bips",
      title: "Bitcoin Improvement Proposals (BIPs)",
      links: [
        { title: "BIP-141", url: "https://bips.dev/141/", desc: "Segregated Witness (Consensus layer)" },
        { title: "BIP-143", url: "https://bips.dev/143/", desc: "Transaction Signature Verification for Version 0 Witness Program" },
        { title: "BIP-173", url: "https://bips.dev/173/", desc: "Bech32 address format for native SegWit outputs" },
        { title: "BIP-39", url: "https://bips.dev/39/", desc: "Mnemonic code for generating deterministic keys" },
        { title: "BIP-146", url: "https://bips.dev/146/", desc: "Dealing with signature encoding malleability (Low-S)" }
      ]
    },
    {
      id: "bitcoin-references",
      title: "Bitcoin Developer Reference",
      links: [
        { title: "Transactions: CompactSize", url: "https://developer.bitcoin.org/reference/transactions.html", desc: "Varint and transaction serialization standards" },
        { title: "Block Chain & Merkle Root", url: "https://developer.bitcoin.org/reference/block_chain.html", desc: "Block header hashing and Merkle tree validation" }
      ]
    },
    {
      id: "algorithms-libraries",
      title: "Algorithms & Libraries",
      links: [
        { title: "LWMA Difficulty Algorithm", url: "https://github.com/zawy12/difficulty-algorithms/issues/3", desc: "Linearly Weighted Moving Average for responsive PoW adjustment" },
        { title: "libsecp256k1", url: "https://github.com/bitcoin-core/secp256k1", desc: "Optimized C library for EC operations on curve secp256k1" },
        { title: "RandomX Reference", url: "https://github.com/tevador/RandomX", desc: "ASIC-resistant Proof of Work algorithm" }
      ]
    },
    {
      id: "secure-messaging",
      title: "Secure Messaging (Signal-style)",
      links: [
        { title: "The X3DH Protocol", url: "https://signal.org/docs/specifications/x3dh", desc: "Extended Triple Diffie-Hellman Key Agreement" },
        { title: "The Double Ratchet Algorithm", url: "https://signal.org/docs/specifications/doubleratchet", desc: "Continuous key ratcheting for end-to-end encrypted messaging" }
      ]
    },
    {
      id: "cryptographic-primitives",
      title: "Cryptographic Primitives",
      links: [
        { title: "RFC 7748", url: "https://www.rfc-editor.org/rfc/rfc7748", desc: "Elliptic Curves for Security (X25519/X448)" },
        { title: "RFC 5869", url: "https://www.rfc-editor.org/rfc/rfc5869", desc: "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)" },
        { title: "NIST SP 800-38D", url: "https://csrc.nist.gov/pubs/sp/800/38/d/final", desc: "Galois/Counter Mode (GCM) and GMAC" }
      ]
    }
  ]
};
