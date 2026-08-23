export const graffitiprotocolId = {
  download: {
    label: "Graffiti Protocol - Draft v0.1 (ID)",
    url: "https://drive.google.com/file/d/1nlNyPciI5Ba0HEHtmR1T-PBASyKowek1/view?usp=drive_link",
    filename: "Graffiti Protocol - Draft v0.1 (ID).pdf"
  },
  title: "Graffiti Protocol",
  subtitle: "Spesifikasi Draf Protokol v0.1",
  tagline: "Tanpa korporasi, Tanpa perantara, Tanpa buzzer — Bagikan senimu dan biarkan suaramu diingat",
  author: "Tsar Studio - 14 November 2025",
  contact: "tsar.studiodesign@gmail.com",
  toc: [
    { id: "manifesto", label: "Manifesto" },
    { id: "ide-inti", label: "1. Ide Inti" },
    { id: "peran-tanggung-jawab", label: "2. Peran & Tanggung Jawab" },
    { id: "alur-ekonomi", label: "3. Alur Ekonomi" },
    { id: "model-data", label: "4. Model Data & Pengenal" },
    { id: "layer-penyimpanan", label: "5. Layer Penyimpanan (Permanen)" },
    { id: "format-wire", label: "6. Format Wire (Petunjuk On-Chain)" },
    { id: "penyelesaian-pembayaran", label: "7. Penyelesaian & Pembayaran" },
    { id: "batasan-privasi", label: "8. Batasan, Penyalahgunaan, dan Privasi" },
    { id: "contoh-kasus", label: "9. Contoh Kasus" },
    { id: "parameter-protokol", label: "10. Parameter Protokol" },
    { id: "model-keamanan", label: "11. Model Keamanan & Postur Anti-Buzzer" },
    { id: "catatan", label: "12. Catatan & Status Pengembangan" },
  ],
  sections: [
    {
      id: "manifesto",
      title: "Manifesto",
      content: `GRAFFITI adalah protokol untuk seni yang lantang dan kebenaran yang lebih lantang. Ini bukan NFT, bukan saham, dan bukan kolaborasi merek.

Setiap karya adalah monumen digital yang diarsipkan secara permanen oleh Node Penyimpanan (Storage Nodes) TsarChain dan ditambatkan (anchored) ke sebuah blok. Komentar publik juga bersifat permanen: setelah disiarkan, komentar tersebut tidak dapat diedit atau dihapus secara diam-diam di tingkat protokol.

Alih-alih mengejar jumlah tayangan viral, GRAFFITI berfokus pada **"daya tahan, keterlacakan, dan imbalan yang adil bagi para kreator"**.

Tidak ada moderator pusat dengan tombol "ban". Jika seseorang ingin berbicara di sini, mereka berkontribusi pada biaya penyimpanan — dan artis mendapatkan bagiannya.

GRAFFITI adalah **"lapisan arsip pro kedaulatan digital"** dalam ekosistem TsarChain yang lebih luas: sebuah cara bagi komunitas untuk melestarikan budaya dan percakapan dari waktu ke waktu, sementara setiap operator node dan pengguna tetap bertanggung jawab untuk mematuhi hukum di yurisdiksi mereka sendiri.`
    },
    {
      id: "ide-inti",
      title: "1. Ide Inti",
      features: [
        {
          title: "Bukan NFT",
          desc: "Tidak ada kepemilikan yang dapat dipindahtangankan. GRAFFITI adalah arsip seni & suara, bukan spekulasi."
        },
        {
          title: "Jangkar Blok",
          desc: "Identitas sebuah karya mengikat hash kontennya dengan hash blok di mana transaksi pengunggahan (upload TX) disertakan."
        },
        {
          title: "Permanensi",
          desc: "File direplikasi oleh Node Penyimpanan; komitmen on-chain mereferensikan apa yang harus ada secara off-chain."
        },
        {
          title: "Komentar yang Tidak Dapat Diubah",
          desc: "Setiap komentar adalah peristiwa on-chain berbayar; teks komentar disimpan secara on-chain dalam batas byte yang aman."
        },
        {
          title: "Royalti Otomatis",
          desc: "80% dari setiap biaya komentar masuk ke kreator, 10% ke Storage Pool, dan ~10% ke penambang (miner) sebagai biaya."
        },
        {
          title: "Tanpa Moderator",
          desc: "Protokol bersifat netral. Penegakan lokal (jika ada) adalah pilihan operator node."
        }
      ]
    },
    {
      id: "peran-tanggung-jawab",
      title: "2. Peran & Tanggung Jawab",
      items: [
        { label: "Kreator (Artis)", text: "Mengunggah seni, membayar biaya unggah, menerima 80% royalti dari setiap komentar berbayar." },
        { label: "Warga (Citizen)", text: "Membayar untuk menambahkan komentar permanen pada karya; dapat menambahkan tip opsional." },
        { label: "Penambang (Miner)", text: "Memvalidasi dan menambang blok; mengumpulkan ~10% dari setiap komentar sebagai biaya transaksi." },
        { label: "Node Penyimpanan (Archivist)", text: "Menyimpan salinan replikasi (R) secara permanen. Menghasilkan 10% dari komentar ditambah bagian dari dana abadi (endowment) pengunggahan." },
        { label: "Pengindeks / Penjelajah", text: "Mengindeks peristiwa GRAFFITI dan merender karya serta utas komentar." }
      ]
    },
    {
      id: "alur-ekonomi",
      title: "3. Alur Ekonomi",
      content: `Protokol menegakkan pembagian pendapatan yang dikunci secara matematis tanpa perantara:

- **3.1 Biaya Unggah**: Kreator membayar berdasarkan ukuran file: \`UPLOAD_FEE\` dengan \`MIN_BILLABLE_SIZE\` (Ukuran ≥ 100KB). Alokasi default: 100% ke dana abadi (endowment) Storage Pool karya tersebut untuk mendanai retensi jangka panjang.
- **3.2 Biaya Komentar**: Setiap komentar menyertakan \`comment_amount\` (≥ \`COMMENT_FEE_MIN\`).
  - **80%** → Alamat kreator (royalti).
  - **10%** → Storage Pool karya tersebut (pembayaran mikro untuk replika).
  - **~10%** → Penambang sebagai biaya (dicapai dengan membuat total output 90% dari input).
- **3.3 Tip**: \`tip_amount\` opsional masuk 100% ke kreator.`
    },
    {
      id: "model-data",
      title: "4. Model Data & Pengenal",
      content: `Objek Seni:


- Hash File: \`Hc = SHA256(file_blob)\`
- Jangkar Blok: \`Hb = Hash blok di mana transaksi upload dikonfirmasi\`
- Kreator: \`addr_c\` (P2WPKH)
- Art ID: \`art_id = SHA256("GRAFFITI" || Hc || Hb || addr_c)\`

Objek Komentar:


- Panjang Maksimum: \`COMMENT_MAX_BYTES\` (280 Byte)
- ID Komentar: \`comment_id = SHA256(art_id || txid || vout_index)\`
- Teks Komentar: Disimpan on-chain (UTF-8 hex) melalui kolom payload \`OP_RETURN\`.`
    },
    {
      id: "layer-penyimpanan",
      title: "5. Layer Penyimpanan (Permanen)",
      content: `- **Faktor Replikasi R**: Default 5 replika menggunakan consistent hashing pada cincin node yang dikunci oleh \`art_id\`.
- **Alamat Storage Pool**: Alamat skrip P2WSH deterministik per art_id: \`pool_addr = GRF_POOL(art_id)\`.
- **Bukti Retensi (Proof of Retention)**: Setiap \`EPOCH_BLOCKS\`, setiap node penyimpanan membuktikan kepemilikan melalui tantangan rentang byte acak. Saldo aktif dibagi di antara provers yang berhasil.
- **Dana Abadi (Endowment)**: Jika tidak ada komentar baru, biaya unggah awal bertindak sebagai dana abadi untuk pembayaran berkala.`
    },
    {
      id: "format-wire",
      title: "6. Format Wire (Petunjuk On-Chain)",
      code: `GRF_MAGIC = 0x47524631 ("GRF1")
Acara: POST, COMMENT, PAYOUT

// Payload POST:
{ magic: GRF_MAGIC, event: "POST", Hc, size_kb, mime, addr_c, R_hint, meta_short }
Outputs: [ pool_addr (upload endowment) ]

// Payload COMMENT:
{ magic: GRF_MAGIC, event: "COMMENT", art_id, comment_utf8_hex }
Outputs: [ 80% -> addr_c, 10% -> pool_addr ]; 10% biaya miner via delta input-output.`
    },
    {
      id: "penyelesaian-pembayaran",
      title: "7. Penyelesaian & Pembayaran",
      content: `- **Pada POST**: Biaya unggah bergerak ke \`pool_addr\`. Dana dibuka secara bertahap per \`EPOCH_BLOCKS\` untuk node yang lulus bukti retensi.
- **Pada COMMENT**: Pembagian 80% / 10% / 10% ditegakkan secara on-chain; tidak ada distributor terpusat.
- **Penalti**: Node yang gagal dalam K epoch berturut-turut untuk sebuah karya tidak menerima pembayaran untuk epoch tersebut.`
    },
    {
      id: "batasan-privasi",
      title: "8. Batasan, Penyalahgunaan, dan Privasi",
      content: `- **Ukuran Komentar**: Dibatasi oleh \`COMMENT_MAX_BYTES\` (280B); UTF-8 dihitung berdasarkan bytes (termasuk emoji).
- **Wallet Rate Limit**: Cooldown UI opsional per alamat per karya untuk mengurangi banjir spam.
- **Pseudonimitas**: Komentar berasal dari alamat pengguna; izinkan alamat baru per komentar untuk privasi yang lebih baik.
- **Konten Ilegal**: Protokol bersifat netral; penyimpanan bersifat sukarela dan non-kustodial. Operator node dapat menetapkan kebijakan lokal.`
    },
    {
      id: "contoh-kasus",
      title: "9. Contoh Kasus",
      content: `**Skenario**:


Kreator mengunggah gambar **720KB** → Ditagihkan 800KB.
   \`UPLOAD_FEE\` (0.8 TSAR) × 8 = **6.4 TSAR** biaya unggah masuk ke \`pool_addr\`.


Pengguna mengirim **Komentar A (2 TSAR)**:
   - **1.6 TSAR** → Alamat kreator
   - **0.2 TSAR** → \`pool_addr\`
   - **0.2 TSAR** → Biaya penambang (miner fee)


Pengguna mengirim **Komentar B (2 TSAR + 5 TSAR Tip)**:
   - **1.6 TSAR** (royalti) + **5.0 TSAR** (tip) = **6.6 TSAR** → Kreator
   - **0.2 TSAR** → \`pool_addr\`
   - **0.2 TSAR** → Biaya penambang


Pembayaran Epoch : Node penyimpanan yang lulus verifikasi bukti Merkle mengklaim pembayaran dari saldo \`pool_addr\`.`
    },
    {
      id: "parameter-protokol",
      title: "10. Parameter Protokol (config.py)",
      table: {
        headers: ["Parameter", "Default (v0.1)", "Deskripsi"],
        rows: [
          ["UPLOAD_FEE", "0.8 TSAR", "Biaya unggah per 100KB (dibulatkan ke atas)"],
          ["MIN_BILLABLE_SIZE", "100 KB", "Ukuran potongan minimal yang dapat ditagih"],
          ["REPLICATION_R", "5", "Faktor replikasi permanen"],
          ["EPOCH_BLOCKS", "720", "Epoch audit retensi (~1 hari @2m/blok)"],
          ["COMMENT_MAX_BYTES", "280 Bytes", "Maksimum byte komentar on-chain"],
          ["COMMENT_FEE_MIN", "1.0 TSAR", "Biaya komentar minimum"],
          ["ROYALTY_CREATOR", "0.80 (80%)", "Bagian royalti kreator"],
          ["SHARE_STORAGE", "0.10 (10%)", "Bagian storage pool"],
          ["SHARE_MINER_FEE", "~0.10 (10%)", "Biaya miner melalui delta I/O"]
        ]
      }
    },
    {
      id: "model-keamanan",
      title: "11. Model Keamanan & Postur Anti-Buzzer",
      content: `- **Ketahanan Sybil Storage**: Dimitigasi oleh bukti retensi per epoch dengan tantangan rentang byte acak & verifikasi Merkle.
- **Banjir Komentar**: Friksi ekonomi melalui \`COMMENT_FEE_MIN\` (1 TSAR) + cooldown dompet.
- **Tanpa Penjaga Gerbang**: Protokol tidak memiliki koordinator takedown terpusat; penyimpanan bersifat sukarela dan tahan sensor.
- **Buzzer**: Harus membayar untuk bersuara, sehingga artis dan arsip tetap didanai.`
    },
    {
      id: "catatan",
      title: "12. Catatan & Status Pengembangan",
      content: `Kami menghormati ide-ide sulit dan percakapan jujur, bukan bahaya. Estetikanya adalah underground secara desain: self-custody (hak asuh mandiri), tanpa penjaga gerbang (gatekeepers), tanda terima on-chain.

TsarChain dan GRAFFITI berada di dalam visi yang lebih luas:
- Sebuah **"sistem pelestarian digital untuk warisan budaya dan kreativitas"**.
- Sebuah jaringan **"pro kedaulatan digital"** di mana kreator memegang kendali lebih besar atas bagaimana karya mereka disimpan dan ditemukan.
- Sebuah *proyek eksperimental, independen, dan digerakkan oleh komunitas.*

*Ini adalah draf awal.*
*Protokol Graffiti masih dalam tahap pengembangan.*
*Draf ini dapat diubah seiring waktu, tetapi gagasan awalnya akan tetap konsisten.*`
    }
  ]
};
