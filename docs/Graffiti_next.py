'''
### --- Next Implementation Steps (Dev Notes) --- 

    1. (DONE) menambahkan prefix di art_id, misal art_id sekarang 'c602d69f2999eebca522cf4479d852e66ea166271d11e0f30dd9a1a20e78b39f' tambahkan 4 karakter prfix didepan, 'graf' sehingga menjadi
       'grafc602d69f2999eebca522cf4479d852e66ea166271d11e0f30dd9a1a20e78' tetapi dipotong 4 karakter terakhir, sehingga tetap 64 karakter.
       - Implementasi: compute_art_id kini mengembalikan art_id dengan prefix graf (kompatibel legacy), parse/comment/derive_pool men-strip prefix secara otomatis.
       - Terverifikasi di block height 7 (post) dan 11 (comment).

	2. (DONE) archivist tidak dapat membaca file graffiti yang diterima di storagenya sendiri, tidak tampil di UI, padahal di storage sudah ada
       - Status: StorageServer kini punya handler STOR_PAID/GC sendiri; fallback node tidak lagi membuat folder data/storage (storage_rpc mengembalikan storage_disabled bila index tidak ada).
       - Index menambah field confirmed_at_height, expire_at_height, paid; expire hanya digunakan untuk file pending (tidak paid). cfg: GRAFFITI_EXPIRE_AFTER_BLOCKS=5.
       - Alur baru: STOR_COMMIT menaruh blob di storage/incoming (state=pending_confirm). STOR_PAID memindahkan ke storage/final, set paid=true, confirmed_at_height, expire_at_height=0 (tidak di-GC).
       - GC hanya menghapus entry yang expire_at_height tercapai dan paid==false (membersihkan incoming yang tidak pernah dibayar).
       - Archivist auto-mark paid: ketika melihat POST terkonfirmasi via GRAFFITI_GET_POSTS, ia memanggil STOR_PAID ke storage server lokal (block_height + txid), sehingga index ter-update dan file berpindah incoming→final tanpa manual.
       - Logging ditambah di StorageServer (STOR_INIT/COMMIT/PAID/GC) dan RPC connect untuk melacak alur.
       
    3. (DONE) Buat supaya wallet mencari informasi graffiti di 'Explore Tab' dengan menggunakan input art_id dengan prefix 'graf' , lalu menampilkan view graffiti dengan membaca file .jpg dari archivist node yang terhubung.
        dan sekaligus menampilkan comment yang ada di graffiti tersebut.
        
	4. (DONE) Retention Proof Scheduler: rancang worker storage node yang periodik menjalankan byte-range challenge sebelum pool balance dibagikan; log penalti jika bukti absen.
 
    5. (DONE) Mempool graffiti POST: modifikasi mempool agar menolak tx graffiti POST ganda per blok, sehingga graffiti tx tersebut bisa masuk ke blok berikutnya.
 
	6. (DONE) Storage Automation: definisikan template transaksi on-chain untuk payout pool (mis. script khusus) sehingga klaim bisa otomatis mengikuti aturan konsensus.
 
    7. (DONE) Perketat Ukuran & Jenis File Graffiti:
       - Batasi ukuran maksimum file graffiti yang dapat diunggah (GRAFFITI_MAX_SIZE di config.py 10MB) buat guard ini di sisi wallet & storage_node (Archivist).
       - Batasi jenis file yang diizinkan untuk graffiti (hanya JPEG,JPG & MP4) dengan memeriksa MIME type atau ekstensi file di wallet & storage_node.
       - Tambahkan validasi di wallet saat mengunggah graffiti dan di storage_node saat menerima file untuk memastikan hanya file yang sesuai yang diproses.
       - Buat supaya wallet mendukung view graffiti MP4 di 'Explore Tab' dengan menampilkan video dari archivist node yang terhubung.
       
    8. (DONE) Buat supaya storage node (archivist) juga bisa memakai storage LMDB saat backend diubah ke config.py KV_BACKEND = "lmdb" .
       - buat penyimpana untuk archivist di lmdb secara terpisah berdasarkan folder
       - data/storage/index.json  -> data/storage/index_db
       - data/storage/incoming/  -> data/storage/incoming_db
       - data/storage/final/     -> data/storage/final_db
       - buat 3 path baru di config.py untuk archivist lmdb storage di kategoti 3. FILESYSTEM LAYOUT ,misal:
         ARCHIVIST_INDEX_DB_PATH      = "data/storage/index_db"
         ARCHIVIST_INCOMING_DB_PATH   = "data/storage/incoming_db"
         ARCHIVIST_FINAL_DB_PATH      = "data/storage/final_db"
       - modul storage sudah tersedia (src/tsarchain/storage/kv) dan sudah terintegrasi dengan module native, tinggal terapkan saja
       - gunakan STORAGE_MAX_BYTES di config.py untuk membatasi ukuran maksimal lmdb archivist, dan STORAGE_SIZE_INIT untuk inisialisasi ukuran awal lmdb archivist
        
	9. (DONE) CLI Archivist Headless:
       - Buatkan varian CLI dari archivist_gui.py (GUI): apps/cli_archivist.py .
       - interaksi awal mirip seperti apps/cli_node_miner.py ( start cli -> input address -> connect )
       - setelah connect/start. langsung menunjukan tabel informasi storage di console, ketika ada data masuk, status paid, dll. termasuk informasi realtime (tip height, peers, dll) seperti di GUI
       - dan buat interaksi khusus untuk 1 aktivitas, yaitu ( Claim Pool Payout ), buat interaksi khusus untuk ini. tanpa mengentikan proses apps.
       - semua module project dan import sama seperti versi GUI, ini hanya membuat versi CLI saja. tanpa merubah sistem yang sudah bekerja
    
    10. Hapus fungsi 'Claim Pool Payout' dan buat fungsi ini khusus di jalur wallet saja kremlin.py.
       - Bantu hapus semua fungsi 'Claim Pool Payout' di sisi Archivist (cli_archivist.py & archivist_gui.py)
       - implementasikan saja fungsi ini di wallet,
 
'''
