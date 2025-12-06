'''
    NOTE: aktivitas upload graffiti tervalidasi di block height 8 dan comment di block height 10, Retention Proof Scheduler sudah terimplementasi, silahkan cek data (data/storage/index.json | archivist) & (data/Contracts/graffiti.json | node)
    NOTE: untuk mendalami struktur data, bisa cek di :
    - data/Block/blockchain.json - untuk melihat block yang sudah mengandung graffiti
    - data/Contracts/graffiti.json - untuk metadata graffiti
    - data/storage/index.json - untuk melihat index graffiti yang sudah tersimpan di storage node (archivist)


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
 
    7. Perketat Ukuran & Jenis File Graffiti:
       - Batasi ukuran maksimum file graffiti yang dapat diunggah (GRAFFITI_MAX_SIZE di config.py 10MB) buat guard ini di sisi wallet & storage_node (Archivist).
       - Batasi jenis file yang diizinkan untuk graffiti (hanya JPEG,JPG & MP4) dengan memeriksa MIME type atau ekstensi file di wallet & storage_node.
       - Tambahkan validasi di wallet saat mengunggah graffiti dan di storage_node saat menerima file untuk memastikan hanya file yang sesuai yang diproses.
       - Buat supaya wallet mendukung view graffiti MP4 di 'Explore Tab' dengan menampilkan video dari archivist node yang terhubung.
 
	8. CLI Archivist Headless:
       - Buatkan 2 varian CLI dari archivist.py (GUI): apps/archivist_node.py (storage publik/VPS) dan apps/archivist_client.py (cache-only CGNAT).
       - Next: tambahkan fetch file & cache untuk client (STOR_GET_BY_ART), dan proof-of-retention worker + jalur payout bagi partisipan non-publik.
       - Dokumentasi argumen CLI & contoh run di README/INSTALL.
       - Opsional: monitoring/logging ringkas (metrics) dan opsi auto-discovery storer.
 
'''
