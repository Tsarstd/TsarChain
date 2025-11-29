'''
NOTE: aktivitas upload graffiti tervalidasi di block height 7, dan comment di block height 11
NOTE: untuk mendalami struktur data, bisa cek di :

    - data/Contracts/graffiti.json - untuk metadata graffiti
    - data/Block/blockchain.json - untuk melihat block yang sudah mengandung graffiti
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

	3. Retention Proof Scheduler: rancang worker storage node yang periodik menjalankan byte-range challenge sebelum pool balance dibagikan; log penalti jika bukti absen.
 
	4. Storage Automation: definisikan template transaksi on-chain untuk payout pool (mis. script khusus) sehingga klaim bisa otomatis mengikuti aturan konsensus.
 
 '''
