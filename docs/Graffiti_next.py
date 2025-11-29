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

	2. archivist tidak dapat membaca file graffiti yang diterima di storagenya sendiri, tidak tampil di UI, padahal di storage sudah ada
       - Status: sebagian. Archivist sudah memanggil STOR_INDEX/PAID/GC; node sudah memberi handler fallback sehingga RPC tidak error.
       - TODO: tambahkan STOR_PAID/GC di storage_node/server.py agar index storage yang asli ikut terupdate tanpa membuat folder baru di node non-storage.
       - TODO: mengubah status "paid": false, menjadi "paid": true, di index.json . saat graffiti tersebut sudah divalidasi di block node memberitahu storage node (archivist) untuk mengupdate status paid di index.json

	3. Retention Proof Scheduler: rancang worker storage node yang periodik menjalankan byte-range challenge sebelum pool balance dibagikan; log penalti jika bukti absen.
 
	4. Storage Automation: definisikan template transaksi on-chain untuk payout pool (mis. script khusus) sehingga klaim bisa otomatis mengikuti aturan konsensus.
 
 '''
