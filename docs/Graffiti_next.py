'''
NOTE: aktivitas upload graffiti tervalidasi di block height 8, dan comment di block height 12
NOTE: untuk mendalami struktur data, bisa cek di :

    - data/Contracts/graffiti.json - untuk metadata graffiti
    - data/Block/blockchain.json - untuk melihat block yang sudah mengandung graffiti
    - data/storage/index.json - untuk melihat index graffiti yang sudah tersimpan di storage node (archivist)


### --- Next Implementation Steps (Dev Notes) --- 

    # DONE 1. Anchoring hash salah, harusnya yang di achoring ke block_id adalah (art_id) bukan hash dari file graffiti itu sendiri, biarkan hash file di metadata dan indexer archivist saja

    2. di wallet, bisa menampilakn graffiti art (.jpeg) di explorer tab dengan pencarian art_id , melalui permintaan  archivist
    
	3. archivist tidak dapat membaca file graffiti yang diterima di storagenya sendiri, tidak tampil di UI, padahal di storage sudah ada

	4. Retention Proof Scheduler: rancang worker storage node yang periodik menjalankan byte-range challenge sebelum pool balance dibagikan; log penalti jika bukti absen.
 
	5. Storage Automation: definisikan template transaksi on-chain untuk payout pool (mis. script khusus) sehingga klaim bisa otomatis mengikuti aturan konsensus.
 
 '''