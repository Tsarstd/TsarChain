import time
from web.Backend.src.core import build_history_book


def history_test():
    return {
        "address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "spendable": 244954110189924,
        "immature": 0,
        "outgoing": 2360000071808,
        "incoming": 0,
        "balance": 247314110261732,
        "utxo_count": 30,
        "history": [
            {
            "txid": "7a089abfd56e34c9dae581f900a415592f32d0f670877140c5171d4a1575268b",
            "direction": "out",
            "amount": 2360000071808,
            "status": "unconfirmed",
            "confirmations": 0,
            "height": None, #mempool (unconfirmed)
            "to": "tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq",
            "timestamp": 1768910523
            },
            {
            "txid": "7d4ad2d11eac10aa002d5ad93fd7ba468683b1872b7cd46fbb812d8eaae295e2",
            "direction": "out",
            "amount": 10640005814,
            "status": "confirmed",
            "confirmations": 4,
            "height": 41,
            "to": "tsar1qhxm6436vjz952t5d8nr27w9ykc25qrt55xj3de5zt8trtfkgx0pqzq9vkp",
            "timestamp": 1768028771
            },
            {
            "txid": "9f9f3ddd2d265ce9cce5369486f767fefec89f33f58341d765b172723dbeb5e3",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 8,
            "height": 37,
            "from": "coinbase",
            "timestamp": 1768028317
            },
            {
            "txid": "b26ac05a6f3b309a2f0e6d55394b8fd624eb8ac71b9bfe5761c244cf2d11b34f",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 9,
            "height": 36,
            "from": "coinbase",
            "timestamp": 1768028313
            },
            {
            "txid": "678a5531bb73b96fd4ea778642616be59e20d6e0f0f36511fec36f96eb1c310c",
            "direction": "in",
            "amount": 25000042126,
            "status": "confirmed",
            "confirmations": 10,
            "height": 35,
            "from": "coinbase",
            "timestamp": 1768028295
            },
            {
            "txid": "84c16e8e8ae4c913d0b63aa08da53a1bb2f3e4d90fd15af7fb3ca6cc1166ff4b",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 11,
            "height": 34,
            "from": "coinbase",
            "timestamp": 1768028244
            },
            {
            "txid": "e6f12dfd636fb7e6ca42acf58e7322048d90e7dc457d00806f83c64afbb56791",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 12,
            "height": 33,
            "from": "coinbase",
            "timestamp": 1768028230
            },
            {
            "txid": "0a68eeba92b36512d0bc92d8e37c0fed73fff82d7f1766235defbc31406d65b3",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 13,
            "height": 32,
            "from": "coinbase",
            "timestamp": 1768028211
            },
            {
            "txid": "ef6a23616dc8d629d09527138b85ac434666e28b9634db3e414bd7b5de7d58f3",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 14,
            "height": 31,
            "from": "coinbase",
            "timestamp": 1768028192
            },
            {
            "txid": "10239358d9d6c73139643b4a0f97b04adbefea6e6818b9f5eea5cc202ba75112",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 15,
            "height": 30,
            "from": "coinbase",
            "timestamp": 1768028128
            },
            {
            "txid": "aba15716791dfc3a026e74458f7e624161fb078b5218662e8b4ddaec241b39e5",
            "direction": "in",
            "amount": 25000063274,
            "status": "confirmed",
            "confirmations": 16,
            "height": 29,
            "from": "coinbase",
            "timestamp": 1768028095
            },
            {
            "txid": "25c0aa344a7c228b2e320693aa1e572bbf9fb63b1832b58fe6715ff835e59ab8",
            "direction": "in",
            "amount": 25000021012,
            "status": "confirmed",
            "confirmations": 17,
            "height": 28,
            "from": "coinbase",
            "timestamp": 1768028079
            },
            {
            "txid": "9669bdb26edcf42548caeb42aebb79864675da9b017318d93200caaebba05464",
            "direction": "in",
            "amount": 25000011492,
            "status": "confirmed",
            "confirmations": 18,
            "height": 27,
            "from": "coinbase",
            "timestamp": 1768028061
            },
            {
            "txid": "ba4f5aab0fddbce27b18ba118c1080a0b458920c8175e632e68db9d7ac72cac7",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 19,
            "height": 26,
            "from": "coinbase",
            "timestamp": 1768028055
            },
            {
            "txid": "e3976197753affb1b28a66510843ad6939b7bc9d5e6f0473286dd21f7f73db2e",
            "direction": "in",
            "amount": 25000005814,
            "status": "confirmed",
            "confirmations": 20,
            "height": 25,
            "from": "coinbase",
            "timestamp": 1768028049
            },
            {
            "txid": "189075e54dc55b73b3822db37207ab510c5563c4087be5f92ba02c94aa7e2924",
            "direction": "in",
            "amount": 25000005814,
            "status": "confirmed",
            "confirmations": 21,
            "height": 24,
            "from": "coinbase",
            "timestamp": 1768028038
            },
            {
            "txid": "b634720217fcf82023c9dafd18e1735ef64e8f6154b8ae53dda37c539b4713bb",
            "direction": "out",
            "amount": 160005814,
            "status": "confirmed",
            "confirmations": 21,
            "height": 24,
            "to": "tsar1q85e8qha36wlxvcscqfyu0wu8466dfk7vs7fhq8wzesq6728ejqsq3pqatn",
            "timestamp": 1768028038
            },
            {
            "txid": "df22850d0ba299fbef4171d68e55932815357edf853a4873ff079f2f4e32e45b",
            "direction": "in",
            "amount": 25000014994,
            "status": "confirmed",
            "confirmations": 22,
            "height": 23,
            "from": "coinbase",
            "timestamp": 1768028003
            },
            {
            "txid": "5de986e3ca6c038fcffdcf0e13d016cbe45d008349689a57690ae9e7a04eae24",
            "direction": "in",
            "amount": 25000021080,
            "status": "confirmed",
            "confirmations": 23,
            "height": 22,
            "from": "coinbase",
            "timestamp": 1768027762
            },
            {
            "txid": "eb42ded67c359f603517876f7d8235e44af0b8a7aa3f00fbff162c88a67682f4",
            "direction": "in",
            "amount": 25000006868,
            "status": "confirmed",
            "confirmations": 24,
            "height": 21,
            "from": "coinbase",
            "timestamp": 1768027722
            },
            {
            "txid": "5ba19b8cd18e493e68b561a35cae35bdf7a2540eba0dbed258a4054d35700cd2",
            "direction": "out",
            "amount": 90006868,
            "status": "confirmed",
            "confirmations": 24,
            "height": 21,
            "to": "tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq",
            "timestamp": 1768027722
            },
            {
            "txid": "6df9cf19cfd56dd481d7db8113e651ce859a438e9c6ccf362a773ee168b2f3ee",
            "direction": "in",
            "amount": 25000028016,
            "status": "confirmed",
            "confirmations": 25,
            "height": 20,
            "from": "coinbase",
            "timestamp": 1768027709
            },
            {
            "txid": "e56e2a40d668eba495c127988aaf268cff2a27c160d37bb88639a17b3f9375fd",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 26,
            "height": 19,
            "from": "coinbase",
            "timestamp": 1768027641
            },
            {
            "txid": "c4ea9844f751a91d5e03a36b274f4220aebc6f0e4983a8c27a681532fcdc48fe",
            "direction": "in",
            "amount": 25000021216,
            "status": "confirmed",
            "confirmations": 27,
            "height": 18,
            "from": "coinbase",
            "timestamp": 1768027630
            },
            {
            "txid": "33a56f3c937a0d3d04c8105b5ba3dc44defafe4b991b03870a5876289ea398d2",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 28,
            "height": 17,
            "from": "coinbase",
            "timestamp": 1768027606
            },
            {
            "txid": "2749a1fc5f519a54721178cbd53cd4b0d76aa24487a126fd2ddf9bae918b432a",
            "direction": "in",
            "amount": 25000026894,
            "status": "confirmed",
            "confirmations": 29,
            "height": 16,
            "from": "coinbase",
            "timestamp": 1768027589
            },
            {
            "txid": "a15f48e03e460cf68092faa28cfdd229d310562d7d0886098aedccf743ea9ab8",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 30,
            "height": 15,
            "from": "coinbase",
            "timestamp": 1768027559
            },
            {
            "txid": "8bd89d0bdcec4efaeeaae8a01b024062b1818cf92c16700258a5283cfa14fb15",
            "direction": "in",
            "amount": 25000005814,
            "status": "confirmed",
            "confirmations": 31,
            "height": 14,
            "from": "coinbase",
            "timestamp": 1768027538
            },
            {
            "txid": "6e7254a87c447259cbb1b65efa467d2ac02bf7e2eab7b90e233473b994eea83c",
            "direction": "in",
            "amount": 25000005814,
            "status": "confirmed",
            "confirmations": 32,
            "height": 13,
            "from": "coinbase",
            "timestamp": 1768027501
            },
            {
            "txid": "be244ca4382efbdae189e36ccec2a7eff1833fb73a4f00e0a76cc6c1e4f238ec",
            "direction": "in",
            "amount": 25000011696,
            "status": "confirmed",
            "confirmations": 33,
            "height": 12,
            "from": "coinbase",
            "timestamp": 1768027455
            },
            {
            "txid": "496c1dc1a8b36c44e64e79cea4e6c76d60c89a2f928ce0c6923342d939f59555",
            "direction": "out",
            "amount": 1200000011696,
            "status": "confirmed",
            "confirmations": 33,
            "height": 12,
            "to": "tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss",
            "timestamp": 1768027455
            },
            {
            "txid": "bafafdd04f751b4d399bd2457b605ee24ee9a6b7076bab9fb073f41ff2c805ad",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 34,
            "height": 11,
            "from": "coinbase",
            "timestamp": 1768027386
            },
            {
            "txid": "49775a31c80a36e4e37390876401b260034bd3adc14bcab50ee7458feb654959",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 35,
            "height": 10,
            "from": "coinbase",
            "timestamp": 1768027378
            },
            {
            "txid": "38409d3164d3e340d3715f1f583d92c7eb6d18dd4daa57b6d8235f688247f66a",
            "direction": "in",
            "amount": 25000009384,
            "status": "confirmed",
            "confirmations": 36,
            "height": 9,
            "from": "coinbase",
            "timestamp": 1768027367
            },
            {
            "txid": "cc58288f37bd1db37d9be5379e5b4e14ed2a05cd108884d33be6c39ae94da5fa",
            "direction": "out",
            "amount": 1200000009384,
            "status": "confirmed",
            "confirmations": 36,
            "height": 9,
            "to": "tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq",
            "timestamp": 1768027367
            },
            {
            "txid": "73de35ee78f3a3366952d02f2a35ab0c2f9d71428e6cd00eab7c50e7ac313b4d",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 37,
            "height": 8,
            "from": "coinbase",
            "timestamp": 1768027341
            },
            {
            "txid": "c59b0f658faec08c3e1c4e66eb167b8a050274aeb8c9bbfddc1c1c4d41b4b5ff",
            "direction": "in",
            "amount": 25000011696,
            "status": "confirmed",
            "confirmations": 38,
            "height": 7,
            "from": "coinbase",
            "timestamp": 1768027206
            },
            {
            "txid": "4556f8cdd501c0499086b8b3ac47a955137f1e0222a60cb28d20e323821f9671",
            "direction": "out",
            "amount": 1200000011696,
            "status": "confirmed",
            "confirmations": 38,
            "height": 7,
            "to": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23",
            "timestamp": 1768027206
            },
            {
            "txid": "628fab7ce8584357df27b368e8b6ce34eb4ca10a027fd0141b004535dc59e4f7",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 39,
            "height": 6,
            "from": "coinbase",
            "timestamp": 1768027157
            },
            {
            "txid": "1e713230b725b98a12de69ba9340ca436ce4f63b2f9ebebfc407602807ce46c8",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 40,
            "height": 5,
            "from": "coinbase",
            "timestamp": 1768027150
            },
            {
            "txid": "ba778d4557a35492f3f74ac05d712453c19a48a8e1506de323d60161a1af18e5",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 41,
            "height": 4,
            "from": "coinbase",
            "timestamp": 1768027117
            },
            {
            "txid": "d1b39e6bdfd57b9b1a4c7298207d7e4fbd53db3550abd35fbbb0161c89792e98",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 42,
            "height": 3,
            "from": "coinbase",
            "timestamp": 1768027075
            },
            {
            "txid": "ced0ad59f63372708469de9650ce1c04bcc34c42949b942494fbbefc575efe5c",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 43,
            "height": 2,
            "from": "coinbase",
            "timestamp": 1768027008
            },
            {
            "txid": "8d218acd7c02ba31a192e7b956aa9f8ea346e8bce25a2281f409fba33fa7956c",
            "direction": "in",
            "amount": 25000000000,
            "status": "confirmed",
            "confirmations": 44,
            "height": 1,
            "from": "coinbase",
            "timestamp": 1768026995
            },
            {
            "txid": "48a8a5daaaddad645dc4ec8557740101410c82b49abd37f530a71720642ff75d",
            "direction": "in",
            "amount": 250000000000000,
            "status": "confirmed",
            "confirmations": 45,
            "height": 0, #genesis
            "from": "coinbase",
            "timestamp": 1768026966
            },
            
        ],
        "height": 44, #tip block height on network
        "total_txs": 45
    }


def rpc_history_book():
    output_dir = "data/web/history_books"
    generator = build_history_book.HistoryBookGenerator(output_dir)
    
    benchmarks = {}
    start_total = time.perf_counter()
    tx_data = history_test()
    generator.generate_history_book_base64(tx_data)
    
    total_time = round((time.perf_counter() - start_total) * 1000.0, 3)
    
    for name, bench_time in benchmarks.items():
        print(f"- {name} : {bench_time}ms")
    print(f"Total Benchmarks (45 TXs) = {total_time}ms")
            
    return total_time

if __name__ == "__main__":
    rpc_history_book()
