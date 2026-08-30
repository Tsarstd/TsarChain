import time
from web.Backend.src.core import build_receipt

def coinbase_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': 'ba4f5aab0fddbce27b18ba118c1080a5005892s28175e632e68db9d7ac72cac7',
        'status': 'confirmed',
        'confirmations': 19,
        'height': 26,
        'timestamp': 1768028055,
        'is_coinbase': True,
        'inputs': [],
        'outputs': [
            {
                'index': 0,
                'amount': 25000000000,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr',
                'event': None
            }
        ],
        'total_in': None,
        'total_out': 25000000000,
        'fee': None,
        'bonus': None
    }
    
def coinbase_tx_bonus():
    return {
        'type': 'TX_DETAIL',
        'txid': 'ba4f5aab0fddbce27b18ba118c1080a0b45892s28175e632e68db9d7ac72cac7',
        'status': 'confirmed',
        'confirmations': 19,
        'height': 26,
        'timestamp': 1768028055,
        'is_coinbase': True,
        'inputs': [],
        'outputs': [
            {
                'index': 0,
                'amount': 25000004355,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr',
                'event': None
            }
        ],
        'total_in': None,
        'total_out': 25000004355,
        'fee': None,
        'bonus': 4355
    }

def common_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': 'cc58288f37bd1db37d9be5379e5b4e14ed2a05cd108884d33be6c39ae94da5fa',
        'status': 'confirmed',
        'confirmations': 36,
        'height': 9,
        'timestamp': 1768027367,
        'is_coinbase': False,
        'inputs': [
            {
                'prev_txid': 'ba778d4557a35492f3f74ac05d712453c19a48a8e1506de323d60161a1af18e5',
                'prev_index': 0,
                'amount': 25000000000,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'
            },
            {
                'prev_txid': '1e713230b725b98a12de69ba9340ca436ce4f63b2f9ebebfc407602807ce46c8',
                'prev_index': 0,
                'amount': 25000000000,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'
            },
            {
                'prev_txid': '4556f8cdd501c0499086b8b3ac47a955137f1e0222a60cb28d20e323821f9671',
                'prev_index': 1,
                'amount': 248874999988304,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'
            }
        ],
        'outputs': [
            {
                'index': 0,
                'amount': 1200000000000,
                'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq',
                'event': None
            },
            {
                'index': 1,
                'amount': 247724999978920,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr',
                'event': None
            }
        ],
        'total_in': 248924999988304,
        'total_out': 248924999978920,
        'fee': 9384,
        'bonus': 42228
    }
    
def mempool_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': '7a089abfd56e34c9dae581f900a415592f32d0f670877140c5171d4a1575268b',
        'status': 'unconfirmed',
        'confirmations': None,
        'height': None,
        'timestamp': 0,
        'is_coinbase': False,
        'inputs': [
            {'prev_txid': '7d4ad2d11eac10aa002d5ad93fd7ba468683b1872b7cd46fbb812d8eaae295e2', 'prev_index': 1, 'amount': 14109981504, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'e56e2a40d668eba495c127988aaf268cff2a27c160d37bb88639a17b3f9375fd', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '0a68eeba92b36512d0bc92d8e37c0fed73fff82d7f1766235defbc31406d65b3', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '9f9f3ddd2d265ce9cce5369486f767fefec89f33f58341d765b172723dbeb5e3', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '33a56f3c937a0d3d04c8105b5ba3dc44defafe4b991b03870a5876289ea398d2', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'a15f48e03e460cf68092faa28cfdd229d310562d7d0886098aedccf743ea9ab8', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'ef6a23616dc8d629d09527138b85ac434666e28b9634db3e414bd7b5de7d58f3', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '84c16e8e8ae4c913d0b63aa08da53a1bb2f3e4d90fd15af7fb3ca6cc1166ff4b', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'b26ac05a6f3b309a2f0e6d55394b8fd624eb8ac71b9bfe5761c244cf2d11b34f', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'ba4f5aab0fddbce27b18ba118c1080a0b458920c8175e632e68db9d7ac72cac7', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '10239358d9d6c73139643b4a0f97b04adbefea6e6818b9f5eea5cc202ba75112', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '49775a31c80a36e4e37390876401b260034bd3adc14bcab50ee7458feb654959', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'e6f12dfd636fb7e6ca42acf58e7322048d90e7dc457d00806f83c64afbb56791', 'prev_index': 0, 'amount': 25000000000, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'e3976197753affb1b28a66510843ad6939b7bc9d5e6f0473286dd21f7f73db2e', 'prev_index': 0, 'amount': 25000005814, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '6e7254a87c447259cbb1b65efa467d2ac02bf7e2eab7b90e233473b994eea83c', 'prev_index': 0, 'amount': 25000005814, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '189075e54dc55b73b3822db37207ab510c5563c4087be5f92ba02c94aa7e2924', 'prev_index': 0, 'amount': 25000005814, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '8bd89d0bdcec4efaeeaae8a01b024062b1818cf92c16700258a5283cfa14fb15', 'prev_index': 0, 'amount': 25000005814, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'eb42ded67c359f603517876f7d8235e44af0b8a7aa3f00fbff162c88a67682f4', 'prev_index': 0, 'amount': 25000006868, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '38409d3164d3e340d3715f1f583d92c7eb6d18dd4daa57b6d8235f688247f66a', 'prev_index': 0, 'amount': 25000009384, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '9669bdb26edcf42548caeb42aebb79864675da9b017318d93200caaebba05464', 'prev_index': 0, 'amount': 25000011492, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'be244ca4382efbdae189e36ccec2a7eff1833fb73a4f00e0a76cc6c1e4f238ec', 'prev_index': 0, 'amount': 25000011696, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'df22850d0ba299fbef4171d68e55932815357edf853a4873ff079f2f4e32e45b', 'prev_index': 0, 'amount': 25000014994, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '25c0aa344a7c228b2e320693aa1e572bbf9fb63b1832b58fe6715ff835e59ab8', 'prev_index': 0, 'amount': 25000021012, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '5de986e3ca6c038fcffdcf0e13d016cbe45d008349689a57690ae9e7a04eae24', 'prev_index': 0, 'amount': 25000021080, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'c4ea9844f751a91d5e03a36b274f4220aebc6f0e4983a8c27a681532fcdc48fe', 'prev_index': 0, 'amount': 25000021216, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '2749a1fc5f519a54721178cbd53cd4b0d76aa24487a126fd2ddf9bae918b432a', 'prev_index': 0, 'amount': 25000026894, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '6df9cf19cfd56dd481d7db8113e651ce859a438e9c6ccf362a773ee168b2f3ee', 'prev_index': 0, 'amount': 25000028016, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '678a5531bb73b96fd4ea778642616be59e20d6e0f0f36511fec36f96eb1c310c', 'prev_index': 0, 'amount': 25000042126, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': 'aba15716791dfc3a026e74458f7e624161fb078b5218662e8b4ddaec241b39e5', 'prev_index': 0, 'amount': 25000063274, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'},
            {'prev_txid': '496c1dc1a8b36c44e64e79cea4e6c76d60c89a2f928ce0c6923342d939f59555', 'prev_index': 1, 'amount': 246599999978920, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'}
        ],
        'outputs': [
            {'index': 0, 'amount': 2360000000000, 'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq', 'event': None},
            {'index': 1, 'amount': 244954110189924, 'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr', 'event': None}
        ],
        'total_in': 247314110261732,
        'total_out': 247314110189924,
        'fee': 71808,
        'bonus': 42228
    }

def post_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': '7d4ad2d11eac10aa002d5ad93fd7ba468683b1872b7cd46fbb812d8eaae295e2',
        'status': 'confirmed',
        'confirmations': 4,
        'height': 41,
        'timestamp': 1768028771,
        'is_coinbase': False,
        'inputs': [
            {
                'prev_txid': 'b634720217fcf82023c9dafd18e1735ef64e8f6154b8ae53dda37c539b4713bb',
                'prev_index': 1,
                'amount': 24749987318,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr'
            }
        ],
        'outputs': [
            {
                'index': 0,
                'amount': 10640000000,
                'address': 'tsar1qhxm6436vjz952t5d8nr27w9ykc25qrt55xj3de5zt8trtfkgx0pqzq9vkp',
                'event': None
            },
            {
                'index': 1,
                'amount': 14109981504,
                'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr',
                'event': None
            },
            {
                'index': 2,
                'amount': 0,
                'address': None,
                'event': 'POST'
            }
        ],
        'total_in': 24749987318,
        'total_out': 24749981504,
        'fee': 5814,
        'bonus': 42228
    }

def comment_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': '94deca7a94cd031243106a192f2ba6fce22f25dd88728e552aaefcdd06ba011b',
        'status': 'confirmed',
        'confirmations': 18,
        'height': 27,
        'timestamp': 1768028061,
        'is_coinbase': False,
        'inputs': [
            {
                'prev_txid': '5ba19b8cd18e493e68b561a35cae35bdf7a2540eba0dbed258a4054d35700cd2',
                'prev_index': 0,
                'amount': 80000000,
                'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq'
            },
            {
                'prev_txid': 'ff36b8571fb73e1c92bdfbdcf39e22c75e11ee33b45ac4013b621f63d9afcb6c',
                'prev_index': 0,
                'amount': 180000000,
                'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq'
            },
            {
                'prev_txid': '2b3af7967c1bacd869cff60e451f908673b3268a8a2035d003c32283519c4a93',
                'prev_index': 1,
                'amount': 1184639994186,
                'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq'
            }
        ],
        'outputs': [
            {
                'index': 0,
                'amount': 280000000,
                'address': 'tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss',
                'event': None
            },
            {
                'index': 1,
                'amount': 10000000,
                'address': 'tsar1q4q3dd0qnas2lv3mjpf5jcvjdl8f54yude0ek88w4880m0fujxn8s7m3gwp',
                'event': None
            },
            {
                'index': 2,
                'amount': 1184609982694,
                'address': 'tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq',
                'event': None
            },
            {
                'index': 3,
                'amount': 0,
                'address': None,
                'event': 'COMMENT'
            }
        ],
        'total_in': 1184899994186,
        'total_out': 1184899982694,
        'fee': 11492,
        'bonus': 42228
    }

def payout_tx():
    return {
        'type': 'TX_DETAIL',
        'txid': 'a846597d906f19f646cfb6a207c24ca5f1994658d6d6da84561426a62e46598e',
        'status': 'confirmed',
        'confirmations': 10,
        'height': 35,
        'timestamp': 1768028295,
        'is_coinbase': False,
        'inputs': [
            {
                'prev_txid': '94deca7a94cd031243106a192f2ba6fce22f25dd88728e552aaefcdd06ba011b',
                'prev_index': 1,
                'amount': 10000000,
                'address': 'tsar1q4q3dd0qnas2lv3mjpf5jcvjdl8f54yude0ek88w4880m0fujxn8s7m3gwp'
            }
        ],
        'outputs': [
            {
                'index': 0,
                'amount': 9978954,
                'address': 'tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07',
                'event': None
            },
            {
                'index': 1,
                'amount': 0,
                'address': None,
                'event': 'PAYOUT'
            }
        ],
        'total_in': 10000000,
        'total_out': 9978954,
        'fee': 21046,
        'bonus': 42228
    }

def rpc_receipt():
    output_dir = "data/web/receipts"
    receipt_gen = build_receipt.PaymentReceiptGenerator(output_dir)
    
    benchmarks = {}
    start_total = time.perf_counter()
        
    t0 = time.perf_counter()
    tx_common = common_tx()
    receipt_gen.generate_receipt_base64(tx_common)
    benchmarks['TX Common'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_mempool = mempool_tx()
    receipt_gen.generate_receipt_base64(tx_mempool)
    benchmarks['TX Mempool'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_comment = comment_tx()
    receipt_gen.generate_receipt_base64(tx_comment)
    benchmarks['TX Comment'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_post = post_tx()
    receipt_gen.generate_receipt_base64(tx_post)
    benchmarks['TX Post'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_payout = payout_tx()
    receipt_gen.generate_receipt_base64(tx_payout)
    benchmarks['TX Payouts'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_coinbase = coinbase_tx()
    receipt_gen.generate_receipt_base64(tx_coinbase)
    benchmarks['TX Coinbase'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    t0 = time.perf_counter()
    tx_coinbase_bonus = coinbase_tx_bonus()
    receipt_gen.generate_receipt_base64(tx_coinbase_bonus)
    benchmarks['TX Coinbase Bonus'] = round((time.perf_counter() - t0) * 1000.0, 3)
    
    total_time = round((time.perf_counter() - start_total) * 1000.0, 3)
    
    print("\nBenchmarks Results :")
    for name, bench_time in benchmarks.items():
        print(f"- {name} : {bench_time}ms")
    print(f"With Total Benchmarks = {total_time}ms")
            
    return total_time

if __name__ == "__main__":
    test_dir = rpc_receipt()