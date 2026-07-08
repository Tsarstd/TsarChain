// SPDX-License-Identifier: MIT
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};
use std::sync::Once;
use tsarcore_native::utxo::utxo_build_ops_compact;

static INIT: Once = Once::new();
fn init_python() {
    INIT.call_once(|| {
        pyo3::Python::initialize();
    });
}

fn to_tuple<'py>(py: Python<'py>, list: &Bound<'py, PyList>) -> Bound<'py, PyTuple> {
    let builtins = py.import("builtins").unwrap();
    builtins.call_method1("tuple", (list,)).unwrap().cast_into::<PyTuple>().unwrap()
}

#[test]
fn test_utxo_build_ops_basic() {
    init_python();
    Python::attach(|py| {
        let block_txs = PyList::empty(py);

        // 1. Coinbase TX (no inputs deleted, insert output)
        let txid1 = [0x11u8; 32];
        let txid1_py = PyBytes::new(py, &txid1);
        let spk1 = b"script1";
        let out1 = PyList::empty(py);
        out1.append(5000000000u64).unwrap();
        out1.append(PyBytes::new(py, spk1)).unwrap();
        let outputs1 = PyList::empty(py);
        outputs1.append(to_tuple(py, &out1)).unwrap();

        let inputs1 = PyList::empty(py);
        
        let tx1_list = PyList::empty(py);
        tx1_list.append(1i32).unwrap();
        tx1_list.append(0u32).unwrap();
        tx1_list.append(inputs1).unwrap();
        tx1_list.append(outputs1).unwrap();
        tx1_list.append(txid1_py).unwrap();
        tx1_list.append(true).unwrap(); // is_coinbase = true
        let tx1 = to_tuple(py, &tx1_list);
        block_txs.append(tx1).unwrap();

        // 2. Normal TX (spends previous output, creates new output + OP_RETURN)
        let prev_txid = [0x22u8; 32];
        let prev_txid_py = PyBytes::new(py, &prev_txid);
        
        let inp_list = PyList::empty(py);
        inp_list.append(prev_txid_py).unwrap();
        inp_list.append(1u32).unwrap(); // vout = 1
        inp_list.append(0u32).unwrap(); // sequence
        inp_list.append(PyList::empty(py)).unwrap(); // witness
        let inputs2 = PyList::empty(py);
        inputs2.append(to_tuple(py, &inp_list)).unwrap();

        let txid2 = [0x33u8; 32];
        let txid2_py = PyBytes::new(py, &txid2);
        
        let out2_1 = PyList::empty(py);
        out2_1.append(1000u64).unwrap();
        out2_1.append(PyBytes::new(py, b"script2")).unwrap();
        
        let out2_2 = PyList::empty(py); // OP_RETURN output
        out2_2.append(0u64).unwrap();
        let mut op_return_script = vec![0x6a]; // OP_RETURN
        op_return_script.extend_from_slice(b"data");
        out2_2.append(PyBytes::new(py, &op_return_script)).unwrap();

        let outputs2 = PyList::empty(py);
        outputs2.append(to_tuple(py, &out2_1)).unwrap();
        outputs2.append(to_tuple(py, &out2_2)).unwrap();

        let tx2_list = PyList::empty(py);
        tx2_list.append(1i32).unwrap();
        tx2_list.append(0u32).unwrap();
        tx2_list.append(inputs2).unwrap();
        tx2_list.append(outputs2).unwrap();
        tx2_list.append(txid2_py).unwrap();
        tx2_list.append(false).unwrap(); // is_coinbase = false
        let tx2 = to_tuple(py, &tx2_list);
        block_txs.append(tx2).unwrap();

        let ops = utxo_build_ops_compact(py, &block_txs, 100).unwrap();
        
        assert_eq!(ops.len(), 3); // 1 insert from tx1, 1 delete from tx2, 1 insert from tx2 (OP_RETURN skipped)

        // Verify TX1 insert
        let op0 = ops.get_item(0).unwrap().cast_into::<PyTuple>().unwrap();
        let key0: String = op0.get_item(0).unwrap().extract().unwrap();
        assert_eq!(key0, format!("{}:0", hex::encode(txid1)));
        assert_eq!(op0.get_item(1).unwrap().extract::<u64>().unwrap(), 5000000000);
        assert_eq!(op0.get_item(3).unwrap().extract::<bool>().unwrap(), true); // is_coinbase
        assert_eq!(op0.get_item(4).unwrap().extract::<i64>().unwrap(), 100); // height

        // Verify TX2 delete
        let op1 = ops.get_item(1).unwrap().cast_into::<PyTuple>().unwrap();
        let key1: String = op1.get_item(0).unwrap().extract().unwrap();
        assert_eq!(key1, format!("{}:1", hex::encode(prev_txid)));
        assert!(op1.get_item(1).unwrap().is_none()); // amount is None

        // Verify TX2 insert
        let op2 = ops.get_item(2).unwrap().cast_into::<PyTuple>().unwrap();
        let key2: String = op2.get_item(0).unwrap().extract().unwrap();
        assert_eq!(key2, format!("{}:0", hex::encode(txid2)));
        assert_eq!(op2.get_item(1).unwrap().extract::<u64>().unwrap(), 1000);
        assert_eq!(op2.get_item(3).unwrap().extract::<bool>().unwrap(), false); // is_coinbase
    });
}

fn build_tx<'py>(py: Python<'py>, tx_mod: &dyn Fn(&Bound<'py, PyList>)) -> Bound<'py, PyList> {
    let tx_list = PyList::empty(py);
    tx_list.append(1i32).unwrap();
    tx_list.append(0u32).unwrap();
    
    let inp_list = PyList::empty(py);
    inp_list.append(PyBytes::new(py, &[0x22u8; 32])).unwrap();
    inp_list.append(1u32).unwrap();
    let inputs = PyList::empty(py);
    inputs.append(to_tuple(py, &inp_list)).unwrap();
    tx_list.append(inputs).unwrap();
    
    let out_list = PyList::empty(py);
    out_list.append(100u64).unwrap();
    out_list.append(PyBytes::new(py, b"")).unwrap();
    let outputs = PyList::empty(py);
    outputs.append(to_tuple(py, &out_list)).unwrap();
    tx_list.append(outputs).unwrap();
    
    tx_list.append(PyBytes::new(py, &[0x33u8; 32])).unwrap();
    tx_list.append(false).unwrap();
    
    tx_mod(&tx_list);
    
    let blocks = PyList::empty(py);
    blocks.append(to_tuple(py, &tx_list)).unwrap();
    blocks
}

#[test]
fn test_utxo_errors() {
    init_python();
    Python::attach(|py| {

        // 1. tx_tuple_arity
        let blocks1 = build_tx(py, &|list| { list.del_item(5).unwrap(); });
        let res = utxo_build_ops_compact(py, &blocks1, 100);
        assert_eq!(res.unwrap_err().to_string(), "ValueError: tx_tuple_arity");

        // 2. tx_txid_length
        let blocks2 = build_tx(py, &|list| { list.set_item(4, PyBytes::new(py, &[0u8; 31])).unwrap(); });
        assert_eq!(utxo_build_ops_compact(py, &blocks2, 100).unwrap_err().to_string(), "ValueError: tx_txid_length");

        // 3. tx_input_tuple_arity
        let blocks3 = build_tx(py, &|list| {
            let inputs = list.get_item(2).unwrap().cast_into::<PyList>().unwrap();
            let inp_tuple = inputs.get_item(0).unwrap().cast_into::<PyTuple>().unwrap();
            let new_inp = PyList::empty(py);
            new_inp.append(inp_tuple.get_item(0).unwrap()).unwrap(); // length 1
            inputs.set_item(0, to_tuple(py, &new_inp)).unwrap();
        });
        assert_eq!(utxo_build_ops_compact(py, &blocks3, 100).unwrap_err().to_string(), "ValueError: tx_input_tuple_arity");

        // 4. tx_input_txid_length
        let blocks4 = build_tx(py, &|list| {
            let inputs = list.get_item(2).unwrap().cast_into::<PyList>().unwrap();
            let new_inp = PyList::empty(py);
            new_inp.append(PyBytes::new(py, &[0u8; 31])).unwrap();
            new_inp.append(1u32).unwrap();
            inputs.set_item(0, to_tuple(py, &new_inp)).unwrap();
        });
        assert_eq!(utxo_build_ops_compact(py, &blocks4, 100).unwrap_err().to_string(), "ValueError: tx_input_txid_length");

        // 5. tx_output_tuple_arity
        let blocks5 = build_tx(py, &|list| {
            let outputs = list.get_item(3).unwrap().cast_into::<PyList>().unwrap();
            let new_out = PyList::empty(py);
            new_out.append(100u64).unwrap(); // length 1
            outputs.set_item(0, to_tuple(py, &new_out)).unwrap();
        });
        assert_eq!(utxo_build_ops_compact(py, &blocks5, 100).unwrap_err().to_string(), "ValueError: tx_output_tuple_arity");
    });
}
