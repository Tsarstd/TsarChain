# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from decimal import Decimal
from unittest.mock import MagicMock, patch

from kremlin.services.send_service import SendService
from tsarchain.utils import config as CFG

def test_parse_amount_str_valid():
    sats, fmt = SendService.parse_amount_str("1.5")
    assert sats == int(Decimal("1.5") * CFG.TSAR)
    assert fmt == "1.5"

    sats, fmt = SendService.parse_amount_str("  2,5  ")
    assert sats == int(Decimal("2.5") * CFG.TSAR)
    assert fmt == "2.5"

    sats, fmt = SendService.parse_amount_str(".5")
    assert sats == int(Decimal("0.5") * CFG.TSAR)
    assert fmt == "0.5"
    
def test_parse_amount_str_invalid():
    with pytest.raises(ValueError, match="Empty Amount"):
        SendService.parse_amount_str("")
        
    with pytest.raises(ValueError, match="Invalid amount format"):
        SendService.parse_amount_str("abc")
        
    with pytest.raises(ValueError, match="Amount must be > 0"):
        SendService.parse_amount_str("0")
        
    with pytest.raises(ValueError, match="Amount must be > 0"):
        SendService.parse_amount_str("-1")
        
    with pytest.raises(ValueError, match="dust"):
        SendService.parse_amount_str("0.00000001") # smaller than 546 sats typically

def test_clamp_fee_rate():
    assert SendService.clamp_fee_rate(None) == int(CFG.DEFAULT_FEE_RATE_SATVB)
    assert SendService.clamp_fee_rate(CFG.MAX_FEE_RATE_SATVB + 100) == int(CFG.MAX_FEE_RATE_SATVB)
    assert SendService.clamp_fee_rate(CFG.MIN_FEE_RATE_SATVB - 1) == int(CFG.MIN_FEE_RATE_SATVB)
    assert SendService.clamp_fee_rate(CFG.MIN_FEE_RATE_SATVB + 10) == int(CFG.MIN_FEE_RATE_SATVB + 10)

def test_estimate_vbytes():
    vbytes = SendService.estimate_vbytes(n_inputs=1, n_outputs=2)
    expected = CFG.TX_BASE_VBYTES + 1 * CFG.SEGWIT_INPUT_VBYTES + 2 * CFG.SEGWIT_OUTPUT_VBYTES
    assert vbytes == expected

def test_estimate_fee():
    # Regular fee estimation
    res = SendService.estimate_fee(100000, 10)
    assert res["n_outputs"] == 2
    
    # Estimation when sending near max spendable
    res2 = SendService.estimate_fee(100000, 10, spendable=101000)
    assert res2["n_outputs"] == 1

@patch("kremlin.services.send_service.Wallet")
def test_create_sign_broadcast_success(mock_wallet):
    service = SendService()
    
    mock_rpc = MagicMock()
    mock_progress = MagicMock()
    mock_done = MagicMock()
    
    # Call the service
    service.create_sign_broadcast(
        from_addr="addr_from",
        to_addr="addr_to",
        amount_sats=10000,
        password_provider=lambda x: "password",
        rpc_send=mock_rpc,
        fee_rate=10,
        on_progress=mock_progress,
        on_done=mock_done
    )
    
    # Should call RPC to get template
    assert mock_rpc.call_count == 1
    args, kwargs = mock_rpc.call_args
    payload, cb = args
    assert payload["type"] == "CREATE_TX"
    assert payload["amount"] == 10000
    
    # Simulate RPC response (TX_TEMPLATE)
    mock_wallet.unlock.return_value = {"private_key": "dummy_key"}
    mock_signed_tx = MagicMock()
    mock_signed_tx.to_dict.return_value = {"tx_data": "signed"}
    mock_wallet.sign_prepared_tx.return_value = mock_signed_tx
    
    cb({
        "type": "TX_TEMPLATE",
        "data": {
            "tx": "unsigned_tx",
            "inputs": []
        }
    })
    
    # Should call rpc_send again with NEW_TX
    assert mock_rpc.call_count == 2
    args2, kwargs2 = mock_rpc.call_args
    payload2, cb2 = args2
    assert payload2["type"] == "NEW_TX"
    assert payload2["data"] == {"tx_data": "signed"}
    
    # Trigger final callback
    cb2({"success": True})
    mock_done.assert_called_with({"success": True})

@patch("kremlin.services.send_service.Wallet")
def test_create_sign_broadcast_multi(mock_wallet):
    service = SendService()
    
    mock_rpc = MagicMock()
    mock_progress = MagicMock()
    mock_done = MagicMock()
    
    service.create_sign_broadcast(
        from_addr="addr_from",
        to_addr="addr_to",
        amount_sats=10000,
        password_provider=lambda x: "password",
        rpc_send=mock_rpc,
        fee_rate=10,
        on_progress=mock_progress,
        on_done=mock_done,
        opret_hex="deadbeef",
        extra_outputs=[{"address": "addr3", "amount": 5000}]
    )
    
    args, kwargs = mock_rpc.call_args
    payload, cb = args
    assert payload["type"] == "CREATE_TX_MULTI"
    assert len(payload["outputs"]) == 3 # base_addr, addr3, opret_hex
    assert payload["outputs"][0]["address"] == "addr_to"
    assert payload["outputs"][1]["address"] == "addr3"
    assert payload["outputs"][2]["opret_hex"] == "deadbeef"

def test_create_sign_broadcast_failures():
    service = SendService()
    mock_rpc = MagicMock()
    mock_progress = MagicMock()
    mock_done = MagicMock()
    
    service.create_sign_broadcast(
        from_addr="addr_from",
        to_addr="addr_to",
        amount_sats=10000,
        password_provider=lambda x: None, # No password
        rpc_send=mock_rpc,
        fee_rate=10,
        on_progress=mock_progress,
        on_done=mock_done
    )
    
    # Fail at template
    args, kwargs = mock_rpc.call_args
    payload, cb = args
    cb({"error": "Bad Request"})
    mock_done.assert_called_with({"error": "template_failed"})
    
    # Fail at password
    cb({
        "type": "TX_TEMPLATE",
        "data": {"tx": "unsigned_tx", "inputs": []}
    })
    mock_done.assert_called_with({"error": "no_password"})

@patch("kremlin.services.send_service.Wallet")
def test_create_sign_broadcast_unlock_sign_fails(mock_wallet):
    service = SendService()
    mock_rpc = MagicMock()
    mock_progress = MagicMock()
    mock_done = MagicMock()
    
    service.create_sign_broadcast(
        from_addr="addr_from",
        to_addr="addr_to",
        amount_sats=10000,
        password_provider=lambda x: "pass",
        rpc_send=mock_rpc,
        fee_rate=10,
        on_progress=mock_progress,
        on_done=mock_done
    )
    
    args, kwargs = mock_rpc.call_args
    cb = args[1]
    
    # Unlock fails
    mock_wallet.unlock.side_effect = Exception("Unlock error")
    cb({
        "type": "TX_TEMPLATE",
        "data": {"tx": "unsigned_tx", "inputs": []}
    })
    mock_done.assert_called_with({"error": "unlock_failed"})
    
    # Sign fails
    mock_wallet.unlock.side_effect = None
    mock_wallet.unlock.return_value = {"private_key": "hex"}
    mock_wallet.sign_prepared_tx.side_effect = Exception("Sign error")
    
    cb({
        "type": "TX_TEMPLATE",
        "data": {"tx": "unsigned_tx", "inputs": []}
    })
    mock_done.assert_called_with({"error": "sign_failed"})
    
    # RPC exception
    mock_rpc.side_effect = Exception("Network error")
    service.create_sign_broadcast(
        from_addr="addr_from",
        to_addr="addr_to",
        amount_sats=10000,
        password_provider=lambda x: "pass",
        rpc_send=mock_rpc,
        fee_rate=10,
        on_progress=mock_progress,
        on_done=mock_done
    )
    mock_done.assert_called_with({"error": "rpc_exception", "detail": "Network error"})
