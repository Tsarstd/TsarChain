# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
from unittest.mock import MagicMock, patch

from kremlin.services.contact_management import _mask_addr, ContactService

# =======================================================
# Test pure function _mask_addr
# =======================================================
def test_mask_addr_empty_or_none():
    assert _mask_addr(None) == ""
    assert _mask_addr("") == ""
    assert _mask_addr("   ") == ""

def test_mask_addr_short():
    assert _mask_addr("tsar1short") == "tsar1short"

def test_mask_addr_long():
    # length >= 20
    # "tsar1qypqpenw24k5m9rqq0z94pxu2j4e0h" (35 chars)
    # first 10 -> "tsar1qypqp", last 6 -> "j4e0h"
    addr = "tsar1qypqpenw24k5m9rqq0z94pxu2j4e0h"
    assert _mask_addr(addr) == "tsar1qypqp-2j4e0h"

# =======================================================
# Test ContactService Business Logic (CRUD & Search)
# =======================================================
@pytest.fixture
def service():
    pwd_cb_mock = MagicMock(return_value="dummy_pwd")
    return ContactService(get_password_cb=pwd_cb_mock)

@patch("kremlin.services.contact_management.list_contacts_in_keystore")
def test_load_with_password(mock_list, service):
    mock_list.return_value = {"tsar1abc": "Alice", "tsar1def": "Bob"}
    
    res = service.load()
    
    assert res == {"tsar1abc": "Alice", "tsar1def": "Bob"}
    service.get_pwd.assert_called_once()
    mock_list.assert_called_once_with("dummy_pwd")
    assert service._contacts == {"tsar1abc": "Alice", "tsar1def": "Bob"}

@patch("kremlin.services.contact_management.list_contacts_in_keystore")
def test_load_no_password(mock_list, service):
    service.get_pwd.return_value = None
    
    res = service.load()
    
    assert res == {}
    mock_list.assert_not_called()

def test_pairs(service):
    # Setup some pre-existing contacts
    service._contacts = {
        "tsar1abcdefghijklmnopqrst": "Bob", 
        "tsar112345678901234567890": "Alice"
    }
    
    items = service.pairs()
    
    # Should be sorted alphabetically by alias (Alice first, then Bob)
    assert len(items) == 2
    
    # Alice
    assert items[0][1] == "tsar112345678901234567890"
    assert "Alice -" in items[0][0]
    
    # Bob
    assert items[1][1] == "tsar1abcdefghijklmnopqrst"
    assert "Bob -" in items[1][0]

@patch("kremlin.services.contact_management.upsert_contact_in_keystore")
def test_upsert_valid(mock_upsert, service):
    # Upsert should normalize casing and spacing
    success, err = service.upsert("  Tsar1VALID  ", "  Charlie  ")
    
    assert success is True
    assert err is None
    mock_upsert.assert_called_once_with("tsar1valid", "Charlie", "dummy_pwd")
    assert service._contacts["tsar1valid"] == "Charlie"

@patch("kremlin.services.contact_management.upsert_contact_in_keystore")
def test_upsert_invalid_address(mock_upsert, service):
    success, err = service.upsert("invalid_addr", "Charlie")
    
    assert success is False
    assert err == "Address must start with tsar1"
    mock_upsert.assert_not_called()

@patch("kremlin.services.contact_management.upsert_contact_in_keystore")
def test_upsert_empty_alias(mock_upsert, service):
    success, err = service.upsert("tsar1valid", "   ")
    
    assert success is False
    assert err == "Alias cannot be empty"
    mock_upsert.assert_not_called()

@patch("kremlin.services.contact_management.upsert_contact_in_keystore")
def test_upsert_no_password(mock_upsert, service):
    service.get_pwd.return_value = None
    
    success, err = service.upsert("tsar1valid", "Charlie")
    
    assert success is False
    assert err is None
    mock_upsert.assert_not_called()

@patch("kremlin.services.contact_management.delete_contact_from_keystore")
def test_delete_valid(mock_delete, service):
    service._contacts = {"tsar1abc": "Alice"}
    
    # Delete should normalize casing and spacing
    success, err = service.delete("  TSAR1abc  ")
    
    assert success is True
    assert err is None
    mock_delete.assert_called_once_with("tsar1abc", "dummy_pwd")
    assert "tsar1abc" not in service._contacts

@patch("kremlin.services.contact_management.delete_contact_from_keystore")
def test_delete_no_password(mock_delete, service):
    service.get_pwd.return_value = None
    service._contacts = {"tsar1abc": "Alice"}
    
    success, err = service.delete("tsar1abc")
    
    assert success is False
    assert err is None
    mock_delete.assert_not_called()
    assert "tsar1abc" in service._contacts

# =======================================================
# Test Search Ranking
# =======================================================
def test_search_contacts(service):
    service._contacts = {
        "tsar1abc": "Alice",
        "tsar1def": "Bob",
        "tsar1ghi": "Charlie (Alice)",
        "tsar1alx": "Alex"
    }

    # Empty search should return all, sorted alphabetically by alias
    res = service.search_contacts("")
    assert len(res) == 4
    assert res[0][1] == "Alex"
    assert res[1][1] == "Alice"
    assert res[2][1] == "Bob"
    assert res[3][1] == "Charlie (Alice)"

    # Search by exact alias start
    res = service.search_contacts("ali")
    # Alice (starts with ali) should be first rank
    # Charlie (Alice) (contains ali) should be second rank
    assert len(res) == 2
    assert res[0][1] == "Alice"
    assert res[1][1] == "Charlie (Alice)"

    # Search by address
    res = service.search_contacts("tsar1alx")
    assert len(res) == 1
    assert res[0][1] == "Alex"
