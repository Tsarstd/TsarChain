# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

import pytest
import tkinter as tk
from unittest.mock import MagicMock, patch

from kremlin.services.contact_management import ContactManager

# =======================================================
# Test ContactManager (View / Controller) UI Logic
# =======================================================
@pytest.fixture
def mock_theme():
    class DummyTheme:
        bg = "#111111"
        panel_bg = "#222222"
        fg = "#ffffff"
        muted = "#888888"
        accent = "#ff8800"
        card_bg = "#333333"
        border = "#444444"
        state_on = "#00ff00"
        state_off = "#ff0000"
    return DummyTheme()

@pytest.fixture
def tk_root():
    """Provides a hidden Tk root for widget testing."""
    root = tk.Tk()
    root.withdraw() # Hide it
    yield root
    root.destroy()

@pytest.fixture
def manager(tk_root, mock_theme):
    pwd_cb_mock = MagicMock(return_value="dummy_pwd")
    cm = ContactManager(
        root=tk_root, 
        get_password_cb=pwd_cb_mock, 
        theme=mock_theme
    )
    # Inject some mock data into the service
    cm.service._contacts = {
        "tsar1abc": "Alice",
        "tsar1def": "Bob"
    }
    return cm

@patch("kremlin.services.contact_management.tk.Toplevel")
def test_pick_contact_initial_render(mock_toplevel, manager, tk_root):
    # Mock Toplevel to avoid actual window creation
    mock_dlg = MagicMock()
    mock_toplevel.return_value = mock_dlg
    pass

def test_pick_contact_real_widgets(manager, tk_root):
    """Integration style test for the UI dialog without showing it."""
    with patch("tkinter.Toplevel.wait_window"):
        with patch("tkinter.Toplevel.grab_set"):
            # Open the dialog
            manager.pick_contact(prompt_password=False)
            
            toplevels = [w for w in tk_root.winfo_children() if isinstance(w, tk.Toplevel)]
            assert len(toplevels) == 1
            dlg = toplevels[0]
            dlg.withdraw() # ensure hidden
            
            state = getattr(dlg, "_test_state", None)
            qvar = getattr(dlg, "_test_qvar", None)
            use_btn = getattr(dlg, "_test_use_btn", None)
            
            assert state is not None
            assert len(state["cards"]) == 2 # Alice and Bob
            assert state["sel_addr"] is None
            assert use_btn["state"] == "disabled"
            
            # Test Search Filtering
            qvar.set("ali")
            tk_root.update_idletasks() # Trigger traces
            assert len(state["cards"]) == 1
            assert "tsar1abc" in state["cards"] # Only Alice remains
            
            # Test clicking a card
            card = state["cards"]["tsar1abc"]
            # Simulate click on the card
            card.event_generate("<Button-1>")
            tk_root.update_idletasks()
            
            assert state["sel_addr"] == "tsar1abc"
            assert use_btn["state"] == "normal"
            assert use_btn["bg"] == manager.colors["accent"]
            
            dlg.destroy()

@patch("kremlin.services.contact_management.messagebox")
def test_manager_upsert_shows_warning(mock_mbox, manager):
    # Upserting invalid should show warning via ContactManager
    res = manager.upsert("invalid_addr", "Charlie")
    
    assert res is False
    mock_mbox.showwarning.assert_called_once_with("Invalid", "Address must start with tsar1")
