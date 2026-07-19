# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import pytest
import tkinter as tk
from unittest.mock import MagicMock, patch

from kremlin.services.media import _fmt_ms, VLCPlayerService, TkVLCPlayer

def test_fmt_ms():
    assert _fmt_ms(None) == "00:00"
    assert _fmt_ms(-1000) == "00:00"
    assert _fmt_ms(0) == "00:00"
    assert _fmt_ms(1000) == "00:01"
    assert _fmt_ms(61000) == "01:01"
    assert _fmt_ms(3600000) == "01:00:00"
    assert _fmt_ms(3661000) == "01:01:01"

@pytest.fixture
def mock_vlc():
    # Patch the global vlc module inside media.py
    with patch("kremlin.services.media.vlc") as mock_vlc_module:
        mock_instance = MagicMock()
        mock_player = MagicMock()
        mock_vlc_module.Instance.return_value = mock_instance
        mock_instance.media_player_new.return_value = mock_player
        
        # Add mock for EventType enum
        mock_vlc_module.EventType.MediaPlayerEndReached = 1
        
        yield mock_vlc_module, mock_instance, mock_player

def test_vlc_service_init(mock_vlc):
    _, mock_instance, mock_player = mock_vlc
    service = VLCPlayerService(init_volume=50)
    
    mock_player.audio_set_volume.assert_called_once_with(50)
    assert not service._ended

def test_vlc_service_play_pause(mock_vlc):
    _, _, mock_player = mock_vlc
    service = VLCPlayerService()
    
    service.play()
    mock_player.play.assert_called_once()
    
    service.pause()
    mock_player.pause.assert_called_once()
    
    mock_player.is_playing.return_value = 1
    assert service.is_playing() is True

def test_vlc_service_toggle_play(mock_vlc):
    _, _, mock_player = mock_vlc
    service = VLCPlayerService()
    
    # Mock currently playing
    mock_player.is_playing.return_value = 1
    service.toggle_play()
    mock_player.pause.assert_called_once()
    
    # Mock paused
    mock_player.is_playing.return_value = 0
    service.toggle_play()
    mock_player.play.assert_called_once()

def test_vlc_service_attach_window(mock_vlc):
    _, _, mock_player = mock_vlc
    service = VLCPlayerService()
    
    win_id = 12345
    with patch("kremlin.services.media.sys") as mock_sys:
        # Test windows
        mock_sys.platform = "win32"
        service.attach_window(win_id)
        mock_player.set_hwnd.assert_called_once_with(win_id)
        
        # Test darwin
        mock_sys.platform = "darwin"
        service.attach_window(win_id)
        mock_player.set_nsobject.assert_called_once_with(win_id)
        
        # Test linux
        mock_sys.platform = "linux"
        service.attach_window(win_id)
        mock_player.set_xwindow.assert_called_once_with(win_id)


@pytest.fixture(scope="module")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()

def test_tk_vlc_player_init(tk_root, mock_vlc):
    player = TkVLCPlayer(tk_root, init_volume=60)
    
    assert player.volume_var.get() == 60.0
    assert player.play_label.get() == "Play"
    # Service should be created
    assert isinstance(player.service, VLCPlayerService)

def test_tk_vlc_player_toggle_play(tk_root, mock_vlc):
    player = TkVLCPlayer(tk_root)
    _, _, mock_player = mock_vlc
    
    # Initially paused
    mock_player.is_playing.return_value = 0
    player.toggle_play()
    mock_player.play.assert_called_once()
    
    # Change mock state to playing
    mock_player.is_playing.return_value = 1
    player.toggle_play()
    mock_player.pause.assert_called_once()
    assert player.play_label.get() == "Pause" # should say Pause when it IS playing

@patch("kremlin.services.media.os.path.isfile", return_value=True)
def test_tk_vlc_player_load(mock_isfile, tk_root, mock_vlc):
    player = TkVLCPlayer(tk_root)
    _, mock_instance, mock_player = mock_vlc
    
    player.load("dummy.mp4", autoplay=True)
    mock_instance.media_new.assert_called_once_with("dummy.mp4")
    mock_player.set_media.assert_called_once()
    mock_player.play.assert_called_once()
