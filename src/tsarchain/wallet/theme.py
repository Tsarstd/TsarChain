# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

"""
Centralised theme registry for Kremlin wallet UI.

This module exposes a single entry point `get_theme(mode)` that returns
palette tokens plus per-tab configuration objects so the whole wallet
can share consistent colours and spacing without hard-coding hex values
inside widgets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


# ---------------------------------------------------------------------------
# Colour utilities
# ---------------------------------------------------------------------------

def _hex_to_rgb(value: str) -> Tuple[int, int, int]:
    value = value.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(
        max(0, min(255, int(round(rgb[0])))),
        max(0, min(255, int(round(rgb[1])))),
        max(0, min(255, int(round(rgb[2])))),
    )


def _blend(color: str, target: str, factor: float) -> str:
    factor = max(0.0, min(1.0, factor))
    c1 = _hex_to_rgb(color)
    c2 = _hex_to_rgb(target)
    mixed = tuple(c1[i] + (c2[i] - c1[i]) * factor for i in range(3))
    return _rgb_to_hex(mixed)


def lighten(color: str, amount: float) -> str:
    return _blend(color, "#ffffff", amount)


def darken(color: str, amount: float) -> str:
    return _blend(color, "#000000", amount)


# --------------------------------------------------------------------------- #
# Theme dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Palette:
    mode: str
    bg: str
    panel_bg: str
    surface: str
    surface_alt: str
    card: str
    fg: str
    muted: str
    accent: str
    accent_soft: str
    border: str
    success: str
    warning: str
    danger: str
    info: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "bg": self.bg,
            "panel_bg": self.panel_bg,
            "fg": self.fg,
            "muted": self.muted,
            "accent": self.accent,
            "card": self.card,
            "border": self.border,
            "success": self.success,
            "warning": self.warning,
            "danger": self.danger,
            "info": self.info,
            "surface": self.surface,
            "surface_alt": self.surface_alt,
            "accent_soft": self.accent_soft,
        }


@dataclass(frozen=True)
class ChatTheme:
    mode: str
    bg: str
    panel_bg: str
    text_fg: str
    muted_fg: str
    accent: str
    border: str
    entry_bg: str
    bubble_peer_bg: str
    bubble_peer_fg: str
    bubble_me_bg: str
    bubble_me_fg: str
    system_fg: str
    status_online_fg: str
    status_offline_fg: str
    warning_fg: str
    error_fg: str


@dataclass(frozen=True)
class ExplorerTheme:
    bg: str
    card_bg: str
    border: str
    fg: str
    muted: str
    accent: str
    value_num: str
    value_id: str
    confirmed: str
    unconfirmed: str


@dataclass(frozen=True)
class SendTheme:
    bg: str
    panel_bg: str
    card_bg: str
    fg: str
    muted: str
    accent: str
    border: str
    slider_bg: str
    slider_trough: str
    success: str
    warning: str
    danger: str


@dataclass(frozen=True)
class GraffitiTheme:
    bg: str
    card_bg: str
    fg: str
    muted: str
    accent: str
    border: str


@dataclass(frozen=True)
class ContactsTheme:
    bg: str
    panel_bg: str
    card_bg: str
    fg: str
    muted: str
    accent: str
    border: str
    state_on: str
    state_off: str


@dataclass(frozen=True)
class WalletTheme:
    bg: str
    panel_bg: str
    fg: str
    muted: str
    accent: str
    hero_tagline: str
    sidebar_bg: str
    sidebar_active: str

    def to_dialog_dict(self) -> Dict[str, str]:
        return {
            "bg": self.bg,
            "panel_bg": self.panel_bg,
            "fg": self.fg,
            "muted": self.muted,
            "accent": self.accent,
            "card": self.panel_bg,
            "border": darken(self.panel_bg, 0.35),
        }


@dataclass(frozen=True)
class ThemeSet:
    palette: Palette
    chat: ChatTheme
    explorer: ExplorerTheme
    send: SendTheme
    graffiti: GraffitiTheme
    contacts: ContactsTheme
    wallet: WalletTheme


# --------------------------------------------------------------------------- #
# Theme registry
# --------------------------------------------------------------------------- #

_BASE_MODES: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#0f1115",
        "panel_bg": "#161a1f",
        "surface": "#1d232b",
        "surface_alt": "#232a33",
        "card": "#161a1f",
        "fg": "#f2f5f7",
        "muted": "#a9b1ba",
        "accent": "#ff6b00",
        "border": "#2a2f36",
        "success": "#31C47F",
        "warning": "#f59f45",
        "danger": "#f87171",
        "info": "#38bdf8",
    },
    "light": {
        "bg": "#f6f7fb",
        "panel_bg": "#e9edf4",
        "surface": "#f1f4fa",
        "surface_alt": "#e0e6f2",
        "card": "#e9edf4",
        "fg": "#16202b",
        "muted": "#59616b",
        "accent": "#2563eb",
        "border": "#b8c2d3",
        "success": "#1a9f63",
        "warning": "#f59b35",
        "danger": "#d3464d",
        "info": "#2072b8",
    },
}


def _build_palette(mode: str) -> Palette:
    base = _BASE_MODES["dark"]
    requested = _BASE_MODES.get(mode.lower(), base)
    accent_soft = lighten(requested["accent"], 0.35)
    return Palette(
        mode=mode.lower(),
        bg=requested["bg"],
        panel_bg=requested["panel_bg"],
        surface=requested["surface"],
        surface_alt=requested["surface_alt"],
        card=requested["card"],
        fg=requested["fg"],
        muted=requested["muted"],
        accent=requested["accent"],
        accent_soft=accent_soft,
        border=requested["border"],
        success=requested["success"],
        warning=requested["warning"],
        danger=requested["danger"],
        info=requested["info"],
    )


def _build_chat_theme(p: Palette) -> ChatTheme:
    bubble_peer = _blend(p.surface, p.accent, 0.12)
    bubble_me = _blend(p.accent, "#ffffff", 0.25)
    return ChatTheme(
        mode=p.mode,
        bg=p.bg,
        panel_bg=p.surface,
        text_fg=p.fg,
        muted_fg=_blend(p.fg, p.muted, 0.6),
        accent=p.accent,
        border=p.border,
        entry_bg=p.surface_alt,
        bubble_peer_bg=bubble_peer,
        bubble_peer_fg=p.fg,
        bubble_me_bg=bubble_me,
        bubble_me_fg=darken(p.fg, 0.15) if p.mode == "light" else p.fg,
        system_fg=_blend(p.fg, p.muted, 0.4),
        status_online_fg=p.success,
        status_offline_fg=p.danger,
        warning_fg=p.warning,
        error_fg=p.danger,
    )


def _build_explorer_theme(p: Palette) -> ExplorerTheme:
    value_num = _blend(p.accent, "#f7e3a1", 0.45)
    value_id = _blend(p.info, "#ffffff", 0.35)
    unconfirmed = _blend(p.warning, "#ffffff", 0.4)
    return ExplorerTheme(
        bg=p.bg,
        card_bg=p.surface,
        border=p.border,
        fg=p.fg,
        muted=p.muted,
        accent=p.accent,
        value_num=value_num,
        value_id=value_id,
        confirmed=p.success,
        unconfirmed=unconfirmed,
    )


def _build_send_theme(p: Palette) -> SendTheme:
    return SendTheme(
        bg=p.bg,
        panel_bg=p.panel_bg,
        card_bg=p.surface,
        fg=p.fg,
        muted=p.muted,
        accent=p.accent,
        border=p.border,
        slider_bg=p.accent,
        slider_trough=darken(p.surface_alt, 0.2),
        success=p.success,
        warning=p.warning,
        danger=p.danger,
    )


def _build_graffiti_theme(p: Palette) -> GraffitiTheme:
    return GraffitiTheme(
        bg=p.bg,
        card_bg=p.surface,
        fg=p.fg,
        muted=p.muted,
        accent=p.accent,
        border=p.border,
    )


def _build_contacts_theme(p: Palette) -> ContactsTheme:
    return ContactsTheme(
        bg=p.bg,
        panel_bg=p.panel_bg,
        card_bg=p.surface,
        fg=p.fg,
        muted=p.muted,
        accent=p.accent,
        border=p.border,
        state_on=p.success,
        state_off=p.danger,
    )


def _build_wallet_theme(p: Palette) -> WalletTheme:
    sidebar_bg = darken(p.panel_bg, 0.08) if p.mode == "light" else darken(p.panel_bg, 0.12)
    sidebar_active = _blend(p.accent, p.bg, 0.2)
    hero_tagline = _blend(p.accent, "#ffffff", 0.55)
    return WalletTheme(
        bg=p.bg,
        panel_bg=p.panel_bg,
        fg=p.fg,
        muted=p.muted,
        accent=p.accent,
        hero_tagline=hero_tagline,
        sidebar_bg=sidebar_bg,
        sidebar_active=sidebar_active,
    )


def get_theme(mode: str = "dark") -> ThemeSet:
    """
    Return a ThemeSet describing the palette and component-specific
    configurations for the requested mode.
    """
    palette = _build_palette(mode)
    return ThemeSet(
        palette=palette,
        chat=_build_chat_theme(palette),
        explorer=_build_explorer_theme(palette),
        send=_build_send_theme(palette),
        graffiti=_build_graffiti_theme(palette),
        contacts=_build_contacts_theme(palette),
        wallet=_build_wallet_theme(palette),
    )


__all__ = [
    "Palette",
    "ChatTheme",
    "ExplorerTheme",
    "SendTheme",
    "GraffitiTheme",
    "ContactsTheme",
    "WalletTheme",
    "ThemeSet",
    "get_theme",
    "lighten",
    "darken",
]
