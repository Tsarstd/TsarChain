# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import sys
import psutil
import shutil
import platform
import subprocess
from typing import Dict, Any

from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.prompt import Prompt
from rich.console import Console

from tsarchain.utils import config as CFG


def _enable_windows_vt100() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32

            kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            kernel32.GetConsoleMode.restype = ctypes.c_int
            kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel32.SetConsoleMode.restype = ctypes.c_int
            kernel32.CreateFileW.argtypes = [
                ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p
            ]
            kernel32.CreateFileW.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int

            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            DISABLE_NEWLINE_AUTO_RETURN = 0x0008

            for std_handle in (0xFFFFFFF5, 0xFFFFFFF4):
                h_out = kernel32.GetStdHandle(std_handle)
                if h_out and h_out != ctypes.c_void_p(-1).value:
                    mode = ctypes.c_ulong()
                    if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
                        kernel32.SetConsoleMode(
                            h_out, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
                        )

            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            h_conout = kernel32.CreateFileW(
                "CONOUT$",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if h_conout and h_conout != ctypes.c_void_p(-1).value:
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(h_conout, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(
                        h_conout, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
                    )
                kernel32.CloseHandle(h_conout)
        except Exception:
            pass


_enable_windows_vt100()


# RGB custom helpers
def rgb_color(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


def bg_rgb_color(r: int, g: int, b: int) -> str:
    return f"\033[48;2;{r};{g};{b}m"


# Text colors
ORANGE = rgb_color(242, 132, 0)
GREY = rgb_color(245, 246, 244)
YELLOW = rgb_color(232, 215, 59)
GREEN = rgb_color(59, 196, 59)
CYAN = rgb_color(0, 215, 235)
RED = rgb_color(235, 59, 59)

# Text styles
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"

# Rich style constants
STYLE_BOLD_CYAN = "bold cyan"
STYLE_BOLD_WHITE = "bold white"



def human_bytes(n: Any) -> str:
    try:
        size = float(n)
    except Exception:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    for u in units:
        if size < 1024.0 or u == units[-1]:
            return f"{size:.2f} {u}" if u != "B" else f"{int(size)} {u}"
        size /= 1024.0
    return f"{size:.2f} EB"


def _cpu_brand() -> str:
    try:
        sysname = platform.system()
        if sysname == "Windows":
            try:
                import winreg  # type: ignore
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
                ) as k:
                    name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
                    name = " ".join(str(name).split())
                    if name:
                        return name
            except Exception:
                pass

            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name"],
                    stderr=subprocess.DEVNULL
                )
                name = " ".join(out.decode(errors="ignore").strip().split())
                if name:
                    return name
            except Exception:
                pass

        if sysname == "Darwin":
            try:
                out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"])
                return out.decode().strip()
            except Exception:
                pass

        elif sysname == "Linux":
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
            except Exception:
                pass

        name = platform.processor() or getattr(platform.uname(), "processor", "") or ""
        name = " ".join(str(name).strip().split())
        return name or "Unknown CPU"
    except Exception:
        return "Unknown CPU"


def print_banner() -> None:
    banner_text = (
        "[bold cyan]"
        " █████╗ ██████╗  ██████╗██╗  ██╗██╗██╗   ██╗██╗███████╗████████╗\n"
        "██╔══██╗██╔══██╗██╔════╝██║  ██║██║██║   ██║██║██╔════╝╚══██╔══╝\n"
        "███████║██████╔╝██║     ███████║██║██║   ██║██║███████╗   ██║   \n"
        "██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗ ██╔╝██║╚════██║   ██║   \n"
        "██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████╔╝ ██║███████║   ██║   \n"
        "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝╚══════╝   ╚═╝   \n"
        "[/bold cyan]\n"
        "[bold yellow]TsarChain Storage Archivist Node  •  Decentralized Data Preservation[/bold yellow]"
    )
    console = Console()
    console.print(Panel(Align.center(banner_text), border_style="cyan", expand=False))


def print_system_snapshot() -> None:
    console = Console()
    try:
        uname = platform.uname()
        vm = psutil.virtual_memory()
        du = shutil.disk_usage("/")
        freq = None
        try:
            freq = psutil.cpu_freq()
        except Exception:
            pass

        phys = psutil.cpu_count(logical=False) or 0
        logi = psutil.cpu_count(logical=True) or 0

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Key", style=STYLE_BOLD_CYAN)
        table.add_column("Value", style=STYLE_BOLD_WHITE)

        table.add_row("CPU Model", _cpu_brand())
        table.add_row("CPU Cores", f"{phys} physical / {logi} logical")

        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur = f"{(freq.current or 0)/1000:.2f}"
                mx = f"{(freq.max or 0)/1000:.2f}"
                table.add_row("CPU Speed", f"{cur} GHz (base ~{base} / boost ~{mx})")
            except Exception:
                pass

        table.add_row("RAM Memory", f"{human_bytes(vm.total)} total, {human_bytes(vm.available)} free")
        table.add_row("Disk Space", f"{human_bytes(du.free)} free of {human_bytes(du.total)}")
        table.add_row("OS System", f"{uname.system} {uname.release} ({uname.machine})")
        table.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

        console.print(Panel(table, title="[bold gold1]Sovereign Archivist System Specifications[/bold gold1]", border_style="cyan", expand=False))
    except Exception as e:
        console.print(f"[bold red][snapshot] failed: {e}[/bold red]")


def get_user_input() -> tuple[str, str, int]:
    console = Console()
    console.print("\n[bold cyan]Sovereign Archivist Setup Wizard[/bold cyan]")

    while True:
        try:
            address = Prompt.ask("[bold cyan]Enter Storage Payout Address[/bold cyan] ([dim]must start with tsar1...[/dim])").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Setup cancelled by user.[/yellow]")
            sys.exit(0)

        if address and address.lower().startswith(CFG.ADDRESS_PREFIX):
            console.print(f"[bold green]✓ Payout Address locked:[bold green] [white]{address}[/white]")
            break
        else:
            console.print(f"[bold red]Error: Address must start with '{CFG.ADDRESS_PREFIX}...'[/bold red]")

    default_host = CFG.BOOTSTRAP_NODE[0]
    default_port = CFG.BOOTSTRAP_NODE[1]

    try:
        host_input = Prompt.ask(
            "[bold cyan]Target Node Host IP[/bold cyan]",
            default=default_host
        ).strip()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Setup cancelled by user.[/yellow]")
        sys.exit(0)

    try:
        port_input = Prompt.ask(
            "[bold cyan]Target Node RPC Port[/bold cyan]",
            default=str(default_port)
        ).strip()
        port = int(port_input)
    except (KeyboardInterrupt, EOFError, ValueError):
        port = default_port

    return address, host_input, port


def format_files_table(files: Dict[str, Any]) -> Table:
    table = Table(title="[bold cyan]Managed Local Files Index[/bold cyan]", show_header=True, header_style="bold magenta")
    table.add_column("Graffiti / Art ID", style=STYLE_BOLD_CYAN, width=36, overflow="ellipsis")
    table.add_column("Size", justify="right", style=STYLE_BOLD_WHITE, width=12)
    table.add_column("Paid", justify="center", style="bold green", width=8)
    table.add_column("Expire Height", justify="center", style="bold yellow", width=14)
    table.add_column("State", justify="center", style="bold blue", width=10)

    if not files:
        table.add_row("[dim]No files stored yet[/dim]", "-", "-", "-", "-")
        return table

    for gid, meta in list(files.items())[:25]:
        art_id = str(meta.get("art_id") or gid)
        display_id = art_id[:34] + "..." if len(art_id) > 34 else art_id
        is_paid = meta.get("paid")
        paid_str = "[bold green]YES[/bold green]" if is_paid else "[bold red]NO[/bold red]"
        size_str = human_bytes(meta.get("size_bytes", 0))
        expire_str = str(meta.get("expire_at_height", "-"))
        state_str = str(meta.get("state", "-"))

        table.add_row(
            display_id,
            size_str,
            paid_str,
            expire_str,
            state_str,
        )
    return table


def format_pool_table(pool_data: Dict[str, Any]) -> Table:
    table = Table(title="[bold gold1]Graffiti Storage Pool Data[/bold gold1]", show_header=True, header_style="bold magenta")
    table.add_column("Art ID", style=STYLE_BOLD_CYAN, width=28, overflow="ellipsis")
    table.add_column("Pool Balance", justify="right", style="bold gold1", width=14)
    table.add_column("Size", justify="right", style=STYLE_BOLD_WHITE, width=12)
    table.add_column("Creator", style="dim white", width=28, overflow="ellipsis")
    table.add_column("Comments", justify="center", style="bold green", width=10)

    if not pool_data:
        table.add_row("[dim]Pool data not available or empty[/dim]", "-", "-", "-", "-")
        return table

    for aid, entry in list(pool_data.items())[:35]:
        stats = entry.get("stats") or {}
        file_meta = entry.get("file") or {}
        creator = (entry.get("post", {}).get("creator") or "")
        creator_disp = creator[:26] + "..." if len(creator) > 26 else (creator or "-")
        pool_bal = float(stats.get("pool_balance", 0)) / float(CFG.TSAR)
        size_bytes = int(file_meta.get("size_bytes", 0))
        aid_disp = aid[:26] + "..." if len(aid) > 26 else aid

        table.add_row(
            aid_disp,
            f"{pool_bal:.6f} TSAR",
            human_bytes(size_bytes),
            creator_disp,
            str(stats.get("comments", 0)),
        )
    return table
