# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import os
import sys
import psutil
import shutil
import platform
import subprocess

from tsarchain.utils import config as CFG
from rich.panel import Panel
from rich.align import Align
from rich.console import Console

from .tui import _enable_windows_vt100

_enable_windows_vt100()


def print_banner():
    banner_text = (
        "[bold orange1]"
        "████████╗███████╗ █████╗ ██████╗    ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗\n"
        "╚══██╔══╝██╔════╝██╔══██╗██╔══██╗  ██╔════╝██║  ██║██╔══██╗██║████╗  ██║\n"
        "   ██║   ███████╗███████║██████╔╝  ██║     ███████║███████║██║██╔██╗ ██║\n"
        "   ██║   ╚════██║██╔══██║██╔══██╗  ██║     ██╔══██║██╔══██║██║██║╚██╗██║\n"
        "   ██║   ███████║██║  ██║██║  ██║  ╚██████╗██║  ██║██║  ██║██║██║ ╚████║\n"
        "   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝\n"
        "[/bold orange1]\n"
        "[bold yellow]TsarChain Mining CLI  •  Long Live The Voice Sovereignty[/bold yellow]"
    )
    console = Console()
    console.print(Panel(Align.center(banner_text), border_style="orange1", expand=False))


# RGB custom
def rgb_color(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def bg_rgb_color(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"


# Text
ORANGE = rgb_color(242, 132, 0)
GREY = rgb_color(245, 246, 244)
YELLOW = rgb_color(232, 215, 59)
GREEN = rgb_color(59, 196, 59)
CYAN = rgb_color(0, 215, 235)
RED = rgb_color(235, 59, 59)

# Header Info
TXT_HEADER = rgb_color(237, 237, 237)
BG_HEADER = bg_rgb_color(220, 64, 50)

# Info Column
TXT_INFO = rgb_color(64, 64, 64)

# Background
BG_GREY = bg_rgb_color(179, 189, 193)
BG_WHITE = bg_rgb_color(240, 247, 249)
BG_RED = bg_rgb_color(191, 34, 34)
BG_BLUE = bg_rgb_color(32, 163, 223)
BG_ORANGE = bg_rgb_color(242, 132, 0)
BG_YELLOW = bg_rgb_color(232, 215, 59)
BG_GREEN = bg_rgb_color(59, 196, 59)


# Text styles
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"
REVERSE = "\033[7m"
HIDDEN = "\033[8m"


def _human_bytes(n: int) -> str:
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B","KB","MB","GB","TB","PB","EB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} ZB"

def _cpu_brand() -> str:
    try:
        sysname = platform.system()
        if sysname == "Windows":
            # Registry
            try:
                import winreg  # type: ignore
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                    name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
                    name = " ".join(str(name).split())
                    if name:
                        return name
            except Exception:
                pass

            # WMIC
            try:
                out = subprocess.check_output(
                    ["wmic", "cpu", "get", "Name"],
                    stderr=subprocess.DEVNULL
                )
                lines = [l.strip() for l in out.decode(errors="ignore").splitlines() if l.strip()]
                if len(lines) >= 2:
                    name = " ".join(lines[1].split())
                    if name:
                        return name
            except Exception:
                pass

            # PowerShell
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
            
            # lscpu
            try:
                out = subprocess.check_output(["lscpu"], stderr=subprocess.DEVNULL)
                for line in out.decode(errors="ignore").splitlines():
                    if "Model name:" in line:
                        name = " ".join(line.split(":", 1)[1].strip().split())
                        if name:
                            return name
            except Exception:
                pass
            
        # Windows / fallback
        name = platform.processor() or getattr(platform.uname(), "processor", "") or ""
        name = " ".join(str(name).strip().split())
        return name or "Unknown CPU"
    except Exception:
        return "Unknown CPU"

def print_system_snapshot(cores_hint: int | None = None):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

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
        table.add_column("Key", style="bold cyan")
        table.add_column("Value", style="bold white")

        table.add_row("CPU Model", _cpu_brand())

        core_info = f"{phys} physical / {logi} logical"
        if cores_hint:
            core_info += f" (recommended: {cores_hint})"
        table.add_row("CPU Cores", core_info)

        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur  = f"{(freq.current or 0)/1000:.2f}"
                mx   = f"{(freq.max or 0)/1000:.2f}"
                table.add_row("CPU Speed", f"{cur} GHz (base ~{base} / boost ~{mx})")
            except Exception:
                pass

        table.add_row("RAM Memory", f"{_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free")
        table.add_row("Disk Space", f"{_human_bytes(du.free)} free of {_human_bytes(du.total)}")
        table.add_row("OS System", f"{uname.system} {uname.release} ({uname.machine})")
        table.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

        console.print(Panel(table, title="[bold gold1]Your Sovereign Hardware Specifications[/bold gold1]", border_style="cyan", expand=False))
    except Exception as e:
        console.print(f"[bold red][snapshot] failed: {e}[/bold red]")

def get_user_input():
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.panel import Panel

    console = Console()
    console.print("\n[bold orange1]Sovereign Miner Setup Wizard[/bold orange1]")

    # Input address
    while True:
        try:
            address = Prompt.ask("[bold cyan]Enter Miner Address[/bold cyan] ([dim]must start with tsar1...[/dim])").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Setup cancelled by user.[/yellow]")
            sys.exit(0)

        if address and address.lower().startswith("tsar1"):
            console.print(f"[bold green]✓ Wallet Address locked:[bold green] [white]{address}[/white]")
            break
        else:
            console.print("[bold red]Error: Address must start with 'tsar1...'[/bold red]")
            console.print("[dim]Example: tsar1qyourwalletaddresshere[/dim]")

    # Input CPU cores
    total_cores = psutil.cpu_count(logical=True) or 1
    console.print(f"\n[bold cyan]System detected [green]{total_cores}[/green] total CPU thread(s).[/bold cyan]")

    while True:
        try:
            cores_input = Prompt.ask(
                "[bold cyan]CPU cores to assign for mining[/bold cyan]",
                default=str(total_cores)
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Setup cancelled by user.[/yellow]")
            sys.exit(0)

        try:
            cores = int(cores_input)
            if cores <= 0:
                console.print("[bold red]Error: Cores must be a positive integer.[/bold red]")
                continue
            if cores > total_cores:
                console.print(f"[bold red]Warning: Selected {cores} exceeds total detected {total_cores} cores. Setting max to {total_cores}.[/bold red]")
                cores = total_cores
            console.print(f"[bold green]✓ Assigned Cores:[bold green] [bold white]{cores} core(s)[/bold white]")
            break
        except ValueError:
            console.print("[bold red]Error: Please enter a valid integer number.[/bold red]")

    return address, cores

def prompt_rx_full_mem() -> bool:
    from rich.console import Console
    from rich.prompt import Confirm
    from rich.panel import Panel

    console = Console()
    console.print("\n[bold orange1]RandomX PoW Engine Configuration[/bold orange1]")
    console.print("[bold green]FULL MEMORY Mode[/bold green] : Faster hashrate (+2.5GB RAM dataset)")
    console.print("[bold blue]LIGHT MODE[/bold blue]        : Stable RAM usage (~2.5GB RAM dataset)")

    vm = psutil.virtual_memory()
    total_ram_gb = vm.total / (1024 ** 3)
    avail_ram_gb = vm.available / (1024 ** 3)

    if total_ram_gb < 3.5 or avail_ram_gb < 2.5:
        console.print(f"[bold yellow]⚠️ System Memory Notice: {avail_ram_gb:.1f} GB available of {total_ram_gb:.1f} GB total.[/bold yellow]")
        console.print("[yellow]RandomX Full Memory Mode requires ~2.5 GB dedicated free RAM. Light Mode is recommended.[/yellow]")

    try:
        enabled = Confirm.ask("[bold cyan]Enable RandomX FULL MEMORY Mode?[/bold cyan]", default=False)
    except (KeyboardInterrupt, EOFError):
        console.print("[yellow]Using default LIGHT MODE.[/yellow]")
        return False

    if enabled:
        if avail_ram_gb < 2.5:
            console.print(f"[bold red]⚠️ Warning: Low available memory ({avail_ram_gb:.1f} GB). Full Memory mode may cause system swapping or OOM crash.[/bold red]")
        console.print("[bold green]✓ RandomX FULL MEMORY Enabled (+2.5GB RAM)[/bold green]\n")
    else:
        console.print("[bold blue]✓ RandomX LIGHT MODE Selected[/bold blue]\n")
    return enabled
