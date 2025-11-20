# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import psutil, platform, shutil, platform, shutil, subprocess, sys, os
from colorama import init, Fore, Back

def print_banner():
    banner = r"""
    ████████╗███████╗ █████╗ ██████╗    ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
    ╚══██╔══╝██╔════╝██╔══██╗██╔══██╗  ██╔════╝██║  ██║██╔══██╗██║████╗  ██║
       ██║   ███████╗███████║██████╔╝  ██║     ███████║███████║██║██╔██╗ ██║
       ██║   ╚════██║██╔══██║██╔══██╗  ██║     ██╔══██║██╔══██║██║██║╚██╗██║
       ██║   ███████║██║  ██║██║  ██║  ╚██████╗██║  ██║██║  ██║██║██║ ╚████║
       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ 
    """
    footer = r"""
                            Tsar Chain Mining CLI
                       Long Live The Voice Sovereignty
    """
    print(f"{TSAR_COLOR}{banner}{RESET}{YELLOW}{footer}{RESET}")

init()

# RGB custom
def rgb_color(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def bg_rgb_color(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"

TSAR_COLOR = rgb_color(255, 94, 0)
BACK_TSAR_COLOR = bg_rgb_color(255, 94, 0)
COMP_PC = bg_rgb_color(203, 205, 205)
COMP_INF = bg_rgb_color(125, 150, 160)


# Base colors
BLACK = Fore.BLACK
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN
WHITE = Fore.WHITE

# Bright colors
BRIGHT_BLACK = Fore.LIGHTBLACK_EX
BRIGHT_RED = Fore.LIGHTRED_EX
BRIGHT_GREEN = Fore.LIGHTGREEN_EX
BRIGHT_YELLOW = Fore.LIGHTYELLOW_EX
BRIGHT_BLUE = Fore.LIGHTBLUE_EX
BRIGHT_MAGENTA = Fore.LIGHTMAGENTA_EX
BRIGHT_CYAN = Fore.LIGHTCYAN_EX
BRIGHT_WHITE = Fore.LIGHTWHITE_EX

# Background colors
BACK_BLACK = Back.BLACK
BACK_RED = Back.RED
BACK_GREEN = Back.GREEN
BACK_YELLOW = Back.YELLOW
BACK_BLUE = Back.BLUE
BACK_MAGENTA = Back.MAGENTA
BACK_CYAN = Back.CYAN
BACK_WHITE = Back.WHITE

# Bright background colors
BACK_BRIGHT_BLACK = Back.LIGHTBLACK_EX
BACK_BRIGHT_RED = Back.LIGHTRED_EX
BACK_BRIGHT_GREEN = Back.LIGHTGREEN_EX
BACK_BRIGHT_YELLOW = Back.LIGHTYELLOW_EX
BACK_BRIGHT_BLUE = Back.LIGHTBLUE_EX
BACK_BRIGHT_MAGENTA = Back.LIGHTMAGENTA_EX
BACK_BRIGHT_CYAN = Back.LIGHTCYAN_EX
BACK_BRIGHT_WHITE = Back.LIGHTWHITE_EX

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
    try:
        uname = platform.uname()
        vm = psutil.virtual_memory()
        du = shutil.disk_usage("/")  # root fs
        freq = None
        try:
            freq = psutil.cpu_freq()
        except Exception:
            pass

        phys = psutil.cpu_count(logical=False) or 0
        logi = psutil.cpu_count(logical=True) or 0
        try:
            la = os.getloadavg()  # Unix
            la_str = f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}"
        except Exception:
            la_str = "n/a"

        print(f"{BOLD}{BACK_BRIGHT_BLACK}                      Your Sovereign                     {RESET}")
        print(f"{BOLD}{BACK_BRIGHT_BLACK}                      Specifications                     {RESET}")
        print(f"{BOLD}{COMP_PC}  CPU      {RESET}{BOLD}{COMP_INF} {_cpu_brand()}       {RESET}")
        line_core = f"{BOLD}{COMP_INF}  Cores    {RESET}{BOLD}{COMP_PC} {phys} phys / {logi} logical                          {RESET}"
        if cores_hint:
            line_core += f"  |  use {cores_hint}"
        print(line_core)
        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur  = f"{(freq.current or 0)/1000:.2f}"
                mx   = f"{(freq.max or 0)/1000:.2f}"
                print(f"{COMP_PC}  Speed    {RESET}{COMP_INF} {cur} GHz (base ~{base} / boost ~{mx})          {RESET}")
            except Exception:
                pass
        print(f"{BOLD}{COMP_INF}  RAM      {RESET}{BOLD}{COMP_PC} {_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free                  {RESET}")
        print(f"{BOLD}{COMP_PC}  Disk     {RESET}{BOLD}{COMP_INF} {_human_bytes(du.free)} free of {_human_bytes(du.total)}                     {RESET}")
        print(f"{BOLD}{COMP_INF}  OS       {RESET}{BOLD}{COMP_PC} {uname.system} {uname.release} ({uname.machine})                           {RESET}")
        print(f"{BOLD}{COMP_PC}  Python   {RESET}{BOLD}{COMP_INF} {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}                                       {RESET}")
        print(f" " * 57)
    except Exception as e:
        print(f"[snapshot] failed: {e}", color=YELLOW)