# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import sys
import psutil
import shutil
import platform
import subprocess

from colorama import init

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
    print(f"{ORANGE}{banner}{RESET}{YELLOW}{footer}{RESET}")

init()

# RGB custom
def rgb_color(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def bg_rgb_color(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"


# Text
ORANGE = rgb_color(242, 132, 0)
GREY = rgb_color(245, 246, 244)
YELLOW = rgb_color(232, 215, 59)

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

        print(f"{BOLD}{TXT_HEADER}{BG_HEADER}                      Your Sovereign                     {RESET}")
        print(f"{BOLD}{TXT_HEADER}{BG_HEADER}                      Specifications                     {RESET}")
        print(f"{BOLD}{TXT_INFO}{BG_WHITE}  CPU      {RESET}{BOLD}{TXT_INFO}{BG_GREY} {_cpu_brand()}       {RESET}")
        line_core = f"{BOLD}{TXT_INFO}{BG_GREY}  Cores    {RESET}{BOLD}{TXT_INFO}{BG_WHITE} {phys} phys / {logi} logical                          {RESET}"
        if cores_hint:
            line_core += f"  |  use {cores_hint}"
        print(line_core)
        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur  = f"{(freq.current or 0)/1000:.2f}"
                mx   = f"{(freq.max or 0)/1000:.2f}"
                print(f"{BOLD}{TXT_INFO}{BG_WHITE}  Speed    {RESET}{TXT_INFO}{BOLD}{BG_GREY} {cur} GHz (base ~{base} / boost ~{mx})          {RESET}")
            except Exception:
                pass
        print(f"{BOLD}{TXT_INFO}{BG_GREY}  RAM      {RESET}{BOLD}{TXT_INFO}{BG_WHITE} {_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free                  {RESET}")
        print(f"{BOLD}{TXT_INFO}{BG_WHITE}  Disk     {RESET}{BOLD}{TXT_INFO}{BG_GREY} {_human_bytes(du.free)} free of {_human_bytes(du.total)}                     {RESET}")
        print(f"{BOLD}{TXT_INFO}{BG_GREY}  OS       {RESET}{BOLD}{TXT_INFO}{BG_WHITE} {uname.system} {uname.release} ({uname.machine})                           {RESET}")
        print(f"{BOLD}{TXT_INFO}{BG_WHITE}  Python   {RESET}{BOLD}{TXT_INFO}{BG_GREY} {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}                                       {RESET}")
        print(" " * 57)
    except Exception as e:
        print(f"[snapshot] failed: {e}")

def get_user_input():
    print(" ")
    print(f"{BOLD}{TXT_HEADER}{BG_HEADER}                Your Sovereignty              {RESET}")
    print(f"{BOLD}{TXT_HEADER}{BG_HEADER}                    Identity                  {RESET}")

    # Input address
    while True:
        try:
            address = input(f"{BOLD}{TXT_INFO}{BG_GREY} Miner address {RESET}{BOLD}{TXT_INFO}{BG_WHITE} tsar1 {RESET} ").strip()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY}Your're Inputting: {RESET}{BOLD}{TXT_INFO}{BG_RED} tsar1... {RESET}")
            address = "tsar1..."
            break
        if address and address.lower().startswith("tsar1"):
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY} -------------------------------------------- {RESET}")
            print(f"{BOLD}{TXT_HEADER}{BG_HEADER} {address} {RESET}")
            break
        else:
            print(f"\033[1A\033[2K{BG_WHITE} Error: Address must start with 'tsar1...' {RESET}")
            print(f"{BG_WHITE} Example: tsar1qyourwalletaddresshere {RESET}")

    # Input CPU cores
    print(" ")
    print(f"{BOLD}{TXT_HEADER}{BG_HEADER}       Input Your CPU Power      {RESET}")
    print(f"{BOLD}{BG_HEADER}                                 {RESET}")
    
    total_cores = psutil.cpu_count(logical=True)
    
    while True:
        try:
            cores_input = input(f"{BOLD}{TXT_INFO}{BG_GREY} You Have {RESET}{BOLD}{TXT_INFO}{BG_RED} {total_cores} Power {RESET} ").strip()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY}     You're Using     {RESET}{BOLD}{TXT_INFO}{BG_BLUE}  {cores_input} cores  {RESET}")
            cores = total_cores
            break
        
        if not cores_input:
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY}     You're Using     {RESET}{BOLD}{TXT_INFO}{BG_BLUE}  {cores_input} cores  {RESET}")
            cores = total_cores
            break
        
        try:
            cores = int(cores_input)
            if cores <= 0:
                print(f"\033[1A\033[2K{BG_WHITE} Security needs energy bro, and you know it {RESET}")
                continue
            if cores > total_cores:
                print(f"\033[1A\033[2K{BG_WHITE} Daamn!! Who are you! Elon Musk? {RESET}")
                print(f"{BG_WHITE} Just calm down!, enter between 1 and {total_cores - 1} {RESET}")
                continue
                
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY}     You're Using     {RESET}{BOLD}{TXT_INFO}{BG_BLUE}  {cores_input} cores  {RESET}")
            break
        except ValueError:
            print(f"\033[1A\033[2K{BG_WHITE} Error: Please enter a valid number {RESET}")
    return address, cores

def prompt_rx_full_mem() -> bool:
    print(" ")
    print(f"{BOLD}{TXT_HEADER}{BG_HEADER}               RandomX Memory Perfomance Boost              {RESET}")
    print(f"{BOLD}{TXT_HEADER}{BG_HEADER}                                                            {RESET}")
    print(f"{BOLD}{TXT_INFO}{BG_ORANGE} FULL MEMORY {RESET}{BOLD}{TXT_INFO}{BG_YELLOW} y {RESET}{BOLD}{TXT_INFO}{BG_GREY} RAM Usage will consume 2.5GB -> 7GB        {RESET}")
    print(f"{BOLD}{TXT_INFO}{BG_BLUE} LIGHT MODE  {RESET}{BOLD}{TXT_INFO}{BG_GREEN} N {RESET}{BOLD}{TXT_INFO}{BG_WHITE} RAM Usage will stable in 2.5GB             {RESET}")
    while True:
        try:
            ans = input(f"{BOLD}{TXT_INFO}{BG_GREY} Enable FULL MEMORY ? {RESET} ").strip().lower()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_GREY}Using default: LIGHT MODE (No){RESET}")
            return False
        
        if ans in ("y", "yes", "1"):
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{DIM}{BG_GREY}     Mining Run in >>>>>     {RESET}{BOLD}{TXT_INFO}{BG_ORANGE}          FULL MEMORY          {RESET}")
            return True
        if ans in ("n", "no", "0", ""):
            print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{DIM}{BG_GREY}     Mining Run in >>>>>     {RESET}{BOLD}{TXT_INFO}{BG_BLUE}           LIGHT MODE          {RESET}")
            return False
        
        print(f"\033[1A\033[2K{BOLD}{TXT_INFO}{BG_RED}Invalid input. Please answer y or n.{RESET}")
        print(f"{BOLD}{TXT_INFO}{BG_WHITE} Example: y (Yes) or n (No){RESET}")