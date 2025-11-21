# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import psutil, platform, shutil, platform, shutil, subprocess, sys, os
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


# Background
BG_ORANGE = bg_rgb_color(242, 132, 0)
BG_GREY = bg_rgb_color(179, 189, 193)
BG_WHITE = bg_rgb_color(240, 247, 249)
BG_RED = bg_rgb_color(191, 34, 34)
BG_BLUE = bg_rgb_color(32, 163, 223)
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
        try:
            la = os.getloadavg()  # Unix
            la_str = f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}"
        except Exception:
            la_str = "n/a"

        print(f"{BOLD}{BG_ORANGE}                      Your Sovereign                     {RESET}")
        print(f"{BOLD}{BG_ORANGE}                      Specifications                     {RESET}")
        print(f"{BOLD}{BG_WHITE}  CPU      {RESET}{BOLD}{BG_GREY} {_cpu_brand()}       {RESET}")
        line_core = f"{BOLD}{BG_GREY}  Cores    {RESET}{BOLD}{BG_WHITE} {phys} phys / {logi} logical                          {RESET}"
        if cores_hint:
            line_core += f"  |  use {cores_hint}"
        print(line_core)
        if freq:
            try:
                base = f"{(freq.min or 0)/1000:.2f}"
                cur  = f"{(freq.current or 0)/1000:.2f}"
                mx   = f"{(freq.max or 0)/1000:.2f}"
                print(f"{BOLD}{BG_WHITE}  Speed    {RESET}{BOLD}{BG_GREY} {cur} GHz (base ~{base} / boost ~{mx})          {RESET}")
            except Exception:
                pass
        print(f"{BOLD}{BG_GREY}  RAM      {RESET}{BOLD}{BG_WHITE} {_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free                  {RESET}")
        print(f"{BOLD}{BG_WHITE}  Disk     {RESET}{BOLD}{BG_GREY} {_human_bytes(du.free)} free of {_human_bytes(du.total)}                     {RESET}")
        print(f"{BOLD}{BG_GREY}  OS       {RESET}{BOLD}{BG_WHITE} {uname.system} {uname.release} ({uname.machine})                           {RESET}")
        print(f"{BOLD}{BG_WHITE}  Python   {RESET}{BOLD}{BG_GREY} {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}                                       {RESET}")
        print(f" " * 57)
    except Exception as e:
        print(f"[snapshot] failed: {e}")

def get_user_input():
    print(f" ")
    print(f"{BOLD}{BG_ORANGE}            Input Your Sovereignty            {RESET}")
    print(f"{BOLD}{BG_ORANGE}                    Identity                  {RESET}")

    # Input address
    while True:
        try:
            address = input(f"{BOLD}{BG_GREY} Miner address {RESET}{BOLD}{BG_WHITE} tsar1 {RESET}").strip()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{BG_GREY}Your're Inputting: {RESET}{BOLD}{BG_RED} tsar1... {RESET}")
            address = "tsar1..."
            break
        if address and address.lower().startswith("tsar1"):
            print(f"\033[1A\033[2K{BOLD}{BG_WHITE}                  Your Address                {RESET}")
            print(f"{BOLD}{BG_ORANGE} {address} {RESET}")
            break
        else:
            print(f"\033[1A\033[2K{BG_WHITE} Error: Address must start with 'tsar1...' {RESET}")
            print(f"{BG_WHITE} Example: tsar1qyourwalletaddresshere {RESET}")

    # Input CPU cores
    print(f" ")
    print(f"{BOLD}{BG_ORANGE}       Input Your CPU Power      {RESET}")
    print(f"{BOLD}{BG_ORANGE}                                 {RESET}")
    
    total_cores = psutil.cpu_count(logical=True)
    
    while True:
        try:
            cores_input = input(f"{BOLD}{BG_WHITE} You Have {RESET}{BOLD}{BG_RED} {total_cores} Power {RESET}").strip()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{BG_WHITE}     You're Using     {RESET}{BOLD}{BG_BLUE}  {cores_input} cores  {RESET}")
            cores = total_cores
            break
        
        if not cores_input:
            print(f"\033[1A\033[2K{BOLD}{BG_WHITE}     You're Using     {RESET}{BOLD}{BG_BLUE}  {cores_input} cores  {RESET}")
            cores = total_cores
            break
        
        try:
            cores = int(cores_input)
            if cores <= 0:
                print(f"\033[1A\033[2K{BG_WHITE} Error: Cores must be at least 1 {RESET}")
                continue
            if cores > total_cores:
                print(f"\033[1A\033[2K{BG_WHITE} Error: Cores cannot exceed {total_cores} (your total cores) {RESET}")
                print(f"{BG_WHITE} Please enter a number between 1 and {total_cores} {RESET}")
                continue
                
            print(f"\033[1A\033[2K{BOLD}{BG_WHITE}     You're Using     {RESET}{BOLD}{BG_BLUE}  {cores_input} cores  {RESET}")
            break
        except ValueError:
            print(f"\033[1A\033[2K{BG_WHITE} Error: Please enter a valid number {RESET}")
    return address, cores

def prompt_rx_full_mem() -> bool:
    print(" ")
    print(f"{BOLD}{BG_ORANGE}               RandomX Memory Perfomance Boost              {RESET}")
    print(f"{BOLD}{BG_ORANGE}                                                            {RESET}")
    print(f"{BOLD}{BG_ORANGE} FULL MEMORY {RESET}{BOLD}{BG_YELLOW} y {RESET}{BOLD}{BG_GREY} RAM Usage will consume 2.5GB -> 7GB        {RESET}")
    print(f"{BOLD}{BG_BLUE} LIGHT MODE  {RESET}{BOLD}{BG_GREEN} N {RESET}{BOLD}{BG_WHITE} RAM Usage will stable in 2.5GB             {RESET}")
    while True:
        try:
            ans = input(f"{BOLD}{BG_RED} Enable FULL MEMORY ? {RESET} : ").strip().lower()
        except EOFError:
            print(f"\033[1A\033[2K{BOLD}{BG_GREY}Using default: LIGHT MODE (No){RESET}")
            return False
        
        if ans in ("y", "yes", "1"):
            print(f"\033[1A\033[2K{BOLD}{BG_ORANGE}                   Mining Run in FULL MEMORY                {RESET}")
            return True
        if ans in ("n", "no", "0", ""):
            print(f"\033[1A\033[2K{BOLD}{BG_BLUE}                   Mining Run in LIGHT MODE                 {RESET}")
            return False
        
        print(f"\033[1A\033[2K{BOLD}{BG_RED}Invalid input. Please answer y or n.{RESET}")
        print(f"{BOLD}{BG_WHITE} Example: y (Yes) or n (No){RESET}")