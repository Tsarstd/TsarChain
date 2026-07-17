$ErrorActionPreference = "Stop"

function Print-Step {
    param([string]$Text)
    Write-Host -ForegroundColor Cyan "==> " -NoNewline
    Write-Host -ForegroundColor Green $Text
}

function Print-Warn {
    param([string]$Text)
    Write-Host -ForegroundColor Yellow "WARNING: $Text"
}

# 1. INSTALL RUST (via rustup)
Print-Step "1/8: Checking/Installing Rust..."
if (!(Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "Rust not found. Downloading and installing via rustup..."
    Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile "rustup-init.exe"
    .\rustup-init.exe -y
    Remove-Item ".\rustup-init.exe" -Force
    $env:Path += ";$env:USERPROFILE\.cargo\bin"
} else {
    Write-Host "Rust is already installed."
}

# 2. INSTALL CMAKE
Print-Step "2/8: Checking/Installing CMake..."
if (!(Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "CMake not found. Installing via winget..."
    winget install -e --id Kitware.CMake --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "CMake is already installed."
}

# 3. INSTALL PYTHON
Print-Step "3/8: Checking/Installing Python..."
if (!(Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Installing Python 3 via winget..."
    # Python 3.12 as a stable default
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} else {
    Write-Host "Python is already installed."
}

# 4. INSTALL WEBSITE REQUIREMENTS ( Frontend & Backend )
Print-Step "4/8: Checking/Installing Node.js & Website Dependencies..."
if (!(Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "npm not found. Installing Node.js via winget..."
    winget install -e --id OpenJS.NodeJS --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

if (Get-Command "npm" -ErrorAction SilentlyContinue) {
    Write-Host "Installing Backend dependencies..."
    Set-Location "src\web\Backend"
    npm install
    Set-Location "..\..\.."

    Write-Host "Installing Frontend dependencies..."
    Set-Location "src\web\Fronted"
    npm install
    Set-Location "..\..\.."
} else {
    Print-Warn "npm is still not available. Please install Node.js manually. Skipping website dependencies."
}

# 5. SETUP VIRTUAL ENVIRONMENT
Print-Step "5/8: Setting up Python Virtual Environment (.venv)..."
if (!(Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Virtual environment created."
} else {
    Write-Host "Virtual environment already exists."
}

# 6. INSTALL MATURIN
Print-Step "6/8: Installing Maturin..."
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip maturin

# 7. INSTALL REQUIREMENTS
Print-Step "7/8: Installing Python Requirements..."
& ".\.venv\Scripts\pip.exe" install -r requirements.txt

# 8. BUILD NATIVE EXTENSION
Print-Step "8/8: Building Native Extension (tsarcore_native)..."
Set-Location "tsarcore_native"
& "..\.venv\Scripts\maturin.exe" develop --release --features parallel
Set-Location ".."

Print-Step "DONE!! Setup is complete."
Write-Host ""
Write-Host -ForegroundColor Yellow "================================================================"
Write-Host -ForegroundColor Green "Graffiti Protocol environment is ready!"
Write-Host "To start running applications, benchmarks, or tests, please"
Write-Host "activate the virtual environment first by running:"
Write-Host ""
Write-Host -ForegroundColor Cyan "    .\.venv\Scripts\activate"
Write-Host ""
Write-Host -ForegroundColor Yellow "================================================================"
