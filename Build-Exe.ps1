<#
.SYNOPSIS
    Builds ArpListener.exe from ArpListener.ps1 using PS2EXE.
#>

$ErrorActionPreference = 'Stop'

# 1. Check/Install PS2EXE
if (-not (Get-Module -ListAvailable -Name PS2EXE)) {
    Write-Host "PS2EXE module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name PS2EXE -Scope CurrentUser -Force -SkipPublisherCheck
}

# 2. Define paths
$ScriptPath = Join-Path $PSScriptRoot "ArpListener-GUI.ps1"
$ExePath = Join-Path $PSScriptRoot "ArpListener.exe"
$IconPath = Join-Path $PSScriptRoot "icon.ico" # Optional, if we had one

# 3. Compile
Write-Host "Compiling $ScriptPath to $ExePath..." -ForegroundColor Cyan

$params = @{
    InputFile   = $ScriptPath
    OutputFile  = $ExePath
    Title       = "ARP Listener"
    Description = "Network neighbor discovery tool"
    Version     = "2.1.0.0"
    Company     = "Digital Swiss Partners DSPSA"
    Copyright   = "Digital Swiss Partners DSPSA"
    Product     = "ArpListener"
    noConsole   = $true
}

if (Test-Path $IconPath) {
    $params['IconFile'] = $IconPath
}

Invoke-PS2EXE @params

Write-Host "Build complete: $ExePath" -ForegroundColor Green
