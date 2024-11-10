# Valthrun PowerShell Launcher Script
# Version: 1.0.0
# PowerShell 5.1 Compatible

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Script initialization
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Constants
$SCRIPT_VERSION = "1.0.0"
$API_BASE_URL = "https://valth.run"
$KDMAPPER_URL = "https://github.com/valthrunner/Valthrun/releases/latest/download/kdmapper.exe"
$LOG_FILE = "valthrun_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$DEBUG_MODE = $false

# ASCII Art with colors
$ASCII_HEADER = @"
  `e[97m_   __     ____  __                              `e[31m/`e[97m       ____        _      __ 
`e[93m | | / /__ _/ / /_/ /  ______ _____  ___  ___ ____  ___   / __/_______(_)__  / /_
`e[33m | |/ / _ ``/ / __/ _ \/ __/ // / _ \/ _ \/ -_) __/ (_-<  _\ \/ __/ __/ / _ \/ __/
`e[31m |___/\_,_/_/\__/_//_/_/  \_,_/_//_/_//_/\__/_/   /___/ /___/\__/_/ /_/ ___/\__/ `e[0m
"@

# Error codes and messages
$ERROR_CODES = @{
    "0x00000000" = "Success"
    "0xc0000603" = "STATUS_IMAGE_CERT_REVOKED - Disable MSFT Driver Block List"
    "0xCF000001" = "Valthrun logging system initialization failed"
    "0xCF000002" = "Valthrun Kernel Driver setup failed"
    "0xCF000003" = "Valthrun Kernel Driver initialization failed"
    "0xCF000004" = "Valthrun Kernel Driver already loaded"
}

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LOG_FILE -Value $logMessage
    
    if ($DEBUG_MODE -or $Level -ne 'Debug') {
        switch ($Level) {
            'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
            'Error' { Write-Host $logMessage -ForegroundColor Red }
            'Debug' { Write-Host $logMessage -ForegroundColor Cyan }
            default { Write-Host $logMessage }
        }
    }
}

# Display ASCII header
function Show-Header {
    Write-Host $ASCII_HEADER
    Write-Host "Valthrun Launcher v$SCRIPT_VERSION" -ForegroundColor Cyan
    Write-Host "----------------------------------------`n"
}

# API interaction functions
function Get-ValthrungArtifacts {
    try {
        $response = Invoke-RestMethod -Uri "$API_BASE_URL/api/artifacts" -Method Get
        return $response
    }
    catch {
        Write-Log "Failed to fetch artifacts: $_" -Level Error
        throw
    }
}

function Get-ArtifactVersions {
    param(
        [string]$ArtifactId,
        [string]$TrackId
    )
    
    try {
        $response = Invoke-RestMethod -Uri "$API_BASE_URL/api/artifacts/$ArtifactId/$TrackId" -Method Get
        return $response
    }
    catch {
        Write-Log "Failed to fetch versions for artifact $ArtifactId: $_" -Level Error
        throw
    }
}

function Get-LatestVersion {
    param(
        [string]$ArtifactId,
        [string]$TrackId,
        [ValidateSet('stable', 'nightly')]
        [string]$Channel = 'stable'
    )
    
    $versions = Get-ArtifactVersions -ArtifactId $ArtifactId -TrackId $TrackId
    
    if ($Channel -eq 'stable') {
        return $versions | Where-Object { !$_.prerelease } | Select-Object -First 1
    }
    else {
        return $versions | Select-Object -First 1
    }
}

function Download-Artifact {
    param(
        [string]$ArtifactId,
        [string]$TrackId,
        [string]$VersionId,
        [string]$OutputPath
    )
    
    try {
        $downloadUrl = "$API_BASE_URL/api/artifacts/$ArtifactId/$TrackId/$VersionId/download"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $OutputPath
        Write-Log "Downloaded artifact to $OutputPath" -Level Info
    }
    catch {
        Write-Log "Failed to download artifact: $_" -Level Error
        throw
    }
}

# Environment preparation
function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level Info
    
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Script must be run as administrator" -Level Error
        throw "Administrator privileges required"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Log "Windows Version: $($osVersion.Major).$($osVersion.Minor)" -Level Info
}

# Driver mapping and error handling
function Map-Driver {
    param(
        [string]$DriverPath
    )
    
    Write-Log "Mapping driver: $DriverPath" -Level Info
    
    # Stop potentially interfering services
    $services = @('faceit', 'vgc', 'vgk', 'ESEADriver2')
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Write-Log "Stopped service: $service" -Level Debug
    }
    
    # Run kdmapper
    $output = & .\kdmapper.exe $DriverPath 2>&1
    $exitCode = $LASTEXITCODE
    
    Write-Log "KDMapper output: $output" -Level Debug
    Write-Log "KDMapper exit code: $exitCode" -Level Debug
    
    # Handle known error codes
    switch ($exitCode) {
        0 { Write-Log "Driver mapped successfully" -Level Info }
        0xcf000004 { Write-Log "Driver already loaded" -Level Warning }
        0xc0000603 { 
            Write-Log "Driver certification issue - applying fixes" -Level Warning
            Apply-Windows11Fix
        }
        default {
            Write-Log "Unknown error mapping driver: $exitCode" -Level Error
            throw "Driver mapping failed"
        }
    }
}

# Main execution flow
function Start-Valthrun {
    try {
        Show-Header
        Test-Prerequisites
        
        # Get channel preference
        $channel = Read-Host "Select channel (stable/nightly)"
        if ($channel -notmatch '^(stable|nightly)$') {
            $channel = 'stable'
        }
        
        Write-Log "Selected channel: $channel" -Level Info
        
        # Download and setup components
        $artifacts = Get-ValthrungArtifacts
        
        # Download required components
        $components = @{
            'controller' = $artifacts | Where-Object { $_.slug -eq 'cs2-overlay' }
            'driver' = $artifacts | Where-Object { $_.slug -eq 'kernel-driver' }
            'interface' = $artifacts | Where-Object { $_.slug -eq 'driver-interface-kernel' }
        }
        
        foreach ($key in $components.Keys) {
            $artifact = $components[$key]
            $version = Get-LatestVersion -ArtifactId $artifact.id -TrackId $artifact.defaultTrack -Channel $channel
            
            Write-Log "Downloading $key component version $($version.version)" -Level Info
            Download-Artifact -ArtifactId $artifact.id -TrackId $artifact.defaultTrack -VersionId $version.id -OutputPath "valthrun-$key"
        }
        
        # Map driver and start controller
        Map-Driver -DriverPath "valthrun-driver"
        Start-Process "valthrun-controller"
        
        Write-Log "Valthrun started successfully" -Level Info
    }
    catch {
        Write-Log "Fatal error: $_" -Level Error
        throw
    }
}

# Entry point
try {
    Start-Valthrun
}
catch {
    Write-Host "`nFatal error occurred. Check $LOG_FILE for details." -ForegroundColor Red
    Write-Host "Please report this issue on Discord: discord.gg/ecKbpAPW5T" -ForegroundColor Yellow
    exit 1
}
