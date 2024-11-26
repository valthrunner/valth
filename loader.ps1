# Define the script directory
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Initialize timestamp and define log file names
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$new_latest_log = "latest_script_$timestamp.log"

# Rename any existing latest_script_<timestamp>.log files to script_<timestamp>.log
Get-ChildItem -Path $scriptDir -Filter 'latest_script_*.log' | ForEach-Object {
    $old_latest_log = $_.Name
    $renamed_log = $old_latest_log -replace 'latest_', ''
    Rename-Item -Path $_.FullName -NewName $renamed_log -ErrorAction SilentlyContinue
}

# Set the current log file as the latest
$logfile = Join-Path $scriptDir $new_latest_log

# Initialize WebClient for faster downloads
$client = New-Object System.Net.WebClient
$client.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")

# Function to log messages
function LogMessage($message) {
    $timestamp = Get-Date -Format '[yyyy-MM-dd HH:mm:ss]'
    $logEntry = "$timestamp $message"
    $logEntry | Out-File -FilePath $logfile -Append
}

LogMessage "Script started"
LogMessage "----------------------------------------"

# Define script title and set initial variables
$script_version = "5.0"
$default_title = "Valthrunner's Script v$script_version"
$debug_mode = 0
$mode = 0
$skipStartCS = $false

# Check if 'run_test' argument is passed
if ($args -contains "run_test") {
    $skipStartCS = $true
    LogMessage "run_test parameter detected: skipping starting CS"
}

[console]::Title = $default_title
LogMessage "Script version: $script_version"
LogMessage "Initial mode: $mode"
LogMessage "Arguments: $($args -join ' ')"

# Set mode based on the argument
$firstArg = $args[0]

switch ($firstArg) {
    'run_debug' {
        $debug_mode = 1
        $mode = 0
        Write-Host "[DEBUG] Running in debug mode" -ForegroundColor Cyan
        Write-Host "[DEBUG] Current directory: $(Get-Location)" -ForegroundColor Cyan
        Write-Host "[DEBUG] Script version: $script_version" -ForegroundColor Cyan
        LogMessage "Debug mode enabled"
        LogMessage "Current directory: $(Get-Location)"
    }
    'run_userperms' {
        $mode = 1
        [console]::Title = "$default_title (with user perms for controller)"
        LogMessage "Running with user permissions mode"
    }
    'run' {
        LogMessage "Run mode selected"
    }
    default {
        if ($firstArg -ne "run_test") {
            LogMessage "No valid run parameter, downloading run.bat"
            $Host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(85,30)
            Write-Host "  Please use run.bat." -ForegroundColor Yellow
            Write-Host "  Downloading run.bat..." -ForegroundColor Yellow
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Attempting to download run.bat" -ForegroundColor Cyan }
            try {
                $runBatPath = Join-Path $scriptDir "run.bat"
                $client.DownloadFile("https://github.com/valthrunner/Valthrun/releases/latest/download/run.bat", $runBatPath)
                LogMessage "run.bat download completed"
                if ($debug_mode -eq 1) { Write-Host "[DEBUG] Download complete." -ForegroundColor Cyan }
                # Call run.bat
                Start-Process "cmd.exe" -ArgumentList "/c `"$runBatPath`"" -Verb RunAs
                exit
            } catch {
                Write-Host "  Failed to download run.bat." -ForegroundColor Red
                LogMessage "ERROR: Failed to download run.bat - $_"
                exit 1
            }
        }
    }
}

# Display ASCII art header
function DisplayHeader {
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Displaying header" -ForegroundColor Cyan }
    LogMessage "Displaying header"

    Write-Host
    Write-Host "  _   __     ____  __                              /       ____        _      __" -ForegroundColor White
    Write-Host " | | / /__ _/ / /_/ /  ______ _____  ___  ___ ____  ___   / __/_______(_)__  / /_" -ForegroundColor Yellow
    Write-Host " | |/ / _ `' / __/ _ \/ __/ // / _ \/ _ \/ -_) __/ (_-<  _\ \/ __/ __/ / _ \/ __/" -ForegroundColor Green
    Write-Host " |___/\_,_/_/\__/_//_/_/  \_,_/_//_/_//_/\__/_/   /___/ /___/\__/_/ /_/ ___/\__/" -ForegroundColor Red
    Write-Host "                                                                     /_/         " -ForegroundColor Red
}

DisplayHeader

# Download and extract files
function DownloadAndExtractFiles {
    Write-Host
    Write-Host "  Starting download process..." -ForegroundColor White
    LogMessage "Starting download process"
    if ($debug_mode -eq 1) {
        Write-Host "[DEBUG] Starting DownloadAndExtractFiles function" -ForegroundColor Cyan
        Write-Host "[DEBUG] Script directory: $scriptDir" -ForegroundColor Cyan
    }

    # Create a temporary directory for extraction
    $temp_dir = Join-Path -Path $scriptDir -ChildPath "temp_extract"
    LogMessage "Creating temporary directory: $temp_dir"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Creating temporary directory: $temp_dir" -ForegroundColor Cyan }
    if (!(Test-Path $temp_dir)) { New-Item -ItemType Directory -Path $temp_dir | Out-Null }

    # Download controller package
    Write-Host "  Downloading controller package..." -ForegroundColor White
    LogMessage "Downloading controller package"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Downloading controller package from valth.run" -ForegroundColor Cyan }
    try {
        $controllerZipPath = Join-Path $temp_dir "valthrun_cs2.zip"
        $client.DownloadFile("https://valth.run/download/cs2", $controllerZipPath)
        $download_error = 0
    } catch {
        $download_error = 1
    }
    LogMessage "Controller package download completed with error level: $download_error"
    if ($download_error -ne 0) {
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Controller package download failed with error: $download_error" -ForegroundColor Cyan }
        Write-Host "  Download failed: Controller package" -ForegroundColor Red
        Write-Host "  Please check your internet connection and try again." -ForegroundColor Red
        LogMessage "ERROR: Controller package download failed"
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Download driver package
    Write-Host "  Downloading driver package..." -ForegroundColor White
    LogMessage "Downloading driver package"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Downloading driver package from valth.run" -ForegroundColor Cyan }
    try {
        $driverZipPath = Join-Path $temp_dir "valthrun_driver_kernel.zip"
        $client.DownloadFile("https://valth.run/download/driver-kernel", $driverZipPath)
        $download_error = 0
    } catch {
        $download_error = 1
    }
    LogMessage "Driver package download completed with error level: $download_error"
    if ($download_error -ne 0) {
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Driver package download failed with error: $download_error" -ForegroundColor Cyan }
        Write-Host "  Download failed: Driver package" -ForegroundColor Red
        Write-Host "  Please check your internet connection and try again." -ForegroundColor Red
        LogMessage "ERROR: Driver package download failed"
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Verify downloads
    if ($debug_mode -eq 1) {
        Write-Host "[DEBUG] Verifying downloaded files" -ForegroundColor Cyan
        Get-ChildItem -Path $temp_dir | ForEach-Object { Write-Host $_.Name }
    }
    LogMessage "Downloads completed successfully"
    Write-Host "  Downloads completed successfully." -ForegroundColor Green

    # Extract controller package
    Write-Host "  Extracting controller package..." -ForegroundColor White
    LogMessage "Extracting controller package"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Extracting controller package" -ForegroundColor Cyan }
    try {
        Expand-Archive -LiteralPath $controllerZipPath -DestinationPath $temp_dir -Force
        $extract_error = 0
    } catch {
        $extract_error = 1
    }
    LogMessage "Controller extraction completed with error level: $extract_error"
    if ($extract_error -ne 0) {
        if ($debug_mode -eq 1) {
            Write-Host "[DEBUG] Controller extraction failed" -ForegroundColor Cyan
        }
        Write-Host "  Extraction failed: Controller package" -ForegroundColor Red
        Write-Host "  Try running the script as administrator." -ForegroundColor Red
        LogMessage "ERROR: Controller extraction failed"
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Extract driver package
    Write-Host "  Extracting driver package..." -ForegroundColor White
    LogMessage "Extracting driver package"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Extracting driver package" -ForegroundColor Cyan }
    try {
        Expand-Archive -LiteralPath $driverZipPath -DestinationPath $temp_dir -Force
        $extract_error = 0
    } catch {
        $extract_error = 1
    }
    LogMessage "Driver extraction completed with error level: $extract_error"
    if ($extract_error -ne 0) {
        if ($debug_mode -eq 1) {
            Write-Host "[DEBUG] Driver extraction failed" -ForegroundColor Cyan
        }
        Write-Host "  Extraction failed: Driver package" -ForegroundColor Red
        Write-Host "  Try running the script as administrator." -ForegroundColor Red
        LogMessage "ERROR: Driver extraction failed"
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Process files
    Write-Host "  Processing files..." -ForegroundColor White
    LogMessage "Processing extracted files"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Processing extracted files" -ForegroundColor Cyan }

    Push-Location $temp_dir

    # Rename controller
    $controller_found = $false
    Get-ChildItem -Filter 'cs2_overlay_*.exe' | ForEach-Object {
        $controller_found = $true
        LogMessage "Found controller: $($_.Name)"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Found controller: $($_.Name)" -ForegroundColor Cyan }
        try {
            Move-Item -Path $_.FullName -Destination (Join-Path $scriptDir "controller.exe") -Force -ErrorAction Stop | Out-Null
        } catch {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Failed to move controller" -ForegroundColor Cyan }
            Write-Host "  Error: Could not move controller file" -ForegroundColor Red
            LogMessage "ERROR: Failed to move controller file"
            Pop-Location
            Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }

    if (-not $controller_found) {
        Write-Host "  Error: Controller file not found in package" -ForegroundColor Red
        LogMessage "ERROR: Controller file not found in package"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] No controller file found" -ForegroundColor Cyan }
        Pop-Location
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Remove radar files
    Get-ChildItem -Filter '*radar*.exe' | ForEach-Object {
        LogMessage "Removing radar file: $($_.Name)"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Removing radar file: $($_.Name)" -ForegroundColor Cyan }
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # Rename driver
    $driver_found = $false
    Get-ChildItem -Filter 'kernel_driver_*.sys' | ForEach-Object {
        $driver_found = $true
        LogMessage "Found driver: $($_.Name)"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Found driver: $($_.Name)" -ForegroundColor Cyan }
        try {
            Move-Item -Path $_.FullName -Destination (Join-Path $scriptDir "valthrun-driver.sys") -Force -ErrorAction Stop | Out-Null
        } catch {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Failed to move driver" -ForegroundColor Cyan }
            Write-Host "  Error: Could not move driver file" -ForegroundColor Red
            LogMessage "ERROR: Failed to move driver file"
            Pop-Location
            Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }

    if (-not $driver_found) {
        Write-Host "  Error: Driver file not found in package" -ForegroundColor Red
        LogMessage "ERROR: Driver file not found in package"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] No driver file found" -ForegroundColor Cyan }
        Pop-Location
        Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Process interface DLL
    $dll_found = $false
    Get-ChildItem -Filter 'driver_interface_kernel_*.dll' | ForEach-Object {
        $dll_found = $true
        LogMessage "Found interface DLL: $($_.Name)"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Found interface DLL: $($_.Name)" -ForegroundColor Cyan }
        $interface_dll = $_.Name
        try {
            Move-Item -Path $_.FullName -Destination (Join-Path $scriptDir $interface_dll) -Force -ErrorAction Stop | Out-Null
        } catch {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Failed to move interface DLL" -ForegroundColor Cyan }
            Write-Host "  Error: Could not move interface DLL" -ForegroundColor Red
            LogMessage "ERROR: Failed to move interface DLL"
            Pop-Location
            Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }

    if (-not $dll_found) {
        Write-Host "  Warning: Interface DLL not found in package" -ForegroundColor Yellow
        LogMessage "WARNING: Interface DLL not found in package"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] No interface DLL found" -ForegroundColor Cyan }
    }

    Pop-Location

    # Download kdmapper
    Write-Host "  Downloading additional components..." -ForegroundColor White
    LogMessage "Downloading kdmapper"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Downloading kdmapper" -ForegroundColor Cyan }
    DownloadFile "https://github.com/valthrunner/Valthrun/releases/latest/download/kdmapper.exe" "kdmapper.exe"

    # Clean up
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Cleaning up temporary files" -ForegroundColor Cyan }
    LogMessage "Cleaning up temporary files"
    Remove-Item -Path $temp_dir -Recurse -Force -ErrorAction SilentlyContinue

    if ($debug_mode -eq 1) {
        Write-Host "[DEBUG] Final file verification:" -ForegroundColor Cyan
        Get-ChildItem -Path $scriptDir -Filter 'controller.exe','valthrun-driver.sys','kdmapper.exe' | ForEach-Object { Write-Host $_.Name -ForegroundColor Green }
    }
    LogMessage "File extraction and processing completed"

    Write-Host
    Write-Host "  All files downloaded and extracted successfully!" -ForegroundColor Green
}

# Function to download files using WebClient
function DownloadFile($url, $destination) {
    LogMessage "Downloading: $url to $destination"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Downloading: $url to $destination" -ForegroundColor Cyan }
    try {
        $destinationPath = Join-Path $scriptDir $destination
        $client.DownloadFile($url, $destinationPath)
        Write-Host "  Download complete: $destination" -ForegroundColor Green
        LogMessage "Download successful: $destination"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Download successful" -ForegroundColor Cyan }
    } catch {
        Write-Host "  Failed to download: $destination" -ForegroundColor Red
        LogMessage "ERROR: Failed to download: $destination - $_"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Download failed: $_" -ForegroundColor Cyan }
    }
    [console]::Title = $default_title
}

# Map driver
function MapDriver {
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Starting driver mapping process" -ForegroundColor Cyan }
    LogMessage "Starting driver mapping process"
    $file = Join-Path $scriptDir "kdmapper_log.txt"

    Write-Host
    Write-Host "  Excluding kdmapper from Win Defender..." -ForegroundColor White
    LogMessage "Adding Windows Defender exclusion for kdmapper"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Adding Windows Defender exclusion" -ForegroundColor Cyan }
    try {
        Add-MpPreference -ExclusionPath (Join-Path $scriptDir "kdmapper.exe") -ErrorAction SilentlyContinue
    } catch {
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Failed to add exclusion for kdmapper.exe" -ForegroundColor Cyan }
    }

    Write-Host "  Stopping interfering services..." -ForegroundColor White
    LogMessage "Stopping potential interfering services"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Stopping potential interfering services" -ForegroundColor Cyan }
    Write-Host

    # Stop services
    'faceit','vgc','vgk','ESEADriver2' | ForEach-Object {
        try {
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            LogMessage "Stopped service: $_"
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Stopped service: $_" -ForegroundColor Cyan }
        } catch {}
    }

    LogMessage "Running kdmapper"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Running kdmapper" -ForegroundColor Cyan }
    try {
        Start-Process -FilePath (Join-Path $scriptDir "kdmapper.exe") -ArgumentList 'valthrun-driver.sys' -RedirectStandardOutput $file -NoNewWindow -Wait
        $kdmapper_error = 0
    } catch {
        $kdmapper_error = 1
    }
    LogMessage "Kdmapper completed with error level: $kdmapper_error"
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Kdmapper completed with error level: $kdmapper_error" -ForegroundColor Cyan }
    HandleKdmapperErrors

    if (!(Test-Path (Join-Path $scriptDir "vulkan-1.dll"))) { CopyVulkanDLL }
}

# Handle kdmapper errors
function HandleKdmapperErrors {
    # Implement error checking logic as per the batch script
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Checking kdmapper errors" -ForegroundColor Cyan }
    LogMessage "Checking kdmapper errors"

    if (!(Test-Path $file)) {
        Write-Host "  Error: kdmapper_log.txt not found." -ForegroundColor Red
        LogMessage "ERROR: kdmapper_log.txt not found."
        Pause
        exit 1
    }

    $fileContent = Get-Content -Path $file

    if ($fileContent -match "\[+\] success") {
        LogMessage "Driver successfully loaded"
        Write-Host "  Driver successfully loaded, will continue." -ForegroundColor Green
    } elseif ($fileContent -match "0xcf000004") {
        LogMessage "Driver already loaded"
        Write-Host "  Driver already loaded, will continue." -ForegroundColor Green
    } elseif ($fileContent -match "Device\\Nal is already in use") {
        LogMessage "Device in use error, downloading NalFix"
        Write-Host "  Device\\Nal is already in use Error" -ForegroundColor Red
        Write-Host
        Write-Host "  Downloading and running Fix..." -ForegroundColor Yellow
        DownloadFile "https://github.com/VollRagm/NalFix/releases/latest/download/NalFix.exe" "NalFix.exe"
        try {
            Start-Process -FilePath (Join-Path $scriptDir "NalFix.exe") -Wait
            LogMessage "NalFix executed"
        } catch {
            LogMessage "ERROR: Failed to execute NalFix - $_"
        }
        MapDriver
    } elseif ($fileContent -match "0xc0000603") {
        ApplyWin11Fix
    } else {
        # Other errors
        LogMessage "ERROR: KDMapper returned an unknown error"
        Write-Host
        Write-Host "  Error: KDMapper returned an error" -ForegroundColor Red
        Write-Host "  Read the wiki: wiki.valth.run" -ForegroundColor Yellow
        Write-Host "  or join discord.gg/ecKbpAPW5T for help" -ForegroundColor Yellow
        Write-Host
        Write-Host "  KDMapper output:" -ForegroundColor White
        Write-Host $fileContent -ForegroundColor Red
        LogMessage "KDMapper output:"
        $fileContent | Out-File -FilePath $logfile -Append
        Pause
        exit 1
    }
}

# Apply Windows 11 fix
function ApplyWin11Fix {
    $fixCount = 0
    LogMessage "Applying Windows 11 fix"
    Write-Host "  Applying Windows 11 fix (restart required afterwards)" -ForegroundColor White

    # Disable VBS
    $vbsKey = 'HKLM:\System\CurrentControlSet\Control\DeviceGuard'
    try {
        $vbsValue = Get-ItemProperty -Path $vbsKey -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
        if ($vbsValue.EnableVirtualizationBasedSecurity -ne 0) {
            Set-ItemProperty -Path $vbsKey -Name EnableVirtualizationBasedSecurity -Value 0
            $fixCount++
            LogMessage "Disabled VBS"
        }
    } catch {}

    # Disable Hypervisor
    try {
        $currentSetting = (bcdedit /enum '{emssettings}' | Select-String 'hypervisorlaunchtype').ToString()
        if ($currentSetting -notmatch 'off') {
            bcdedit /set hypervisorlaunchtype off | Out-Null
            $fixCount++
            LogMessage "Disabled Hypervisor"
        }
    } catch {}

    # Disable Vulnerable Driver Blocklist
    $ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    try {
        $ciValue = Get-ItemProperty -Path $ciKey -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue
        if ($ciValue.VulnerableDriverBlocklistEnable -ne 0) {
            Set-ItemProperty -Path $ciKey -Name VulnerableDriverBlocklistEnable -Value 0
            $fixCount++
            LogMessage "Disabled Vulnerable Driver Blocklist"
        }
    } catch {}

    if ($fixCount -eq 3) {
        LogMessage "All fixes applied, scheduling system reboot"
        Write-Host
        Write-Host "  System rebooting in 15 Seconds" -ForegroundColor Yellow
        shutdown.exe /r /t 15
    } else {
        LogMessage "Not all fixes could be applied"
        HandleKdmapperErrors
    }
}

# Copy Vulkan DLL if necessary
function CopyVulkanDLL {
    LogMessage "Checking for vulkan-1.dll"
    if (!(Test-Path (Join-Path $scriptDir "vulkan-1.dll"))) {
        $dllName = 'vulkan-1.dll'
        $sourcePaths = @(
            "$env:PROGRAMFILES(X86)\Microsoft\Edge\Application",
            "$env:PROGRAMFILES(X86)\Google\Chrome\Application",
            "$env:PROGRAMFILES(X86)\BraveSoftware\Brave-Browser\Application"
        )

        foreach ($sourcePath in $sourcePaths) {
            LogMessage "Searching for vulkan-1.dll in: $sourcePath"
            $foundFiles = Get-ChildItem -Path $sourcePath -Filter $dllName -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $foundFiles) {
                LogMessage "Found vulkan-1.dll at: $($file.FullName)"
                try {
                    Copy-Item -Path $file.FullName -Destination (Join-Path $scriptDir $dllName) -Force
                    LogMessage "Copied vulkan-1.dll from: $($file.FullName)"
                    break
                } catch {
                    LogMessage "ERROR: Failed to copy vulkan-1.dll from: $($file.FullName) - $_"
                }
            }
        }
    }
}

# Create and run scheduled task
function CreateAndRunTask($taskName, $taskPath) {
    $startIn = $scriptDir
    $userName = $env:USERNAME

    LogMessage "Creating scheduled task: $taskName"
    LogMessage "Task path: $taskPath"
    LogMessage "Working directory: $startIn"
    LogMessage "User name: $userName"

    try {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(1)
        $action = New-ScheduledTaskAction -Execute (Join-Path $startIn $taskPath) -WorkingDirectory $startIn
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -User "$env:COMPUTERNAME\$userName" -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        [console]::Title = $default_title
        Start-ScheduledTask -TaskName $taskName
        LogMessage "Started scheduled task: $taskName"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {
        LogMessage "ERROR: Failed to create or run scheduled task: $taskName - $_"
        Write-Host "  ERROR: Could not create or run scheduled task: $taskName" -ForegroundColor Red
    }
}

# Run Valthrun
function RunValthrun {
    if ($debug_mode -eq 1) { Write-Host "[DEBUG] Starting Valthrun launch process" -ForegroundColor Cyan }
    LogMessage "Starting Valthrun launch process"

    $cs2_running = Get-Process -Name 'cs2' -ErrorAction SilentlyContinue
    if ($cs2_running) {
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] CS2 is already running" -ForegroundColor Cyan }
        LogMessage "CS2 is already running"
        Write-Host
        Write-Host "  CS2 is running. Valthrun will load." -ForegroundColor Green
        Write-Host
    } else {
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] Starting CS2" -ForegroundColor Cyan }
        LogMessage "Starting CS2"
        Write-Host
        Write-Host "  CS2 is not running. Starting it..." -ForegroundColor Yellow
        Start-Process 'steam://run/730'
        Write-Host
        Write-Host "  Waiting for CS2 to start..." -ForegroundColor White
        do {
            Start-Sleep -Seconds 1
            $cs2_running = Get-Process -Name 'cs2' -ErrorAction SilentlyContinue
        } until ($cs2_running)
        LogMessage "CS2 has started"
        if ($debug_mode -eq 1) { Write-Host "[DEBUG] CS2 has started" -ForegroundColor Cyan }
        Write-Host
        Write-Host "  Valthrun will now load." -ForegroundColor Green
        Write-Host
        Start-Sleep -Seconds 15
    }

    if ($skipStartCS -eq $false) {
        if ($mode -eq 1) {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Running with user permissions" -ForegroundColor Cyan }
            LogMessage "Running with user permissions"
            CreateAndRunTask "ValthTask" "controller.exe"
        } elseif ($mode -eq 2) {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Running experimental version" -ForegroundColor Cyan }
            LogMessage "Running experimental version"
            CreateAndRunTask "ValthExpTask" "controller_experimental.exe"
            Write-Host "  Running experimental version with Aimbot!" -ForegroundColor Green
            Write-Host
            Write-Host "  BE WARNED YOU SHOULDN'T USE THIS ON YOUR MAIN!" -ForegroundColor Red
            Write-Host
            Write-Host "  Have fun!" -ForegroundColor Green
            Write-Host
        } else {
            if ($debug_mode -eq 1) { Write-Host "[DEBUG] Running standard version" -ForegroundColor Cyan }
            LogMessage "Running standard version"
            Start-Process 'controller.exe'
        }
    } else {
        Write-Host "  Run_test mode: CS will not be started automatically." -ForegroundColor Yellow
        LogMessage "Run_test mode: Skipping starting CS"
    }
}

# Main Execution
DownloadAndExtractFiles
MapDriver
RunValthrun

# Dispose of WebClient
$client.Dispose()

LogMessage "Script execution completed"
LogMessage "----------------------------------------"
Pause
Exit
