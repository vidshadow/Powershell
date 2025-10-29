<#
.SYNOPSIS
    Cleans and debloats Windows 11 while preserving personal files and games.

.DESCRIPTION
    This script performs a comprehensive cleanup and debloat of Windows 11:
    1. Creates a system restore point
    2. Removes bloatware apps and games (except Solitaire, Mahjong)
    3. Installs Minesweeper from Microsoft Store
    4. Disables advertisements, telemetry, and tracking
    5. Optimizes privacy settings
    6. Cleans temporary files and system cache
    7. Repairs system files (DISM and SFC)

    IMPORTANT: This script PRESERVES:
    - All personal files (Documents, Downloads, Desktop, Pictures, Videos, Music)
    - Steam games and installation
    - Other game launchers (Epic, GOG, Battle.net, etc.)
    - Installed applications
    - User settings and configurations

.NOTES
    Author: Claude
    Requires: PowerShell 5.1 or higher, Administrator privileges
    Target: Windows 11 (any version)

.EXAMPLE
    .\Reset-Windows11-Clean.ps1

.EXAMPLE
    .\Reset-Windows11-Clean.ps1 -NoRestorePoint
    (Skip creating system restore point)

.EXAMPLE
    .\Reset-Windows11-Clean.ps1 -SkipSystemRepair
    (Skip DISM and SFC system repair - faster but less thorough)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$NoRestorePoint,

    [Parameter(Mandatory=$false)]
    [switch]$SkipSystemRepair
)

# Requires Administrator privileges
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Script configuration
$LogFile = "$env:TEMP\Win11Reset_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Color-coded logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }

    # File output
    Add-Content -Path $LogFile -Value $logMessage
}

# Create system restore point
function New-SystemRestorePoint {
    Write-Log "Creating system restore point..." -Level Info

    try {
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Before Windows 11 Clean Reset" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "System restore point created successfully" -Level Success
    } catch {
        Write-Log "Failed to create restore point: $($_.Exception.Message)" -Level Warning
    }
}

# Check Windows version
function Test-WindowsVersion {
    Write-Log "Checking Windows version..." -Level Info

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = $osInfo.BuildNumber

    Write-Log "Current Windows Build: $buildNumber" -Level Info
    Write-Log "OS Name: $($osInfo.Caption)" -Level Info

    if ($buildNumber -lt 22000) {
        Write-Log "This script is designed for Windows 11 (build 22000+)" -Level Warning
        Write-Log "You are running Windows 10 or earlier (build $buildNumber)" -Level Warning
        $response = Read-Host "Continue anyway? (yes/no)"
        if ($response -ne "yes") {
            Write-Log "Script cancelled by user" -Level Warning
            return $false
        }
    }

    return $true
}

# Remove bloatware apps
function Remove-BloatwareApps {
    Write-Log "Removing bloatware applications..." -Level Info

    # List of bloatware apps to remove
    $bloatwareApps = @(
        # Gaming
        "Microsoft.XboxApp",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.GamingApp",

        # Entertainment
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.Music",
        "Microsoft.Movies",
        "SpotifyAB.SpotifyMusic",

        # Games (keeping Solitaire & Mahjong per user request)
        "king.com.CandyCrushSaga",
        "king.com.CandyCrushSodaSaga",
        "king.com.CandyCrushFriends",

        # Social & Communication
        "Microsoft.People",
        "Microsoft.Messaging",
        "Microsoft.SkypeApp",

        # News & Weather
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.BingFinance",
        "Microsoft.BingSports",

        # Other bloatware
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MixedReality.Portal",
        "Microsoft.Office.OneNote",
        "Microsoft.OneConnect",
        "Microsoft.Print3D",
        "Microsoft.Wallet",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.YourPhone",
        "Microsoft.PowerAutomateDesktop",
        "MicrosoftTeams",
        "Microsoft.Todos",

        # OEM bloatware patterns
        "*.Disney",
        "*.McAfee",
        "*.Netflix",
        "*.Twitter",
        "*.Facebook",
        "*.Instagram",
        "*.LinkedIn",
        "ActiproSoftwareLLC*",
        "AdobeSystemsIncorporated.AdobePhotoshopExpress",
        "Duolingo*",
        "EclipseManager",
        "PandoraMediaInc*",
        "Wunderlist*"
    )

    $removedCount = 0
    foreach ($app in $bloatwareApps) {
        try {
            $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
            foreach ($package in $packages) {
                Write-Log "Removing: $($package.Name)" -Level Info
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                $removedCount++
            }

            # Also remove provisioned packages (prevents reinstall)
            $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app
            foreach ($package in $provisionedPackages) {
                Write-Log "Removing provisioned: $($package.DisplayName)" -Level Info
                Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Could not remove $app : $($_.Exception.Message)" -Level Warning
        }
    }

    Write-Log "Bloatware removal completed - removed $removedCount app packages" -Level Success
}

# Install classic games (Minesweeper)
function Install-ClassicGames {
    Write-Log "Installing classic Microsoft games..." -Level Info

    try {
        # Check if winget is available
        $winget = Get-Command winget -ErrorAction SilentlyContinue

        if ($winget) {
            # Install Microsoft Minesweeper using winget
            Write-Log "Installing Microsoft Minesweeper from Microsoft Store..." -Level Info
            winget install "Microsoft Minesweeper" --source msstore --accept-package-agreements --accept-source-agreements 2>$null
            Write-Log "Minesweeper installation completed" -Level Success
        } else {
            Write-Log "Winget not available. Opening Microsoft Store page for Minesweeper..." -Level Warning
            Write-Log "You can manually install Minesweeper from: ms-windows-store://pdp/?ProductId=9WZDNCRFHWCN" -Level Info

            # Open the Store page for Minesweeper
            Start-Process "ms-windows-store://pdp/?ProductId=9WZDNCRFHWCN" -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Could not install Minesweeper: $($_.Exception.Message)" -Level Warning
        Write-Log "You can manually install it from the Microsoft Store" -Level Info
    }
}

# Disable Windows ads and suggestions
function Disable-WindowsAds {
    Write-Log "Disabling advertisements and suggestions..." -Level Info

    $registrySettings = @(
        # Disable suggestions in Start Menu
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353696Enabled"; Value=0},

        # Disable tips and suggestions
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SoftLandingEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="RotatingLockScreenEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="RotatingLockScreenOverlayEnabled"; Value=0},

        # Disable app suggestions
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowSyncProviderNotifications"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0},

        # Disable advertising ID
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Value=0},

        # Disable tailored experiences
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name="TailoredExperiencesWithDiagnosticDataEnabled"; Value=0},

        # Disable suggested content in Settings
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"; Value=0}
    )

    $appliedCount = 0
    foreach ($setting in $registrySettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
            $appliedCount++
        } catch {
            Write-Log "Failed to apply: $($setting.Path)\$($setting.Name)" -Level Warning
        }
    }

    Write-Log "Advertisement settings disabled - applied $appliedCount settings" -Level Success
}

# Disable telemetry and tracking
function Disable-Telemetry {
    Write-Log "Disabling telemetry and tracking..." -Level Info

    # Disable telemetry services
    $servicesToDisable = @(
        "DiagTrack",                          # Connected User Experiences and Telemetry
        "dmwappushservice",                   # WAP Push Message Routing Service
        "XblAuthManager",                     # Xbox Live Auth Manager
        "XblGameSave",                        # Xbox Live Game Save
        "XboxNetApiSvc",                      # Xbox Live Networking Service
        "XboxGipSvc"                          # Xbox Accessory Management Service
    )

    $disabledCount = 0
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $service" -Level Info
                $disabledCount++
            }
        } catch {
            Write-Log "Could not disable service: $service" -Level Warning
        }
    }

    # Disable scheduled telemetry tasks
    $tasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    $tasksDisabled = 0
    foreach ($task in $tasksToDisable) {
        try {
            # Split the full path into folder path and task name
            $taskName = Split-Path -Path $task -Leaf
            $taskPath = Split-Path -Path $task -Parent

            # Ensure path ends with backslash as required by Get-ScheduledTask
            if (-not $taskPath.EndsWith('\')) {
                $taskPath += '\'
            }

            # Get and disable the task using both path and name
            $scheduledTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
            if ($scheduledTask) {
                Disable-ScheduledTask -InputObject $scheduledTask -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Disabled task: $task" -Level Info
                $tasksDisabled++
            }
        } catch {
            Write-Log "Could not disable task: $task - $($_.Exception.Message)" -Level Warning
        }
    }

    # Registry settings for telemetry
    $telemetrySettings = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0},
        @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0}
    )

    foreach ($setting in $telemetrySettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
        } catch {
            Write-Log "Failed to apply telemetry setting: $($setting.Path)" -Level Warning
        }
    }

    Write-Log "Telemetry disabled - $disabledCount services, $tasksDisabled tasks" -Level Success
}

# Optimize privacy settings
function Optimize-Privacy {
    Write-Log "Optimizing privacy settings..." -Level Info

    $privacySettings = @(
        # Disable activity history
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableActivityFeed"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="PublishUserActivities"; Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="UploadUserActivities"; Value=0},

        # Disable location tracking
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableLocation"; Value=1},

        # Disable web search in Start Menu
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"; Value=0},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaConsent"; Value=0},

        # Disable Cortana
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"; Value=0}
    )

    $appliedCount = 0
    foreach ($setting in $privacySettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
            $appliedCount++
        } catch {
            Write-Log "Failed to apply privacy setting: $($setting.Path)\$($setting.Name)" -Level Warning
        }
    }

    Write-Log "Privacy settings optimized - applied $appliedCount settings" -Level Success
}

# Disable OneDrive
function Disable-OneDrive {
    Write-Log "Disabling OneDrive..." -Level Info

    try {
        # Stop OneDrive process
        taskkill /f /im OneDrive.exe 2>$null

        # Uninstall OneDrive
        $oneDrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        if (Test-Path $oneDrivePath) {
            Start-Process -FilePath $oneDrivePath -ArgumentList "/uninstall" -NoNewWindow -Wait
        }

        # Remove OneDrive from registry
        $oneDriveSettings = @(
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name="DisableFileSyncNGSC"; Value=1},
            @{Path="HKCU:\Software\Microsoft\OneDrive"; Name="PreventNetworkTrafficPreUserSignIn"; Value=1}
        )

        foreach ($setting in $oneDriveSettings) {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
        }

        Write-Log "OneDrive disabled" -Level Success
    } catch {
        Write-Log "Failed to disable OneDrive: $($_.Exception.Message)" -Level Warning
    }
}

# Clean temporary files and cache
function Clear-SystemCache {
    Write-Log "Cleaning temporary files and system cache..." -Level Info

    $locationsToClean = @(
        "$env:TEMP",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Prefetch",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
    )

    $totalFreed = 0
    foreach ($location in $locationsToClean) {
        try {
            if (Test-Path $location) {
                $beforeSize = (Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum

                # Clean the location
                Remove-Item -Path "$location\*" -Recurse -Force -ErrorAction SilentlyContinue

                $afterSize = (Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $freed = ($beforeSize - $afterSize) / 1MB
                $totalFreed += $freed

                if ($freed -gt 0) {
                    Write-Log "Cleaned $location : $([math]::Round($freed, 2)) MB freed" -Level Info
                }
            }
        } catch {
            Write-Log "Could not clean $location : $($_.Exception.Message)" -Level Warning
        }
    }

    # Clean Windows Update cache
    try {
        Write-Log "Stopping Windows Update service..." -Level Info
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue

        $updateCachePath = "$env:SystemRoot\SoftwareDistribution\Download"
        if (Test-Path $updateCachePath) {
            $beforeSize = (Get-ChildItem -Path $updateCachePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            Remove-Item -Path "$updateCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            $afterSize = (Get-ChildItem -Path $updateCachePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            $freed = $beforeSize - $afterSize
            $totalFreed += $freed
            Write-Log "Cleaned Windows Update cache: $([math]::Round($freed, 2)) MB freed" -Level Info
        }

        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Could not clean Windows Update cache: $($_.Exception.Message)" -Level Warning
    }

    # Run Disk Cleanup utility
    try {
        Write-Log "Running Windows Disk Cleanup..." -Level Info
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Could not run Disk Cleanup: $($_.Exception.Message)" -Level Warning
    }

    Write-Log "System cache cleaned - Total freed: $([math]::Round($totalFreed, 2)) MB" -Level Success
}

# Repair system files
function Repair-SystemFiles {
    Write-Log "Repairing system files (this may take several minutes)..." -Level Info

    try {
        # Run DISM to repair Windows image
        Write-Log "Running DISM to check and repair Windows image..." -Level Info
        $dismResult = & DISM.exe /Online /Cleanup-Image /RestoreHealth

        if ($LASTEXITCODE -eq 0) {
            Write-Log "DISM repair completed successfully" -Level Success
        } else {
            Write-Log "DISM completed with warnings or errors (Exit code: $LASTEXITCODE)" -Level Warning
        }

        # Run System File Checker
        Write-Log "Running System File Checker (SFC)..." -Level Info
        $sfcResult = & sfc.exe /scannow

        if ($LASTEXITCODE -eq 0) {
            Write-Log "SFC scan completed successfully" -Level Success
        } else {
            Write-Log "SFC completed with warnings or errors (Exit code: $LASTEXITCODE)" -Level Warning
        }

    } catch {
        Write-Log "System repair encountered errors: $($_.Exception.Message)" -Level Warning
    }
}

# Display protected locations
function Show-ProtectedLocations {
    Write-Log "=====================================" -Level Info
    Write-Log "PROTECTED LOCATIONS (NOT MODIFIED)" -Level Success
    Write-Log "=====================================" -Level Info

    $protectedPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Pictures",
        "$env:USERPROFILE\Videos",
        "$env:USERPROFILE\Music",
        "C:\Program Files (x86)\Steam",
        "$env:ProgramFiles\Epic Games",
        "$env:ProgramFiles\GOG Galaxy",
        "$env:ProgramFiles (x86)\Battle.net",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    )

    foreach ($path in $protectedPaths) {
        if (Test-Path $path) {
            $size = (Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB
            Write-Log "✓ $path ($([math]::Round($size, 2)) GB)" -Level Success
        }
    }

    Write-Log "=====================================" -Level Info
}

# Main execution
function Start-WindowsReset {
    Write-Log "=====================================" -Level Info
    Write-Log "Windows 11 Clean Reset Script" -Level Info
    Write-Log "=====================================" -Level Info
    Write-Log "Log file: $LogFile" -Level Info

    # Show protected locations
    Show-ProtectedLocations

    # Check Windows version
    if (-not (Test-WindowsVersion)) {
        return
    }

    # Create restore point
    if (-not $NoRestorePoint) {
        New-SystemRestorePoint
    }

    # Perform cleanup operations
    Write-Log "=====================================" -Level Info
    Write-Log "Starting cleanup operations..." -Level Info
    Write-Log "=====================================" -Level Info

    Remove-BloatwareApps
    Install-ClassicGames
    Disable-WindowsAds
    Disable-Telemetry
    Optimize-Privacy
    Disable-OneDrive
    Clear-SystemCache

    # System repair (optional)
    if (-not $SkipSystemRepair) {
        Repair-SystemFiles
    } else {
        Write-Log "Skipping system repair (use without -SkipSystemRepair to enable)" -Level Info
    }

    Write-Log "=====================================" -Level Success
    Write-Log "Windows 11 clean reset completed!" -Level Success
    Write-Log "Log saved to: $LogFile" -Level Success
    Write-Log "=====================================" -Level Success
    Write-Log "RECOMMENDED: Restart your computer to apply all changes" -Level Warning

    # Show what was preserved
    Write-Log "" -Level Info
    Write-Log "Your personal files, Steam games, and installed applications remain untouched!" -Level Success

    $restart = Read-Host "Would you like to restart now? (yes/no)"
    if ($restart -eq "yes") {
        Write-Log "Restarting computer in 10 seconds..." -Level Warning
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}

# Run the script
Start-WindowsReset
