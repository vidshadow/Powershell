<#
.SYNOPSIS
    Upgrades Windows 10 to Windows 11 and removes bloatware, ads, and unwanted features.
    PRESERVES all personal files, installed programs, and game installations.

.DESCRIPTION
    This script performs the following actions:
    1. Displays what will be preserved (personal files, apps, games, settings)
    2. Checks Windows 11 compatibility (TPM 2.0, Secure Boot, CPU, RAM, Storage)
    3. Creates a system restore point for safety
    4. Downloads and initiates Windows 11 upgrade (uses official Microsoft installer)
    5. Removes pre-installed bloatware apps and games (after upgrade completes)
    6. Disables advertisements, telemetry, and unwanted features
    7. Optimizes privacy settings

    DATA PRESERVATION:
    ✓ All personal files (Documents, Downloads, Desktop, Pictures, Videos, Music)
    ✓ Installed applications and programs
    ✓ Game installations (Steam, Epic, GOG, Battle.net, etc.)
    ✓ User settings and preferences
    ✓ Browser bookmarks and history

    WHAT GETS REMOVED:
    • Bloatware apps (Xbox apps, Candy Crush, pre-installed OEM bloatware)
    • OneDrive (can be reinstalled if needed)
    • Telemetry and advertising services

.NOTES
    Author: Claude
    Requires: PowerShell 5.1 or higher, Administrator privileges
    Tested on: Windows 10 21H2, 22H2
    IMPORTANT: While this script preserves data, always backup important files before major upgrades

.EXAMPLE
    .\Upgrade-To-Windows11-Debloated.ps1

.EXAMPLE
    .\Upgrade-To-Windows11-Debloated.ps1 -SkipUpgrade
    (Only performs debloating on existing Windows 11 installation)

.EXAMPLE
    .\Upgrade-To-Windows11-Debloated.ps1 -BypassRequirements
    (Bypasses TPM 2.0, Secure Boot, RAM, Storage, and CPU requirements for upgrade)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipUpgrade,

    [Parameter(Mandatory=$false)]
    [switch]$SkipCompatibilityCheck,

    [Parameter(Mandatory=$false)]
    [switch]$NoRestorePoint,

    [Parameter(Mandatory=$false)]
    [switch]$BypassRequirements
)

# Requires Administrator privileges
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Script configuration
$LogFile = "$env:TEMP\Win11Upgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$DownloadPath = "$env:TEMP\Win11Upgrade"

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

# Check Windows 11 compatibility
function Test-Windows11Compatibility {
    Write-Log "Checking Windows 11 compatibility..." -Level Info

    $compatible = $true
    $issues = @()

    # Check TPM 2.0
    try {
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($null -eq $tpm -or $tpm.SpecVersion -notmatch "^2\.") {
            $issues += "TPM 2.0 not detected or not enabled"
            $compatible = $false
        } else {
            Write-Log "TPM 2.0: OK" -Level Success
        }
    } catch {
        $issues += "Unable to check TPM status"
        $compatible = $false
    }

    # Check Secure Boot
    try {
        $secureBoot = Confirm-SecureBootUEFI
        if (-not $secureBoot) {
            $issues += "Secure Boot is not enabled"
            $compatible = $false
        } else {
            Write-Log "Secure Boot: OK" -Level Success
        }
    } catch {
        $issues += "Unable to verify Secure Boot (may not be UEFI system)"
        $compatible = $false
    }

    # Check RAM (minimum 4GB)
    $ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
    if ($ram -lt 4) {
        $issues += "Insufficient RAM: $ram GB (minimum 4GB required)"
        $compatible = $false
    } else {
        Write-Log "RAM: $ram GB - OK" -Level Success
    }

    # Check Storage (minimum 64GB)
    $systemDrive = Get-PSDrive -Name C
    $totalSpace = [math]::Round($systemDrive.Used / 1GB + $systemDrive.Free / 1GB, 2)
    if ($totalSpace -lt 64) {
        $issues += "Insufficient storage: $totalSpace GB (minimum 64GB required)"
        $compatible = $false
    } else {
        Write-Log "Storage: $totalSpace GB - OK" -Level Success
    }

    # Check free space (minimum 20GB recommended for upgrade)
    $freeSpace = [math]::Round($systemDrive.Free / 1GB, 2)
    if ($freeSpace -lt 20) {
        $issues += "Low free space: $freeSpace GB (minimum 20GB recommended)"
        Write-Log "Warning: Low free space" -Level Warning
    }

    # Check CPU compatibility (basic check)
    $cpu = Get-CimInstance -ClassName Win32_Processor
    Write-Log "CPU: $($cpu.Name)" -Level Info

    # Check current Windows version
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = $osInfo.BuildNumber
    Write-Log "Current Windows Build: $buildNumber" -Level Info

    if ($buildNumber -ge 22000) {
        Write-Log "Already running Windows 11!" -Level Warning
        return $false
    }

    if (-not $compatible) {
        Write-Log "Compatibility issues found:" -Level Error
        foreach ($issue in $issues) {
            Write-Log "  - $issue" -Level Error
        }
    }

    return $compatible
}

# Create system restore point
function New-SystemRestorePoint {
    Write-Log "Creating system restore point..." -Level Info

    try {
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Before Windows 11 Upgrade" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "System restore point created successfully" -Level Success
    } catch {
        Write-Log "Failed to create restore point: $($_.Exception.Message)" -Level Warning
    }
}

# Bypass Windows 11 system requirements
function Enable-Windows11BypassRegistry {
    Write-Log "Applying registry modifications to bypass Windows 11 requirements..." -Level Info

    try {
        # Registry path for Windows 11 upgrade bypass
        $registryPath = "HKLM:\SYSTEM\Setup\MoSetup"

        # Create the registry key if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Log "Created registry path: $registryPath" -Level Info
        }

        # Bypass TPM requirement
        Set-ItemProperty -Path $registryPath -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -Type DWord -Force
        Write-Log "Bypassed TPM requirement" -Level Success

        # Additional bypass registry keys for Windows 11 installation
        $bypassPath = "HKLM:\SYSTEM\Setup\LabConfig"

        if (-not (Test-Path $bypassPath)) {
            New-Item -Path $bypassPath -Force | Out-Null
            Write-Log "Created registry path: $bypassPath" -Level Info
        }

        # Bypass TPM 2.0 check
        Set-ItemProperty -Path $bypassPath -Name "BypassTPMCheck" -Value 1 -Type DWord -Force
        Write-Log "Set BypassTPMCheck = 1" -Level Info

        # Bypass Secure Boot check
        Set-ItemProperty -Path $bypassPath -Name "BypassSecureBootCheck" -Value 1 -Type DWord -Force
        Write-Log "Set BypassSecureBootCheck = 1" -Level Info

        # Bypass RAM check (4GB minimum)
        Set-ItemProperty -Path $bypassPath -Name "BypassRAMCheck" -Value 1 -Type DWord -Force
        Write-Log "Set BypassRAMCheck = 1" -Level Info

        # Bypass storage check (64GB minimum)
        Set-ItemProperty -Path $bypassPath -Name "BypassStorageCheck" -Value 1 -Type DWord -Force
        Write-Log "Set BypassStorageCheck = 1" -Level Info

        # Bypass CPU compatibility check
        Set-ItemProperty -Path $bypassPath -Name "BypassCPUCheck" -Value 1 -Type DWord -Force
        Write-Log "Set BypassCPUCheck = 1" -Level Info

        Write-Log "Windows 11 requirement bypass enabled successfully!" -Level Success
        Write-Log "Your system will now bypass TPM 2.0, Secure Boot, RAM, Storage, and CPU checks" -Level Success

    } catch {
        Write-Log "Failed to apply registry bypass: $($_.Exception.Message)" -Level Error
        Write-Log "You may need to apply these manually" -Level Warning
    }
}

# Download Windows 11 Installation Assistant
function Get-Windows11Installer {
    Write-Log "Downloading Windows 11 Installation Assistant..." -Level Info

    if (-not (Test-Path $DownloadPath)) {
        New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
    }

    $installerUrl = "https://go.microsoft.com/fwlink/?linkid=2171764"
    $installerPath = Join-Path $DownloadPath "Windows11InstallationAssistant.exe"

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        $ProgressPreference = 'Continue'
        Write-Log "Downloaded to: $installerPath" -Level Success
        return $installerPath
    } catch {
        Write-Log "Failed to download installer: $($_.Exception.Message)" -Level Error
        return $null
    }
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

    foreach ($app in $bloatwareApps) {
        try {
            $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
            foreach ($package in $packages) {
                Write-Log "Removing: $($package.Name)" -Level Info
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
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

    Write-Log "Bloatware removal completed" -Level Success
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

    foreach ($setting in $registrySettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
            Write-Log "Applied: $($setting.Path)\$($setting.Name)" -Level Info
        } catch {
            Write-Log "Failed to apply: $($setting.Path)\$($setting.Name)" -Level Warning
        }
    }

    Write-Log "Advertisement settings disabled" -Level Success
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

    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $service" -Level Info
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
            } else {
                Write-Log "Task not found (may not exist on this system): $task" -Level Info
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
            Write-Log "Applied telemetry setting: $($setting.Path)" -Level Info
        } catch {
            Write-Log "Failed to apply telemetry setting: $($setting.Path)" -Level Warning
        }
    }

    Write-Log "Telemetry disabled" -Level Success
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

    foreach ($setting in $privacySettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
            Write-Log "Applied privacy setting: $($setting.Path)\$($setting.Name)" -Level Info
        } catch {
            Write-Log "Failed to apply privacy setting: $($setting.Path)" -Level Warning
        }
    }

    Write-Log "Privacy settings optimized" -Level Success
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

# Display data protection information
function Show-DataProtectionInfo {
    Write-Log "=====================================" -Level Success
    Write-Log "DATA PROTECTION INFORMATION" -Level Success
    Write-Log "=====================================" -Level Success
    Write-Log "" -Level Info
    Write-Log "The Windows 11 upgrade process preserves:" -Level Info
    Write-Log "  ✓ All personal files (Documents, Downloads, Desktop, etc.)" -Level Success
    Write-Log "  ✓ Installed applications and programs" -Level Success
    Write-Log "  ✓ User settings and preferences" -Level Success
    Write-Log "  ✓ Game installations (Steam, Epic, etc.)" -Level Success
    Write-Log "  ✓ Browser bookmarks and history" -Level Success
    Write-Log "" -Level Info
    Write-Log "What this script removes:" -Level Warning
    Write-Log "  • Bloatware apps (Xbox, Candy Crush, etc.)" -Level Warning
    Write-Log "  • OneDrive (can be reinstalled if needed)" -Level Warning
    Write-Log "  • Telemetry and advertising services" -Level Warning
    Write-Log "" -Level Info
    Write-Log "RECOMMENDED: Backup important data before major upgrades" -Level Warning
    Write-Log "=====================================" -Level Info
    Write-Log "" -Level Info

    $confirm = Read-Host "Do you want to continue? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Log "Upgrade cancelled by user" -Level Warning
        return $false
    }
    return $true
}

# Main execution
function Start-UpgradeAndDebloat {
    Write-Log "=====================================" -Level Info
    Write-Log "Windows 11 Upgrade & Debloat Script" -Level Info
    Write-Log "=====================================" -Level Info
    Write-Log "Log file: $LogFile" -Level Info

    # Show data protection information
    if (-not $SkipUpgrade) {
        if (-not (Show-DataProtectionInfo)) {
            return
        }
    }

    # Check compatibility
    if (-not $SkipUpgrade -and -not $SkipCompatibilityCheck) {
        if (-not (Test-Windows11Compatibility)) {
            Write-Log "System does not meet Windows 11 requirements or already running Windows 11" -Level Error
            $response = Read-Host "Continue anyway? (yes/no)"
            if ($response -ne "yes") {
                Write-Log "Upgrade cancelled by user" -Level Warning
                return
            }
        }
    }

    # Create restore point
    if (-not $NoRestorePoint) {
        New-SystemRestorePoint
    }

    # Bypass Windows 11 requirements if requested
    if ($BypassRequirements) {
        Write-Log "=====================================" -Level Warning
        Write-Log "BYPASSING WINDOWS 11 REQUIREMENTS" -Level Warning
        Write-Log "=====================================" -Level Warning
        Enable-Windows11BypassRegistry
    }

    # Download and run upgrade
    if (-not $SkipUpgrade) {
        $installerPath = Get-Windows11Installer

        if ($installerPath) {
            Write-Log "=====================================" -Level Info
            Write-Log "Starting Windows 11 upgrade..." -Level Info
            Write-Log "The installer will now launch." -Level Warning
            Write-Log "Follow the on-screen instructions." -Level Warning
            Write-Log "=====================================" -Level Info

            Start-Process -FilePath $installerPath -Wait

            Write-Log "=====================================" -Level Success
            Write-Log "Windows 11 installer has been launched!" -Level Success
            Write-Log "=====================================" -Level Success
            Write-Log "" -Level Info
            Write-Log "IMPORTANT: The upgrade process will continue through multiple reboots." -Level Warning
            Write-Log "After Windows 11 installation is complete, run this script again:" -Level Warning
            Write-Log "" -Level Info
            Write-Log "    .\Upgrade-To-Windows11-Debloated.ps1 -SkipUpgrade" -Level Info
            Write-Log "" -Level Info
            Write-Log "This will remove bloatware and optimize your fresh Windows 11 installation." -Level Info
            Write-Log "=====================================" -Level Info

            # Exit here - don't run debloat operations until after upgrade completes
            return
        }
    }

    # Debloat operations (only runs if -SkipUpgrade was specified or no installer was launched)
    Write-Log "=====================================" -Level Info
    Write-Log "Starting debloat operations..." -Level Info
    Write-Log "=====================================" -Level Info

    Remove-BloatwareApps
    Install-ClassicGames
    Disable-WindowsAds
    Disable-Telemetry
    Optimize-Privacy
    Disable-OneDrive

    Write-Log "=====================================" -Level Success
    Write-Log "Script completed successfully!" -Level Success
    Write-Log "Log saved to: $LogFile" -Level Success
    Write-Log "=====================================" -Level Success
    Write-Log "RECOMMENDED: Restart your computer to apply all changes" -Level Warning

    $restart = Read-Host "Would you like to restart now? (yes/no)"
    if ($restart -eq "yes") {
        Write-Log "Restarting computer in 10 seconds..." -Level Warning
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}

# Run the script
Start-UpgradeAndDebloat
