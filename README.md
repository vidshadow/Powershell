# Windows 11 Upgrade & Debloat Scripts

PowerShell scripts to upgrade Windows 10 to Windows 11 and remove bloatware, advertisements, and telemetry.

## Scripts

### 1. `Upgrade-To-Windows11-Debloated.ps1`
Complete solution for upgrading to Windows 11 and removing bloatware.

**Features:**
- Windows 11 compatibility checking (TPM 2.0, Secure Boot, RAM, Storage)
- **Bypass option for older hardware** - install Windows 11 without TPM 2.0 or Secure Boot
- Automatic system restore point creation
- Downloads official Windows 11 Installation Assistant
- Removes 50+ bloatware apps including:
  - Xbox apps and gaming overlays
  - Bloatware games (Candy Crush, etc.) - keeps Solitaire & Mahjong
  - Entertainment apps (Spotify, Netflix, etc.)
  - Social media apps
  - Unwanted Microsoft apps
- Installs classic Microsoft Minesweeper from Store
- Disables advertisements and suggestions in Start Menu
- Disables telemetry and tracking
- Optimizes privacy settings
- Disables OneDrive
- Comprehensive logging

### 2. `Debloat-Windows11.ps1`
Standalone debloating script for existing Windows 11 installations.

## Requirements

- Windows 10 (version 2004 or later) or Windows 11
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection (for upgrade)

### Windows 11 System Requirements:
- **Processor**: 1 GHz or faster with 2+ cores on compatible 64-bit processor
- **RAM**: 4 GB or more
- **Storage**: 64 GB or larger
- **System firmware**: UEFI, Secure Boot capable
- **TPM**: Trusted Platform Module (TPM) version 2.0
- **Graphics card**: DirectX 12 compatible or later with WDDM 2.0 driver
- **Display**: >9" with HD Resolution (720p)

## Usage

### Full Upgrade + Debloat

**Step 1: Start the Windows 11 Upgrade**

1. **Right-click PowerShell** and select "Run as Administrator"

2. **Allow script execution** (if not already enabled):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the upgrade script**:
   ```powershell
   .\Upgrade-To-Windows11-Debloated.ps1
   ```

4. **The script will**:
   - Check system compatibility
   - Create a restore point
   - Apply registry bypass (if using `-BypassRequirements`)
   - Download and launch Windows 11 installer
   - Exit and wait for you to complete the upgrade

5. **Complete the Windows 11 installation** - Follow the on-screen prompts through multiple reboots

**Step 2: Debloat Your Fresh Windows 11 Installation**

6. **After Windows 11 is fully installed**, run the script again:
   ```powershell
   .\Upgrade-To-Windows11-Debloated.ps1 -SkipUpgrade
   ```

7. **The script will now**:
   - Remove all bloatware apps
   - Install Minesweeper
   - Disable ads and telemetry
   - Optimize privacy settings
   - Disable OneDrive

### Debloat Only (Already on Windows 11)

If you're already running Windows 11 and just want to remove bloatware:

```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -SkipUpgrade
```

Or use the standalone script:

```powershell
.\Debloat-Windows11.ps1
```

### Advanced Options

**Bypass TPM 2.0 and Secure Boot requirements (for older hardware):**
```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -BypassRequirements
```
This applies registry modifications to bypass:
- TPM 2.0 requirement
- Secure Boot requirement
- RAM minimum (4GB)
- Storage minimum (64GB)
- CPU compatibility check

**Skip compatibility check:**
```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -SkipCompatibilityCheck
```

**Skip restore point creation:**
```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -NoRestorePoint
```

**Combine options:**
```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -BypassRequirements -NoRestorePoint
```

## What Gets Removed

### Apps & Games
- Xbox apps (Xbox, Game Bar, Gaming Overlay)
- Pre-installed games (Candy Crush and similar bloatware - keeps Solitaire & Mahjong)
- Entertainment (Spotify, Music, Movies & TV)
- Social media (Twitter, Facebook, Instagram, LinkedIn)
- Microsoft bloatware (Your Phone, Tips, Feedback Hub, 3D Viewer, Mixed Reality)
- OEM bloatware (McAfee, Disney, Netflix installers)

### Advertisements & Suggestions
- Start Menu suggestions
- Lock screen ads
- Tips and tricks
- App install suggestions
- Tailored experiences

### Privacy & Telemetry
- Diagnostic data collection
- Activity history
- Advertising ID
- Location tracking
- Cortana
- Web search in Start Menu

### Services Disabled
- Connected User Experiences and Telemetry
- Xbox Live services
- OneDrive sync

## What's Preserved

The scripts **DO NOT** remove:
- Microsoft Edge (system component)
- Microsoft Store (needed for app management)
- Windows Security
- Windows Photos
- Calculator
- Notepad
- Snipping Tool
- Solitaire & Mahjong (classic games preserved)
- Essential system apps

**Bonus**: The script automatically installs Microsoft Minesweeper from the Store!

## Safety Features

1. **System Restore Point**: Automatically created before changes (can skip with `-NoRestorePoint`)
2. **Logging**: All actions logged to `%TEMP%\Win11Upgrade_[timestamp].log`
3. **Error Handling**: Non-fatal errors won't stop the entire process
4. **Compatibility Checks**: Verifies system meets Windows 11 requirements

## Troubleshooting

### TPM 2.0 Not Detected or Secure Boot Not Supported

**Option 1: Enable in BIOS/UEFI (Recommended)**
1. Restart computer
2. Enter BIOS/UEFI (usually Del, F2, or F12 during boot)
3. Look for "TPM", "Security Device", or "PTT" (Intel Platform Trust Technology)
4. Enable TPM and Secure Boot
5. Save and restart

**Option 2: Bypass Requirements (for older hardware)**

If your hardware doesn't support TPM 2.0 or Secure Boot, use the bypass option:

```powershell
.\Upgrade-To-Windows11-Debloated.ps1 -BypassRequirements
```

This applies registry modifications that allow Windows 11 installation on unsupported hardware by bypassing:
- TPM 2.0 check
- Secure Boot check
- RAM check
- Storage check
- CPU compatibility check

**Note**: While this works for most systems, be aware that:
- Future Windows updates may have issues on unsupported hardware
- Some security features may not be available
- Microsoft recommends TPM 2.0 for full security features

**Check TPM status manually**:
```powershell
Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
```

### Script Execution Policy Error
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### Some Apps Won't Uninstall
This is normal for system-integrated apps. The script safely handles these cases.

## Post-Installation Recommendations

1. **Windows Update**: Check for and install all updates
   ```
   Settings > Update & Security > Windows Update
   ```

2. **Graphics Drivers**: Update to latest from manufacturer
   - NVIDIA: GeForce Experience
   - AMD: Adrenalin Software
   - Intel: Driver & Support Assistant

3. **Privacy Settings**: Review additional privacy settings
   ```
   Settings > Privacy & security
   ```

4. **Optional Features**: Remove unused Windows features
   ```
   Settings > Apps > Optional features
   ```

## Reverting Changes

If you need to undo changes:

1. **System Restore**:
   - Search "Create a restore point"
   - Click "System Restore"
   - Select the restore point created before upgrade

2. **Rollback to Windows 10** (within 10 days):
   - Settings > System > Recovery
   - Click "Go back" under "Recovery options"

## Customization

To customize what gets removed, edit the `$bloatwareApps` array in the script:

```powershell
$bloatwareApps = @(
    "Microsoft.XboxApp",
    "Microsoft.YourPhone",
    # Add or remove apps here
)
```

## Security Notes

- Scripts are **defensive security tools** for personal system administration
- All changes can be reverted via System Restore
- No registry modifications that break Windows functionality
- Scripts use official Microsoft upgrade tools only

## Logs

All operations are logged to: `%TEMP%\Win11Upgrade_[timestamp].log`

View logs:
```powershell
notepad $env:TEMP\Win11Upgrade_*.log
```

## Contributing

To report issues or suggest improvements, please open an issue in the repository.

## Disclaimer

**USE AT YOUR OWN RISK**. While these scripts are designed to be safe:
- Always back up important data before major system changes
- Review the script before running to understand what it does
- System restore point is created automatically (unless skipped)
- Tested on Windows 10 21H2/22H2, but your configuration may differ

## License

Free to use and modify for personal or commercial purposes.

## Author

Created by Claude - AI assistant focused on system administration and security tools.

---

**Last Updated**: October 2025
**Tested On**: Windows 10 21H2, 22H2 → Windows 11 23H2
