# intune-win32-content-recovery

Download and decrypt the source content of an Intune Win32 app **without installing it**. Optionally re-wrap it as a fresh, uploadable `.intunewin`.

The script does what the Intune Management Extension does right before a Win32 app download, then stops:

1. Finds the device's Intune MDM certificate (`LocalMachine\My`, issuer *Microsoft Intune MDM Device CA*).
2. Looks up the tenant's SideCar gateway.
3. Sends `GetContentInfo` for the App ID, which returns the blob URL and CMS-encrypted DecryptInfo.
4. Decrypts DecryptInfo with the device certificate to get the AES-256 key and IV.
5. Downloads the encrypted `.bin`, decrypts it and extracts the original source files.

Nothing is installed and nothing is handed to the IME or Company Portal.

## Usage

```powershell
# Interactive: prompts for the App ID and output folder
.\Get-IntuneWin32AppContent.ps1

# Source files only
.\Get-IntuneWin32AppContent.ps1 -AppId <guid> -OutputPath D:\Recovered\App

# Source files plus a fresh .intunewin in D:\Recovered\App_intunewin\
.\Get-IntuneWin32AppContent.ps1 -AppId <guid> -OutputPath D:\Recovered\App -AsIntuneWin
```

| Parameter | Notes |
|---|---|
| `-AppId` | Win32 app GUID, from the admin center URL or Graph `deviceAppManagement/mobileApps`. |
| `-OutputPath` | Extract target. Default is `C:\Temp\IntuneAppContent\<AppId>`. |
| `-AsIntuneWin` | Re-wrap the source with `IntuneWinAppUtil.exe`. The tool is downloaded from Microsoft's GitHub repo if `-IntuneWinAppUtilPath` isn't given. |
| `-SetupFile` | Setup file for `-AsIntuneWin`. If omitted, the script looks for PSADT first, then a single `.msi`, `.exe` or `.ps1` at the root, then prompts. |
| `-ApplicationVersion` | Sent in the request. Default is `1`. Raise it if you get an empty response or stale content. |
| `-Environment` | Use `https://manage.microsoft.us` for GCC High or DoD. |
| `-KeepEncrypted` | Keep the downloaded `.bin` and the decrypted `.zip`. |

## Requirements

- Run it elevated on an Intune-enrolled, Entra-joined Windows device.
- The app has to be assigned to that device or user. An Available assignment to a test group is enough and never auto-installs. If it isn't assigned, the gateway returns 403.
- The enrollment has to be tied to the Entra join, as with Autopilot. Otherwise there's no SideCar gateway URL.
- Use Windows PowerShell 5.1.

## Limitations

- **You can't recover the byte-identical original `.intunewin`.** The gateway returns only the encryption key and IV, not the MacKey that `Detection.xml` needs. `-AsIntuneWin` builds a new package from the same content with new keys.
- **Install and uninstall commands, detection rules and requirements aren't in the package.** They live on the app object, so pull them from Graph (`win32LobApp`).
- **Enterprise App Catalog apps aren't supported.**
- **This uses an undocumented Microsoft endpoint**, so it may break without notice.

## Credits

Based on research by Oliver Kieselbach ([IntuneWinAppUtilDecoder](https://msendpointmgr.com/2019/01/18/how-to-decode-intune-win32-app-packages/)), Tom Plant ([content info flow](https://garden-d59.pages.dev/Microsoft/Intune/Win32-Apps)) and [Patch My PC](https://patchmypc.com/blog/download-intunewin-win32-app-files-from-intune/).

Provided as-is, with no warranty.
