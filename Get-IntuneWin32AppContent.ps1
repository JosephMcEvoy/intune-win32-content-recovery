<#
.SYNOPSIS
    Downloads and decrypts the source content of an Intune Win32 app (.intunewin) WITHOUT installing it.

.DESCRIPTION
    Mimics the one call the Intune Management Extension (IME) makes before it downloads a Win32 app:
      1. Finds this device's Intune MDM device certificate (LocalMachine\My, issued by "Microsoft Intune MDM Device CA").
      2. Discovers the tenant's SideCar gateway (RestUserAuthLocationService -> SideCarGatewayService).
      3. Sends a GetContentInfo request for the App ID -> gets the blob download URL + CMS-encrypted DecryptInfo.
      4. Decrypts DecryptInfo with the device cert's private key -> AES-256 key + IV.
      5. Downloads the encrypted .bin, decrypts it (skips 32-byte HMAC + 16-byte IV header), and extracts the zip.

    No install, no detection, nothing handed to IME. You end up with the original source folder
    (setup.exe / .ps1 / .xml / PSADT tree, whatever was packaged).

.REQUIREMENTS
    - Run ELEVATED on an Intune-enrolled, Entra-joined Windows device (needs the MDM cert private key).
    - The app must be assigned (Required or Available) to this device or the signed-in user.
      Not assigned -> the gateway returns 403/empty. Make a test group and assign as Available.
    - Windows PowerShell 5.1 recommended (TPM-backed cert keys + Invoke-RestMethod -Certificate is the proven path).

.PARAMETER AppId
    Win32 app GUID (Intune admin center URL: .../appId/<GUID>, or Graph deviceAppManagement/mobileApps). Prompts if omitted.

.PARAMETER OutputPath
    Folder to extract into. Prompts if omitted (default C:\Temp\IntuneAppContent\<AppId>).

.PARAMETER ApplicationVersion
    Value sent in the GetContentInfo payload. Default 1. If the gateway errors or you get stale content, try 2, 3, ...

.PARAMETER KeepEncrypted
    Keep the downloaded encrypted .bin and the decrypted .zip next to the output folder.

.EXAMPLE
    .\Get-IntuneWin32AppContent.ps1
    .\Get-IntuneWin32AppContent.ps1 -AppId 1b2c3d4e-... -OutputPath D:\Recovered\7zip
    .\Get-IntuneWin32AppContent.ps1 -AppId 1b2c3d4e-... -OutputPath D:\Recovered\7zip -AsIntuneWin
    # -> D:\Recovered\7zip (source) + D:\Recovered\7zip_intunewin\<setup>.intunewin (fresh keys, uploadable)
#>
[CmdletBinding()]
param(
    [string]$AppId,
    [string]$OutputPath,
    [int]$ApplicationVersion = 1,
    [string]$Environment = 'https://manage.microsoft.com',   # GCC High / DoD: https://manage.microsoft.us
    [switch]$KeepEncrypted,
    [switch]$AsIntuneWin,          # also re-wrap the recovered source into a fresh, uploadable .intunewin
    [string]$SetupFile,            # setup file for -AsIntuneWin (relative to source root); auto-detected if omitted
    [string]$IntuneWinAppUtilPath  # path to IntuneWinAppUtil.exe; downloaded from Microsoft's GitHub if omitted
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # IWR progress bar kills download speed in 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.IO.Compression.FileSystem

#region --- Preflight ----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated - the MDM device certificate private key is in the LocalMachine store.'
}

$guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
while (-not $AppId -or $AppId -notmatch $guidRx) {
    $AppId = (Read-Host 'Win32 App ID (GUID)').Trim().Trim('{}')
}
if (-not $OutputPath) {
    $default    = "C:\Temp\IntuneAppContent\$AppId"
    $OutputPath = Read-Host "Output folder [$default]"
    if (-not $OutputPath) { $OutputPath = $default }
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$workDir = Join-Path $env:TEMP "IntuneAppContent_$AppId"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
#endregion

#region --- Device certificate ------------------------------------------------
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Issuer -like '*Microsoft Intune MDM Device CA*' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw 'No valid Intune MDM device certificate with private key in LocalMachine\My. Is this device enrolled?' }
Write-Host "Device cert : $($cert.Subject)  (exp $($cert.NotAfter.ToString('yyyy-MM-dd')))"
#endregion

#region --- Client info (use real values, fall back to known-good) ------------
$imeExe   = "${env:ProgramFiles(x86)}\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
$imeVer   = if (Test-Path $imeExe) { (Get-Item $imeExe).VersionInfo.FileVersion } else { '1.81.107.0' }
$osVer    = [Environment]::OSVersion.Version
$osVerStr = "$($osVer.Major).$($osVer.Minor).$($osVer.Build)"
#endregion

#region --- Gateway discovery -------------------------------------------------
$discoUrl = "$Environment/RestUserAuthLocationService/RestUserAuthLocationService/Certificate/ServiceAddresses"
$disco    = Invoke-RestMethod -Uri $discoUrl -Method Get -Certificate $cert
$gateway  = ($disco.Services | Where-Object ServiceName -eq 'SideCarGatewayService').Url | Select-Object -First 1
if (-not $gateway) { throw 'No SideCarGatewayService URL returned. Enrollment may not be anchored to Entra join (enrollmentType 0).' }
Write-Host "Gateway     : $gateway"
#endregion

#region --- GetContentInfo ----------------------------------------------------
$zero = '00000000-0000-0000-0000-000000000000'
$body = @{
    Key                = $zero
    SessionId          = $zero
    RequestContentType = 'GetContentInfo'
    RequestPayload     = (@{
        CertificateBlob    = [Convert]::ToBase64String($cert.RawData)
        ApplicationId      = $AppId
        ApplicationVersion = $ApplicationVersion
    } | ConvertTo-Json -Compress)
    ClientInfo         = (@{
        OperatingSystemVersion = $osVerStr
        SideCarAgentVersion    = $imeVer
    } | ConvertTo-Json -Compress)
} | ConvertTo-Json -Compress

$sessionUrl = "$gateway/SideCarGatewaySessions('$zero')%3Fapi-version=1.5"
try {
    $resp = Invoke-RestMethod -Uri $sessionUrl -Method Put -Body $body -ContentType 'application/json' `
                              -Headers @{ Prefer = 'return-content' } -Certificate $cert
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 403) { throw "403 from gateway - app $AppId is not assigned to this device/user (check web Company Portal)." }
    throw
}
if (-not $resp.ResponsePayload) { throw "Empty ResponsePayload. Try -ApplicationVersion 2 (or higher), or confirm the App ID is a Win32 app." }

$payload     = $resp.ResponsePayload | ConvertFrom-Json
$contentInfo = $payload.ContentInfo  | ConvertFrom-Json
$downloadUrl = $contentInfo.UploadLocation
if (-not $downloadUrl) { throw 'No UploadLocation in ContentInfo (catalog/Enterprise App Catalog apps are not supported by this flow).' }
#endregion

#region --- Decrypt DecryptInfo (CMS, device cert) -----------------------------
$encXml = [xml]$payload.DecryptInfo
$cms    = New-Object Security.Cryptography.Pkcs.EnvelopedCms
$cms.Decode([Convert]::FromBase64String($encXml.EncryptedMessage.EncryptedContent))
$cms.Decrypt((New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection $cert))
$decryptInfo = [Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content) | ConvertFrom-Json
$key = [Convert]::FromBase64String($decryptInfo.EncryptionKey)
$iv  = [Convert]::FromBase64String($decryptInfo.IV)
Write-Host 'DecryptInfo : OK (AES-256 key + IV recovered)'
#endregion

#region --- Download ------------------------------------------------------------
$binPath = Join-Path $workDir "$AppId.bin"
$zipPath = Join-Path $workDir "$AppId.zip"
Write-Host 'Downloading encrypted content...'
$sw = [Diagnostics.Stopwatch]::StartNew()
(New-Object Net.WebClient).DownloadFile($downloadUrl, $binPath)
Write-Host ("Downloaded  : {0:N1} MB in {1:N0}s" -f ((Get-Item $binPath).Length / 1MB), $sw.Elapsed.TotalSeconds)
#endregion

#region --- AES-256-CBC decrypt (layout: HMAC[32] | IV[16] | ciphertext) --------
$aes = [Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv
$aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
$in  = [IO.File]::OpenRead($binPath)
$out = [IO.File]::Create($zipPath)
try {
    [void]$in.Seek(48, 'Begin')
    $cs = New-Object Security.Cryptography.CryptoStream($in, $aes.CreateDecryptor(), 'Read')
    $cs.CopyTo($out)
    $cs.Dispose()
} finally { $out.Dispose(); $in.Dispose(); $aes.Dispose() }
#endregion

#region --- Extract ----------------------------------------------------------------
Expand-Archive -Path $zipPath -DestinationPath $OutputPath -Force
if ($KeepEncrypted) {
    Copy-Item $binPath, $zipPath -Destination (Split-Path $OutputPath -Parent) -Force
}
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`nExtracted to $OutputPath" -ForegroundColor Green
Get-ChildItem $OutputPath -Recurse -File |
    Select-Object @{n='File';e={$_.FullName.Substring($OutputPath.Length).TrimStart('\')}}, @{n='KB';e={[math]::Round($_.Length/1KB,1)}} |
    Format-Table -AutoSize
#endregion

#region --- Optional: re-wrap into .intunewin ---------------------------------------
if ($AsIntuneWin) {
    if (-not $IntuneWinAppUtilPath) {
        $IntuneWinAppUtilPath = Join-Path $env:TEMP 'IntuneWinAppUtil.exe'
        if (-not (Test-Path $IntuneWinAppUtilPath)) {
            Write-Host 'Fetching IntuneWinAppUtil.exe from microsoft/Microsoft-Win32-Content-Prep-Tool...'
            (New-Object Net.WebClient).DownloadFile(
                'https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe',
                $IntuneWinAppUtilPath)
        }
    }

    if (-not $SetupFile) {
        # PSADT v4 / v3 first, then a lone MSI / EXE / PS1 at the root
        $root = Get-ChildItem $OutputPath -File
        foreach ($n in 'Invoke-AppDeployToolkit.exe','Deploy-Application.exe','Invoke-AppDeployToolkit.ps1','Deploy-Application.ps1') {
            if ($root.Name -contains $n) { $SetupFile = $n; break }
        }
        if (-not $SetupFile) {
            foreach ($ext in '.msi','.exe','.ps1') {
                $hits = @($root | Where-Object Extension -eq $ext)
                if ($hits.Count -eq 1) { $SetupFile = $hits[0].Name; break }
            }
        }
        while (-not $SetupFile -or -not (Test-Path (Join-Path $OutputPath $SetupFile))) {
            Write-Host "Root files: $($root.Name -join ', ')"
            $SetupFile = Read-Host 'Setup file (relative to source root)'
        }
    }
    Write-Host "Setup file  : $SetupFile"

    # Output must live OUTSIDE the source folder or the next wrap would swallow it
    $iwOut = Join-Path (Split-Path $OutputPath -Parent) "$(Split-Path $OutputPath -Leaf)_intunewin"
    New-Item -ItemType Directory -Path $iwOut -Force | Out-Null
    & $IntuneWinAppUtilPath -c $OutputPath -s $SetupFile -o $iwOut -q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil exited $LASTEXITCODE" }

    $iw = Get-ChildItem $iwOut -Filter *.intunewin | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host "IntuneWin   : $($iw.FullName)" -ForegroundColor Green
}
#endregion
