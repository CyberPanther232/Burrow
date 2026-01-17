<#

Windows PowerShell script to set up the development environment.
This script installs necessary packages, configures environment variables,

#>

$DownloadUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"

# Function to download and install Wintun
function Install-Wintun {

    $tempZipPath = Join-Path $env:TEMP "wintun.zip"
    $extractDir  = Join-Path $env:TEMP "wintun"

    # Clean previous temp artifacts
    if (Test-Path $tempZipPath) { Remove-Item $tempZipPath -Force }
    if (Test-Path $extractDir)  { Remove-Item $extractDir -Force -Recurse }

    try {
        Write-Host "Downloading Wintun..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempZipPath -UseBasicParsing
    } catch {
        Write-Error "Download failed: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        return
    }

    try {
        Expand-Archive -Path $tempZipPath -DestinationPath $extractDir -Force
    } catch {
        Write-Error "Extraction failed: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        return
    }

    # Resolve correct DLL path by architecture, searching common layouts from the zip
    $architecture = (Get-CimInstance Win32_Processor).Architecture
    $candidatePaths = @()
    switch ($architecture) {
        0  { $candidatePaths = @("x86/wintun.dll", "wintun/bin/x86/wintun.dll", "bin/x86/wintun.dll", "wintun/x86/wintun.dll") }
        5  { $candidatePaths = @("arm/wintun.dll", "wintun/bin/arm/wintun.dll", "bin/arm/wintun.dll", "wintun/arm/wintun.dll") }
        9  { $candidatePaths = @("amd64/wintun.dll", "wintun/bin/amd64/wintun.dll", "bin/amd64/wintun.dll", "wintun/amd64/wintun.dll", "x64/wintun.dll", "wintun/bin/x64/wintun.dll") }
        12 { $candidatePaths = @("arm64/wintun.dll", "wintun/bin/arm64/wintun.dll", "bin/arm64/wintun.dll", "wintun/arm64/wintun.dll") }
        default {
            Write-Error "Unsupported architecture: $architecture"
            Read-Host "Press Enter to exit"
            return
        }
    }

    $dllPath = $null
    foreach ($rel in $candidatePaths) {
        $p = Join-Path $extractDir $rel
        if (Test-Path $p) { $dllPath = $p; break }
    }

    if (-not $dllPath) {
        # Fallback: search recursively for wintun.dll and try to pick arch-specific match
        $allDlls = Get-ChildItem -Path $extractDir -Recurse -File -Filter "wintun.dll"
        if ($allDlls) {
            switch ($architecture) {
                0  { $dllPath = ($allDlls | Where-Object { $_.FullName -match "x86" }).FullName }
                5  { $dllPath = ($allDlls | Where-Object { $_.FullName -match "arm(?!64)" }).FullName }
                9  { $dllPath = ($allDlls | Where-Object { $_.FullName -match "amd64|x64" }).FullName }
                12 { $dllPath = ($allDlls | Where-Object { $_.FullName -match "arm64" }).FullName }
            }
            if (-not $dllPath) { $dllPath = $allDlls[0].FullName }
        }
    }

    if (-not $dllPath -or -not (Test-Path $dllPath)) {
        Write-Error "DLL not found after extraction under $extractDir"
        Read-Host "Press Enter to exit"
        return
    }

    $destPath = Join-Path $env:SystemRoot "System32/wintun.dll"

    try {
        Copy-Item -Path $dllPath -Destination $destPath -Force
        Write-Host "Wintun DLL installed to $destPath" -ForegroundColor Green
    } catch {
        Write-Error "Copy failed. Try running as Administrator. Error: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        return
    } finally {
        if (Test-Path $tempZipPath) { Remove-Item $tempZipPath -Force }
        if (Test-Path $extractDir)  { Remove-Item $extractDir -Force -Recurse }
    }

    Read-Host "Done. Press Enter to exit"
}

# Ensure elevated privileges before installing
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting elevation..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Install-Wintun

