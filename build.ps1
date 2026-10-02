<#
    Builds the launcher and its installer in one go.

        .\build.ps1                # both
        .\build.ps1 -SkipInstaller # just the one-folder build

    Produces:
        dist\TurboRivals\          the one-folder build - hand out the installer, not a zip of
                                   this (Mark-of-the-Web, see the readme)
        dist\TurboRivalsSetup-<version>.exe  installer (Start Menu entry, uninstaller)

    Inno Setup is needed only for the second step:
        winget install JRSoftware.InnoSetup
#>

[CmdletBinding()]
param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$python = Join-Path $PSScriptRoot 'venv\Scripts\pyinstaller.exe'
if (-not (Test-Path $python)) {
    throw "PyInstaller is missing from the venv. Run: venv\Scripts\python.exe -m pip install -r requirements.txt"
}

$version = (Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
Write-Host "==> building TurboRivals $version (PyInstaller, one folder)" -ForegroundColor Cyan
# WARN keeps the ~200 lines of hook chatter out of the way, so a real problem
# is the only thing on screen.
& $python TurboRivals.spec --noconfirm --log-level WARN
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$app = Join-Path $PSScriptRoot 'dist\TurboRivals\TurboRivals.exe'
if (-not (Test-Path $app)) { throw "expected $app, which is not there" }
$sizeMb = [math]::Round(((Get-ChildItem 'dist\TurboRivals' -Recurse | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Host "    dist\TurboRivals\  ($sizeMb MB)" -ForegroundColor Green

if ($SkipInstaller) { return }

# winget puts Inno Setup under LOCALAPPDATA; a machine-wide install lands in
# Program Files. Look in both rather than guess.
$iscc = @(
    "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    Write-Warning @'
Inno Setup not found, so the installer was not built. The portable build in
dist\TurboRivals is ready either way.

To get the installer:
    winget install JRSoftware.InnoSetup
    .\build.ps1
'@
    return
}

Write-Host '==> building the installer (Inno Setup)' -ForegroundColor Cyan

# Writing icons and version info into a freshly created exe intermittently hits
# "EndUpdateResource failed ... (110)" - a real-time virus scanner still has the
# file open. PyInstaller retries this internally; ISCC gives up at once, so we
# retry for it.
$attempts = 4
for ($i = 1; $i -le $attempts; $i++) {
    & $iscc 'installer\TurboRivals.iss'
    if ($LASTEXITCODE -eq 0) { break }
    if ($i -eq $attempts) { throw "ISCC failed with exit code $LASTEXITCODE after $attempts attempts" }
    Write-Warning "ISCC attempt $i failed (exit $LASTEXITCODE) - retrying in 2 s"
    Start-Sleep -Seconds 2
}

$setup = Join-Path $PSScriptRoot "dist\TurboRivalsSetup-$version.exe"
$setupMb = [math]::Round(((Get-Item $setup).Length / 1MB), 1)
Write-Host "    dist\TurboRivalsSetup-$version.exe  ($setupMb MB)" -ForegroundColor Green
