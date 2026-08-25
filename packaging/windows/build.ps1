<#
.SYNOPSIS
    Build the iPulse MSI installer.

.DESCRIPTION
    Requires the WiX Toolset v4 or later:  dotnet tool install --global wix

    The binary is cross-compiled beforehand by scripts/build.sh --all, so this can run
    on a Windows host with no Go toolchain.

.EXAMPLE
    .\build.ps1 -Architecture x64
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = 'x64',
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')

if (-not $Version) {
    $versionFile = Join-Path $repoRoot 'VERSION'
    $Version = if (Test-Path $versionFile) { (Get-Content $versionFile -Raw).Trim() } else { '1.0.0' }
}

$goarch = if ($Architecture -eq 'x64') { 'amd64' } else { 'arm64' }
$binary = Join-Path $repoRoot "dist\windows-$goarch\ipulse.exe"

if (-not (Test-Path $binary)) {
    throw "Missing $binary. Run scripts/build.sh --all first (it cross-compiles from any host)."
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "The WiX Toolset is not installed. Install it with: dotnet tool install --global wix"
}

# The UI extension supplies WixUI_Minimal; util supplies PermissionEx.
Write-Host "Ensuring WiX extensions are available"
wix extension add -g WixToolset.UI.wixext | Out-Null
wix extension add -g WixToolset.Util.wixext | Out-Null

# A minimal licence in RTF, which is the only format the MSI UI accepts.
$licenseRtf = Join-Path $PSScriptRoot 'license.rtf'
if (-not (Test-Path $licenseRtf)) {
    Write-Host "Generating license.rtf from LICENSE"
    $license = Get-Content (Join-Path $repoRoot 'LICENSE') -Raw
    $escaped = $license -replace '\\', '\\\\' -replace '{', '\{' -replace '}', '\}'
    $escaped = $escaped -replace "`r`n", '\par ' -replace "`n", '\par '
    "{\rtf1\ansi\deff0{\fonttbl{\f0 Segoe UI;}}\fs18 $escaped}" |
        Set-Content -Path $licenseRtf -Encoding ASCII
}

$outDir = Join-Path $repoRoot 'dist'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$output = Join-Path $outDir "ipulse-$Version-$Architecture.msi"

Write-Host "Building $output"
wix build `
    -arch $Architecture `
    -d Version=$Version `
    -d BinaryPath=$binary `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    ipulse.wxs `
    -o $output

Write-Host ""
Write-Host "Built $output"
Get-Item $output | Format-List Name, Length, LastWriteTime
Write-Host "Install with:  msiexec /i `"$output`" /qn"
Write-Host "Remove with:   msiexec /x `"$output`" /qn"
