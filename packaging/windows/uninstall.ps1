<#
.SYNOPSIS
    Remove iPulse from Windows.

.DESCRIPTION
    Stops and removes the service, deletes the binary and takes the install directory
    off the system PATH. Historical measurements are kept unless -Purge is given: an
    uninstall is often a reinstall, and months of history should not disappear silently.

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -Purge
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\iPulse",
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This uninstaller must run as Administrator."
}

$exe = Join-Path $InstallDir 'ipulse.exe'
$dataRoot = Join-Path $env:ProgramData 'iPulse'

Write-Host "Removing iPulse"

if (Test-Path $exe) {
    Write-Host "  stopping and removing the service"
    $serviceArgs = @('service', 'uninstall')
    if ($Purge) { $serviceArgs += '--purge' } else { $serviceArgs += '--keep-data' }
    & $exe @serviceArgs
    Start-Sleep -Seconds 2
} else {
    # The binary is gone but the service may still be registered.
    $service = Get-Service -Name 'iPulse' -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "  removing the orphaned service registration"
        Stop-Service -Name 'iPulse' -Force -ErrorAction SilentlyContinue
        sc.exe delete iPulse | Out-Null
    }
}

if (Test-Path $InstallDir) {
    Write-Host "  removing $InstallDir"
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -like "*$InstallDir*") {
    Write-Host "  removing $InstallDir from the system PATH"
    $cleaned = ($machinePath -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $cleaned, 'Machine')
}

$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\iPulse'
if (Test-Path $shortcut) { Remove-Item -Path $shortcut -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
if ($Purge) {
    if (Test-Path $dataRoot) {
        Write-Host "  deleting $dataRoot"
        Remove-Item -Path $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "iPulse and all of its data have been removed."
} else {
    Write-Host "iPulse has been removed. Historical data was kept in:"
    Write-Host "  $dataRoot"
    Write-Host ""
    Write-Host "Re-run with -Purge to delete it as well."
}
