<#
.SYNOPSIS
    Install iPulse on Windows without an MSI.

.DESCRIPTION
    Copies the binary into Program Files, creates the data directories with restrictive
    permissions, writes a default configuration and registers the "iPulse" service.

    Use this when you have a binary rather than an MSI, or when installing from a script.
    The MSI does exactly the same things.

    Must be run as Administrator: registering a service, writing to Program Files and
    creating the Event Log source all require it.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -BinaryPath .\ipulse.exe -NoStart
#>
[CmdletBinding()]
param(
    [string]$BinaryPath = '',
    [string]$InstallDir = "$env:ProgramFiles\iPulse",
    [switch]$NoStart,
    [switch]$NoEnable
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This installer must run as Administrator. Right-click PowerShell and choose 'Run as administrator'."
    }
}

Assert-Administrator

# Locate the binary: an explicit path, next to this script, or a cross-compiled artifact.
if (-not $BinaryPath) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'ipulse.exe'),
        (Join-Path $PSScriptRoot '..\..\dist\windows-amd64\ipulse.exe'),
        (Join-Path $PSScriptRoot '..\..\bin\ipulse.exe'),
        '.\ipulse.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { $BinaryPath = (Resolve-Path $candidate).Path; break }
    }
}
if (-not $BinaryPath -or -not (Test-Path $BinaryPath)) {
    throw "No iPulse binary found. Pass -BinaryPath, or build one with scripts/build.sh --all."
}

$dataRoot  = Join-Path $env:ProgramData 'iPulse'
$configDir = Join-Path $dataRoot 'config'
$dataDir   = Join-Path $dataRoot 'data'
$logDir    = Join-Path $dataRoot 'logs'
$exe       = Join-Path $InstallDir 'ipulse.exe'

Write-Host "Installing iPulse"

# 1. Stop an existing service so the binary can be replaced.
$existing = Get-Service -Name 'iPulse' -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -eq 'Running') {
    Write-Host "  stopping the running service"
    Stop-Service -Name 'iPulse' -Force
    # The service needs a moment to release the executable.
    Start-Sleep -Seconds 2
}

# 2. Binary.
Write-Host "  installing $exe"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path $BinaryPath -Destination $exe -Force

# 3. Directories. The data directory holds connection metadata, so inherited
#    ProgramData permissions (readable by every local user) are replaced with an
#    explicit list: SYSTEM and Administrators only.
Write-Host "  creating $dataRoot"
foreach ($dir in @($dataRoot, $configDir, $dataDir, $logDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

Write-Host "  restricting permissions on the data and log directories"
foreach ($dir in @($dataDir, $logDir)) {
    $acl = Get-Acl $dir
    $acl.SetAccessRuleProtection($true, $false)   # stop inheriting
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($account in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $dir -AclObject $acl
}

# 4. Configuration, only if absent: an upgrade must not overwrite local settings.
$configPath = Join-Path $configDir 'ipulse.yaml'
if (Test-Path $configPath) {
    Write-Host "  keeping existing $configPath"
} else {
    Write-Host "  writing default $configPath"
    $shipped = Join-Path $PSScriptRoot '..\..\configs\ipulse.yaml'
    if (Test-Path $shipped) {
        Copy-Item -Path $shipped -Destination $configPath -Force
    } else {
        & $exe config init | Out-Null
    }
}

# 5. Validate before registering, so a typo does not become a service that fails at boot.
Write-Host "  validating the configuration"
& $exe config validate | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "The configuration at $configPath is not valid. Run 'ipulse config validate' to see the problems."
}

# 6. PATH, so `ipulse status` works from any prompt.
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike "*$InstallDir*") {
    Write-Host "  adding $InstallDir to the system PATH"
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$InstallDir", 'Machine')
}

# 7. Service registration, done by the binary so the definition matches what the CLI
#    would create: automatic delayed start, recovery actions, Event Log source.
Write-Host "  registering the iPulse service"
$serviceArgs = @('service', 'install')
if ($NoEnable) { $serviceArgs += '--no-enable' }
if ($NoStart)  { $serviceArgs += '--no-start' }
& $exe @serviceArgs
if ($LASTEXITCODE -ne 0) { throw "Service registration failed." }

Write-Host ""
& $exe service status
Write-Host ""
Write-Host "  configuration  $configPath"
Write-Host "  data           $dataDir"
Write-Host "  logs           $logDir"
Write-Host "  dashboard      http://127.0.0.1:8750"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Set your ISP plan in $configPath (speed_test.expected_*_mbps)"
Write-Host "  2. Restart-Service iPulse"
Write-Host "  3. ipulse status"
