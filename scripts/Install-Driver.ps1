[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DriverPath,

    [string]$InfPath,

    [string]$ServiceName = 'MakeMePPL'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root "bin\$Configuration\MakeMePPL.sys"
}
if (-not $InfPath) {
    $InfPath = Join-Path $Root "bin\$Configuration\MakeMePPL.inf"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell console.'
    }
}

Assert-Administrator

if (-not (Test-Path $DriverPath)) {
    throw "Driver not found at '$DriverPath'. Run scripts\Build.ps1 and scripts\Sign-Driver.ps1 first."
}
if (-not (Test-Path $InfPath)) {
    throw "INF not found at '$InfPath'. Run scripts\Build.ps1 first (it stages the INF next to the driver)."
}

$DriverPath = (Resolve-Path $DriverPath).Path
$InfPath = (Resolve-Path $InfPath).Path

$testSigning = (& bcdedit.exe /enum '{current}' 2>$null) -join "`n"
if ($testSigning -notmatch 'testsigning\s+Yes') {
    Write-Warning 'Test signing does not appear to be enabled. A test-signed driver will not load.'
}

Write-Host "Stopping/deleting any existing service '$ServiceName'..."
& sc.exe stop $ServiceName | Out-Host
for ($i = 0; $i -lt 100; $i++) {
    $query = (& sc.exe query $ServiceName 2>&1) -join "`n"
    if ($query -match 'STOPPED' -or $query -match '1060') {
        break
    }
    Start-Sleep -Milliseconds 200
}
& sc.exe delete $ServiceName | Out-Host
Start-Sleep -Milliseconds 500

#
# Install the driver package through MakeMePPL.inf.  The INF's
# [DefaultInstall.Services] section creates the file-system service and its
# [MakeMePPL.AddRegistry] section writes the Instances\DefaultInstance,
# Altitude and Flags values that FltRegisterFilter requires.  This is the same
# data the old script created by hand, but in the normal minifilter package.
#
Write-Host "Installing driver package from $InfPath..."
$InfDefaultInstall = Join-Path $env:SystemRoot 'System32\InfDefaultInstall.exe'
if (Test-Path $InfDefaultInstall) {
    & $InfDefaultInstall $InfPath | Out-Host
} else {
    # Quote the comma: unquoted, PowerShell would split the library and the
    # entry point into two arguments.
    & rundll32.exe 'setupapi.dll,InstallHinfSection' DefaultInstall 132 $InfPath
}
if ($LASTEXITCODE -ne 0) {
    Write-Warning "INF installation returned exit code $LASTEXITCODE; verifying the registry below."
}

#
# InfDefaultInstall does not always return a useful exit code, so verify the
# service and minifilter instance that the INF is responsible for.
#
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$instancesKey = Join-Path $serviceKey 'Instances'
if (-not (Test-Path $serviceKey)) {
    throw "The INF did not create the '$ServiceName' service key. Check the setupapi.dev.log for details."
}

$defaultInstance = (Get-ItemProperty -Path $instancesKey -Name 'DefaultInstance' -ErrorAction SilentlyContinue).DefaultInstance
if (-not $defaultInstance) {
    throw "The INF did not create '$instancesKey\DefaultInstance'. FltStartFiltering would report no usable instance."
}

$instanceKey = Join-Path $instancesKey $defaultInstance
$altitude = (Get-ItemProperty -Path $instanceKey -Name 'Altitude' -ErrorAction SilentlyContinue).Altitude
if (-not $altitude) {
    throw "The INF did not create '$instanceKey\Altitude'."
}

Write-Host "Minifilter instance: '$defaultInstance' (altitude $altitude)"

Write-Host "Starting '$ServiceName'..."
& sc.exe start $ServiceName | Out-Host
if ($LASTEXITCODE -ne 0) {
    & sc.exe query $ServiceName | Out-Host
    throw "sc.exe start failed with exit code $LASTEXITCODE. Check the System event log and test signing."
}

& sc.exe query $ServiceName | Out-Host
Write-Host ''
Write-Host "Driver loaded. Try: .\bin\$Configuration\PplCtl.exe info"
