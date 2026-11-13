[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DriverPath,

    [string]$ServiceName = 'MakeMePPL'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root "bin\$Configuration\MakeMePPL.sys"
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
$DriverPath = (Resolve-Path $DriverPath).Path

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

Write-Host "Creating '$ServiceName' -> $DriverPath"
& sc.exe create $ServiceName type= filesys start= demand error= normal group= "FSFilter Anti-Virus" depend= FltMgr binPath= "`"$DriverPath`""
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE."
}

#
# Register a default minifilter instance.  MakeMePPL now also hosts the
# WdFilter-style telemetry source (MpTelemetry.c); FltRegisterFilter needs a
# DefaultInstance plus an altitude entry under the service key.  These are
# normally written by a minifilter INF.  Every other minifilter on the system
# (WdFilter, FileInfo, FileCrypt, bindflt) has the same shape.
#
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$instancesKey = Join-Path $serviceKey 'Instances'
$instanceKey = Join-Path $instancesKey "$ServiceName Instance"
New-Item -Path $instanceKey -Force | Out-Null
New-ItemProperty -Path $instancesKey -Name 'DefaultInstance' `
    -Value "$ServiceName Instance" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instanceKey -Name 'Altitude' -Value '328500' `
    -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instanceKey -Name 'Flags' -Value 0 `
    -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $serviceKey -Name 'SupportedFeatures' -Value 15 `
    -PropertyType DWord -Force | Out-Null

Write-Host "Starting '$ServiceName'..."
& sc.exe start $ServiceName | Out-Host
if ($LASTEXITCODE -ne 0) {
    & sc.exe query $ServiceName | Out-Host
    throw "sc.exe start failed with exit code $LASTEXITCODE. Check the System event log and test signing."
}

& sc.exe query $ServiceName | Out-Host
Write-Host ''
Write-Host "Driver loaded. Try: .\bin\$Configuration\PplCtl.exe info"
