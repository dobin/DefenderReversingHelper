[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DriverPath,

    [string]$ServiceName = 'PplExecutor'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root "bin\$Configuration\PplExecutor.sys"
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
& sc.exe delete $ServiceName | Out-Host
Start-Sleep -Milliseconds 500

Write-Host "Creating '$ServiceName' -> $DriverPath"
& sc.exe create $ServiceName type= kernel start= demand error= normal binPath= "`"$DriverPath`""
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE."
}

Write-Host "Starting '$ServiceName'..."
& sc.exe start $ServiceName | Out-Host
if ($LASTEXITCODE -ne 0) {
    & sc.exe query $ServiceName | Out-Host
    throw "sc.exe start failed with exit code $LASTEXITCODE. Check the System event log and test signing."
}

& sc.exe query $ServiceName | Out-Host
Write-Host ''
Write-Host "Driver loaded. Try: .\bin\$Configuration\PplCtl.exe info"
