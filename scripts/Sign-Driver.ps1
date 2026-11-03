[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DriverPath,

    [string]$PfxPath,

    [string]$PfxPassword = $env:PPL_TEST_PFX_PASSWORD
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root "bin\$Configuration\MakeMePPL.sys"
}
if (-not $PfxPath) {
    $PfxPath = Join-Path $Root 'certs\ppl_test.pfx'
}

function Find-SignTool {
    $kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
    if (-not $kitsRoot) {
        $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\'
    }

    $preferred = Join-Path $kitsRoot 'bin\10.0.26100.0\x64\signtool.exe'
    if (Test-Path $preferred) {
        return $preferred
    }

    $found = Get-ChildItem (Join-Path $kitsRoot 'bin') -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if ($found) {
        return $found.FullName
    }

    throw 'signtool.exe was not found. Install the Windows SDK/WDK signing tools.'
}

if (-not (Test-Path $DriverPath)) {
    throw "Driver not found at '$DriverPath'. Run scripts\Build.ps1 first."
}
if (-not (Test-Path $PfxPath)) {
    throw "PFX not found at '$PfxPath'. Run scripts\New-TestCert.ps1 first."
}
if ([string]::IsNullOrWhiteSpace($PfxPassword)) {
    throw 'Set PPL_TEST_PFX_PASSWORD or pass -PfxPassword.'
}

$SignTool = Find-SignTool
$DriverPath = (Resolve-Path $DriverPath).Path

Write-Host "Signing : $DriverPath"
Write-Host "PFX     : $PfxPath"
Write-Host "signtool: $SignTool"
Write-Host ''

& $SignTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /ph /v $DriverPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed with exit code $LASTEXITCODE."
}

& $SignTool verify /v /pa $DriverPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool verify failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host 'Signature verified. The driver still requires test signing to be enabled.'
