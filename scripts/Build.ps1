[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [ValidateSet('x64')]
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Solution = Join-Path $Root 'MakeMePPL.sln'

function Find-MSBuild {
    $candidates = @()

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and $installPath) {
            $candidates += (Join-Path $installPath.Trim() 'MSBuild\Current\Bin\MSBuild.exe')
        }
    }

    $candidates += @(
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe')
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    throw 'MSBuild.exe was not found. Install Visual Studio 2022 with the C++ desktop workload.'
}

$MSBuild = Find-MSBuild

# Verify the WDK is actually present. Do not install it automatically.
$kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if (-not $kitsRoot) {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\'
}
$KernelInclude = Join-Path $kitsRoot 'Include\10.0.26100.0\km'
if (-not (Test-Path $KernelInclude)) {
    throw "The WDK kernel headers were not found at '$KernelInclude'. Install the Windows Driver Kit for SDK 10.0.26100 through Visual Studio Installer. This script never installs the WDK."
}

$VsRoot = $MSBuild -replace '\\MSBuild\\Current\\Bin\\MSBuild\.exe$', ''
$DriverToolset = Join-Path $VsRoot 'MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0'
if (-not (Test-Path $DriverToolset)) {
    throw "The WindowsKernelModeDriver10.0 toolset was not found under '$VsRoot'. Install the WDK Visual Studio extension."
}

Write-Host "MSBuild : $MSBuild"
Write-Host "WDK     : $kitsRoot"
Write-Host "Config  : $Configuration|$Platform"
Write-Host ''

& $MSBuild $Solution /m /nologo /v:minimal `
    "/p:Configuration=$Configuration" `
    "/p:Platform=$Platform"

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE."
}

$Output = Join-Path $Root "bin\$Configuration"
Write-Host ''
Write-Host "Build succeeded. Output: $Output"
Get-ChildItem $Output -File |
    Where-Object { $_.Extension -in '.sys', '.exe', '.dll' } |
    Select-Object Name, Length |
    Format-Table -AutoSize
