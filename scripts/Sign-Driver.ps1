[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DriverPath,

    [string]$InfPath,

    [string]$PfxPath,

    [string]$PfxPassword = $env:PPL_TEST_PFX_PASSWORD
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if (-not $DriverPath) {
    $DriverPath = Join-Path $Root "bin\$Configuration\MakeMePPL.sys"
}
if (-not $InfPath) {
    $InfPath = Join-Path $Root "bin\$Configuration\MakeMePPL.inf"
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

function Find-Inf2Cat {
    $kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
    if (-not $kitsRoot) {
        $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\'
    }

    $found = Get-ChildItem (Join-Path $kitsRoot 'bin') -Recurse -Filter inf2cat.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x86\\inf2cat\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if ($found) {
        return $found.FullName
    }

    return $null
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
$Inf2Cat = Find-Inf2Cat
$DriverPath = (Resolve-Path $DriverPath).Path
$PackageDir = Split-Path -Parent $DriverPath
$CatPath = Join-Path $PackageDir 'MakeMePPL.cat'

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

#
# Build the driver-package catalog and sign it, so the INF is a complete
# package.  The .sys embedded signature above is what SCM/FltMgr checks on
# load; the catalog is what SetupAPI checks when installing through the INF.
# Catalog generation is best effort: a missing inf2cat should not stop the
# .sys from being signed.
#
if (-not (Test-Path $InfPath)) {
    Write-Warning "INF not found at '$InfPath'; skipping catalog generation. Run scripts\Build.ps1 to stage it."
} elseif (-not $Inf2Cat) {
    Write-Warning 'inf2cat.exe was not found in the WDK; skipping catalog generation.'
} else {
    if (Test-Path $CatPath) {
        Remove-Item $CatPath -Force
    }

    Write-Host ''
    Write-Host "Catalog : $CatPath"
    Write-Host "inf2cat : $Inf2Cat"
    & $Inf2Cat "/driver:$PackageDir" /os:10_X64
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $CatPath)) {
        Write-Warning "inf2cat failed with exit code $LASTEXITCODE; the INF will install without a catalog."
    } else {
        & $SignTool sign /fd SHA256 /f $PfxPath /p $PfxPassword /ph /v $CatPath
        if ($LASTEXITCODE -ne 0) {
            throw "signtool sign (catalog) failed with exit code $LASTEXITCODE."
        }

        & $SignTool verify /v /pa $CatPath
        if ($LASTEXITCODE -ne 0) {
            throw "signtool verify (catalog) failed with exit code $LASTEXITCODE."
        }
    }
}

Write-Host ''
Write-Host 'Signature verified. The driver still requires test signing to be enabled.'
