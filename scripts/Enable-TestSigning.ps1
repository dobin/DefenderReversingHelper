[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell console.'
    }
}

Assert-Administrator

$secureBoot = $null
try {
    $secureBoot = Confirm-SecureBootUEFI
} catch {
    Write-Warning "Could not query Secure Boot state: $($_.Exception.Message)"
}

if ($secureBoot -eq $true) {
    throw 'Secure Boot is enabled. Turn it off in UEFI firmware before enabling test signing.'
}
if ($secureBoot -eq $false) {
    Write-Host 'Secure Boot is off.'
}

try {
    $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName Win32_DeviceGuard -ErrorAction Stop
    if ($deviceGuard.SecurityServicesRunning -contains 2) {
        Write-Warning 'HVCI / memory integrity appears to be running. Disable it for this test VM before loading the driver.'
    }
} catch {
    Write-Warning "Could not query Device Guard state: $($_.Exception.Message)"
}

& bcdedit.exe /set testsigning on
if ($LASTEXITCODE -ne 0) {
    throw "bcdedit failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host 'Test signing is enabled for the next boot. Reboot before loading the driver.'
Write-Host 'Verify with: bcdedit /enum {current}   (look for "testsigning Yes")'
Write-Host ''
Write-Host 'This weakens the machine. Disable test signing and remove the test certificate when done.'
