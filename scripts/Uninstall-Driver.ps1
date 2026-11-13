[CmdletBinding()]
param(
    [string]$ServiceName = 'MakeMePPL'
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell console.'
    }
}

Assert-Administrator

Write-Host "Close PplCtl and broker windows before stopping the driver."
Write-Host "Stopping '$ServiceName' (the unload callback restores tracked protections)..."

#
# The minifilter registers a FilterUnloadCallback, so sc stop now performs a
# real unload: MpTelemetryShutdown, restore of tracked processes, control
# device deletion.  Wait for STOPPED before deleting the service, otherwise the
# delete races the unload and leaves the driver "marked for deletion" until
# the next reboot.
#
& sc.exe stop $ServiceName | Out-Host
for ($i = 0; $i -lt 100; $i++) {
    $query = (& sc.exe query $ServiceName 2>&1) -join "`n"
    if ($query -match 'STOPPED' -or $query -match '1060') {
        break
    }
    Start-Sleep -Milliseconds 200
}
if ($query -match 'STOP_PENDING') {
    Write-Warning "'$ServiceName' is still stopping. Close any handle to its control device and retry the delete."
} elseif ($query -match 'RUNNING') {
    Write-Warning "'$ServiceName' did not stop; the loaded image may predate FilterUnloadCallback support."
}

Write-Host "Deleting '$ServiceName'..."
& sc.exe delete $ServiceName | Out-Host

#
# sc delete removes the service key, including Instances.  If the key is still
# present (driver busy / pending reboot), remove the minifilter instance data
# explicitly on a best-effort basis.
#
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
Start-Sleep -Milliseconds 500
if (Test-Path $serviceKey) {
    Remove-Item -Path (Join-Path $serviceKey 'Instances') -Recurse -Force `
        -ErrorAction SilentlyContinue
}

#
# The INF copies the driver into the drivers directory; sc delete leaves that
# file behind.  Remove it only after the service has stopped, otherwise the
# loaded image is still mapped.
#
$installedDriver = Join-Path $env:SystemRoot 'System32\drivers\MakeMePPL.sys'
if (Test-Path $installedDriver) {
    Remove-Item -Path $installedDriver -Force -ErrorAction SilentlyContinue
    if (Test-Path $installedDriver) {
        Write-Warning "Could not delete '$installedDriver'. It may still be loaded or pending unload."
    }
}

Write-Host ''
& sc.exe query $ServiceName | Out-Host
Write-Host ''
Write-Host 'If stop/delete reported that the service is not installed, it was already removed.'
