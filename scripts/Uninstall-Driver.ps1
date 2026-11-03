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
Write-Host "Stopping '$ServiceName' (DriverUnload restores tracked protections)..."
& sc.exe stop $ServiceName | Out-Host

Write-Host "Deleting '$ServiceName'..."
& sc.exe delete $ServiceName | Out-Host

Write-Host ''
& sc.exe query $ServiceName | Out-Host
Write-Host ''
Write-Host 'If stop/delete reported that the service is not installed, it was already removed.'
