[CmdletBinding()]
param(
    [string]$PfxPassword = $env:PPL_TEST_PFX_PASSWORD,

    [string]$Subject = 'CN=MakeMePPL Test',

    [int]$Years = 3
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$CertDir = Join-Path $Root 'certs'
$PfxPath = Join-Path $CertDir 'ppl_test.pfx'
$CerPath = Join-Path $CertDir 'ppl_test.cer'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell console.'
    }
}

Assert-Administrator

if ([string]::IsNullOrWhiteSpace($PfxPassword)) {
    throw 'Set PPL_TEST_PFX_PASSWORD or pass -PfxPassword. The PFX password must not be empty.'
}

New-Item -ItemType Directory -Path $CertDir -Force | Out-Null

$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -HashAlgorithm SHA256 `
    -KeyLength 2048 `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears($Years) `
    -TextExtension @(
        '2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3'
    )

$securePassword = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText

Export-PfxCertificate -Cert $certificate -FilePath $PfxPath -Password $securePassword | Out-Null
Export-Certificate -Cert $certificate -FilePath $CerPath | Out-Null

Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null

Write-Host "Certificate subject : $($certificate.Subject)"
Write-Host "Certificate thumbprint: $($certificate.Thumbprint)"
Write-Host "PFX                 : $PfxPath"
Write-Host "CER                 : $CerPath"
Write-Host ''
Write-Host 'Installed the test root into LocalMachine\Root and LocalMachine\TrustedPublisher.'
Write-Host 'WARNING: this weakens certificate trust on the machine. Use a test VM only.'
Write-Host 'Never commit certs\ppl_test.pfx or its password.'
