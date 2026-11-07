# MakeMePPL

A test-signed Windows driver and CLI that grant **Protected Process Light (PPL)** to a
process by PID, name filter, or named-pipe connection. Default: PPL-Antimalware (`0x31`).
It can also remove the **block non-Microsoft binaries** process mitigation (Cobalt Strike
`blockdll`), so a target can load unsigned or test-signed DLLs.

The purpose is to enable AI agents to start tools as PPL. 

> **Isolated test VM only.** Unsupported kernel memory modification can crash Windows.
> Take a snapshot first. The driver allows **any local user** to grant or clear PPL on
> non-blocklisted processes; the optional broker also allows everyone by default.
> Never use on a production host.

Vibe coded by Deepseek V4.1 Flash. With input from [KDU](https://github.com/hfiref0x/KDU). 
Similar to [PPLRunner](https://github.com/pathtofile/PPLRunner) but easier to use. 

## Requirements

- Windows x64 test VM; Windows 11 24H2/25H2 is the tested target.
- Visual Studio 2022: **Desktop development with C++** workload.
- Windows SDK and WDK **10.0.26100.0**, including `WindowsKernelModeDriver10.0`.
- **Secure Boot off**, **HVCI / memory integrity off** in the test VM.
- Elevated PowerShell for setup and cleanup. Run commands from the repository root.

The scripts do not install the SDK/WDK. See the [detailed guide](GUIDE.md) for supported
builds, limitations, and troubleshooting.

## Build and install

In elevated PowerShell:

Enable test mode to allow self signed kernel drivers, if not already:

```powershell
.\scripts\Enable-TestSigning.ps1
Restart-Computer
```

Build:

```powershell
.\scripts\Build.ps1 -Configuration Release
$env:PPL_TEST_PFX_PASSWORD = "choose-a-non-production-password"
.\scripts\New-TestCert.ps1
.\scripts\Sign-Driver.ps1 -Configuration Release
.\scripts\Install-Driver.ps1 -Configuration Release
.\bin\Release\PplCtl.exe info
```

## Try it

```powershell
$target = Start-Process .\bin\Release\test_target.exe -PassThru
.\bin\Release\PplCtl.exe set --pid $target.Id
.\bin\Release\PplCtl.exe query --pid $target.Id
.\bin\Release\PplCtl.exe clear --pid $target.Id

# Remove the blockdll mitigation so the target can load unsigned DLLs
.\bin\Release\PplCtl.exe allow-dlls --pid $target.Id
```

`query` should show `0x31`;
`clear` restores the tracked original protection byte and the original DLL
signature level. Existing handles are not revoked.

For name filters, the on-connect broker, other signers, and all CLI options, see the
[command reference and examples](GUIDE.md#quick-start).

## More information

[Detailed guide](GUIDE.md): full setup, commands, architecture, risks, tests, and troubleshooting.

