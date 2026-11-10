# DefenderReversingHelper

A test-signed Windows driver and CLI that grant: 
* **Protected Process Light (PPL)** to a process by PID, name filter, or named-pipe connection.
* Remove the **block non-Microsoft binaries** process mitigation of processes
* Clear **Arbitrary Code Guard (ACG)** so an in-process Detours hook can patch code
* DLL inject into `MsMpEng.exe`

It ships a DLL injector, `bin\Release\injector.exe`, with driver-backed
`--ppl`, `--allow-dynamic-code`, `--fix-handle`, and `--kernel-thread` options.
Together they can load a DLL into a protected process such as `MsMpEng.exe`.
See [dll_injector](dll_injector/README.md) for usage and caveats.

It also ships `bin\Release\mpengine_hook.dll`, a Microsoft Detours payload that
hooks `mpengine.dll!__rsignal` and emits each call's arguments and pointed-to
data as ETW/TraceLogging events. `bin\Release\rsignal_etw_listener.exe`
(third_party/krabsetw) renders them in another process. Detours is compiled from
its source checkout (`C:\Repos\Detours` by default). Use `--allow-dynamic-code`
in addition to `--ppl` when the target has ACG. See
[dll_injector/detours_payload](dll_injector/detours_payload/README.md) and
[tools/etw_listener](tools/etw_listener/README.md).

The purpose is to enable AI agents to start tools as PPL. 

> **Isolated test VM only.** Unsupported kernel memory modification can crash Windows.
> Take a snapshot first. The driver allows **any local user** to grant or clear PPL on
> non-blocklisted processes; the optional broker also allows everyone by default.
> Never use on a production host.

Vibe coded by Deepseek V4.1 Flash. With input from [KDU](https://github.com/hfiref0x/KDU). 
Similar to [PPLRunner](https://github.com/pathtofile/PPLRunner) but easier to use. 
Based on the initial [MakeMePPL](https://github.com/dobin/MakeMePPL) tool. 

## Requirements

- Windows x64 test VM; Windows 11 24H2/25H2 is the tested target.
- Visual Studio 2022: **Desktop development with C++** workload.
- Windows SDK and WDK **10.0.26100.0**, including `WindowsKernelModeDriver10.0`.
- A Microsoft Detours source checkout at `C:\Repos\Detours`, or pass
  `-DetoursDir <path>` / set `DETOURS_DIR`.
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

# Clear ACG so an in-process Detours hook can modify code pages
.\bin\Release\PplCtl.exe allow-dynamic-code --pid $target.Id
```

`query` should show `0x31`;
`clear` restores the tracked original protection byte and the original DLL
signature level. Existing handles are not revoked.

### Inject a DLL

Normal target:

```powershell
$target = Start-Process .\bin\Release\test_target.exe -PassThru
.\bin\Release\injector.exe $target.Id .\bin\Release\payload.dll
Get-Content "C:\data\dll_load_$($target.Id).txt"
```

Protected target (`MsMpEng.exe`) from an elevated console with the driver
loaded:

```powershell
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\payload.dll `
    --ppl --fix-handle --kernel-thread --restore
```

`--ppl` clears PPL and the blockdll mitigation before `OpenProcess`;
`--allow-dynamic-code` also clears ACG (needed by the Detours payload);
`--fix-handle` repairs access stripped by Defender self-protection;
`--kernel-thread` creates the remote thread from kernel mode; `--restore`
puts the original protection back afterwards. See
[dll_injector/README.md](dll_injector/README.md).

To hook `mpengine.dll!__rsignal` from inside the engine and stream its data over
ETW, start the listener and then inject the Detours payload:

```powershell
# Terminal 1 (elevated)
.\bin\Release\rsignal_etw_listener.exe --pid <MsMpEng pid>

# Terminal 2 (elevated)
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

For name filters, the on-connect broker, other signers, and all CLI options, see the
[command reference and examples](GUIDE.md#quick-start).

## More information

[Detailed guide](GUIDE.md): full setup, commands, architecture, risks, tests, and troubleshooting.

