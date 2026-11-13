# DefenderReversingHelper

A test-signed Windows driver and CLI that grant: 
* **Protected Process Light (PPL)** to a process by PID, name filter, or named-pipe connection.
* Remove the **block non-Microsoft binaries** process mitigation of processes
* Clear **Arbitrary Code Guard (ACG)** so an in-process Detours hook can patch code
* DLL inject into `MsMpEng.exe`
* Emit WdFilter-style file/process **kernel telemetry** over the minifilter
  communication port `\MpEngineTelemetryPort` for a user-mode consumer

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

To restart a protected process, use `kill` (it force-clears PPL and repairs the
handle access that self-protection stripped, which `Stop-Process` cannot):

```powershell
.\bin\Release\PplCtl.exe kill --pid <pid> --wait
```

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
.\bin\Release\rsignal_etw_listener.exe --out rsignal.txt

# Terminal 2 (elevated)
.\bin\Release\injector.exe MsMpEng.exe .\bin\Release\mpengine_hook.dll `
    --ppl --allow-dynamic-code --fix-handle --kernel-thread --restore
```

For name filters, the on-connect broker, other signers, and all CLI options, see the
[command reference and examples](GUIDE.md#quick-start).

## Kernel telemetry source (WdFilter-style)

`MakeMePPL.sys` is also a minifilter. It mirrors the shape of `WdFilter.sys`:
a filter-manager communication port plus `FltSendMessage` telemetry, a
process-creation callback, and file callbacks for create/write/cleanup/rename/
delete. The wire protocol and the WdFilter analysis are documented in
[docs/mp_telemetry.md](docs/mp_telemetry.md).

The consumer lives in `C:\Data\defender-2026-autumn\mpclient`
(`mpengine_client.exe agent`). The agent connects to
`\MpEngineTelemetryPort`, converts the messages into RTP notes and forwards
them to `mpengine.dll` through `__rsignal`/0x4039, along with its ETW sources.

```powershell
# Elevated: reload the driver in place (no reboot needed)
.\scripts\Uninstall-Driver.ps1        # sc stop + sc delete; the unload callback
                                     # restores tracked protections first
.\scripts\Install-Driver.ps1
.\bin\Release\PplCtl.exe info       # telemetry : minifilter active

# Other repository: agent plus kernel telemetry
cd C:\Data\defender-2026-autumn\mpclient
.\mpengine_client.exe agent --seconds 10
.\mpengine_test.exe diag drv --seconds 3 --no-elevate
```

`Install-Driver.ps1` writes the minifilter `Instances\MakeMePPL Instance`
altitude/instance registry values between `sc create` and `sc start`.
`MpTelemetryInitialize` is best effort: if `FltRegisterFilter` or
`FltStartFiltering` fails, PPL/injection keep working and `PplCtl info`
reports `telemetry : unavailable`. The port DACL allows any local user,
consistent with the rest of this test driver; restrict it before using this
outside an isolated VM.

Because the minifilter registers a `FilterUnloadCallback`, `sc stop` performs a
full unload instead of requiring a reboot. Close the agent and `PplCtl` first:
an open handle to the control device keeps the driver image referenced after
the filter unregisters.

## More information

[Detailed guide](GUIDE.md): full setup, commands, architecture, risks, tests, and troubleshooting.

