---
name: ppl-executor
description: "Use when testing software as Windows Protected Process Light (PPL) with MakeMePPL and pplctl: grant by PID, image-name filter, or a target connecting to the PplGrant broker. Requires an already-loaded driver; verify readiness, protection, and cleanup."
---

# PPL software testing

Use only in an isolated Windows 11 x64 test VM with the driver already loaded.
See [README](./README.md) for command details and user-managed driver setup.

## Guardrails

- Confirm the intended target before changing protection. Never target system processes
  or the agent's shell/host unless explicitly required for the test.
- Use signer `am` (`0x31`); use `wintcb` only if explicitly requested.
- Do not build, sign, install, start, stop, or uninstall the driver, enable test signing,
  reboot, or guess/patch kernel offsets. Report missing prerequisites to the user.
- The control device allows all local users. The broker also defaults to Everyone:
  any connecting process becomes PPL. Restrict its lifetime to the test and prefer
  `--admin-only` when the target can run elevated or as SYSTEM.
- Always verify grants and clean up test-owned protections, filters, and brokers.

## Preflight — once per session

```powershell
$PplCtl = (Resolve-Path .\bin\Release\PplCtl.exe -ErrorAction Stop).Path
& $PplCtl info
if ($LASTEXITCODE -ne 0) { throw 'Driver not ready; stop and notify the user.' }
```

Require `driver status : STATUS_SUCCESS` and a real `PPL offset` (not `-` or
`(unsupported build)`). Filters additionally require `notify callback: registered`.
On failure, stop and report the exact output; do not repair the environment.
Missing CLI, device error 2, and device error 5 mean missing binary, unloaded driver,
and an older admin-only device DACL respectively. CLI commands otherwise need no elevation.

## Choose the narrowest method

| Need | Method |
|---|---|
| One running process | PID; confirm its image path and PID |
| Repeated launches | Exact image-name filter |
| Application can request PPL itself | On-connect; the target must open the pipe |

## PID

```powershell
$target = @(Get-Process -Name test_target -ErrorAction Stop)
if ($target.Count -ne 1) { throw 'Expected exactly one target process.' }
$targetPid = $target[0].Id
$target[0].Path
# Confirm this is the intended image before granting.
& $PplCtl set --pid $targetPid --signer am
if ($LASTEXITCODE -ne 0) { throw 'PPL grant failed.' }
```

## Image-name filter

Matches the base image name case-insensitively. Prefer `--exact`; the default is a
substring match. Patterns must be 3–127 characters; at most 16 filters are allowed.

```powershell
& $PplCtl filter add --name 'test_target.exe' --exact --signer am
if ($LASTEXITCODE -ne 0) { throw 'Filter registration failed.' }
$newTarget = Start-Process .\test_target.exe -PassThru
$targetPid = $newTarget.Id
Start-Sleep -Milliseconds 500
```

**Protection is deferred (about 100 ms), not instantaneous!**

Add `--apply-existing` to
`filter add` to include running matches; inspect `applied=`, `skipped=`, and `failed=`.
Already-protected, blocklisted, and calling CLI processes are skipped. Duplicate patterns
return `STATUS_OBJECT_NAME_COLLISION`; inspect `filter list` and reuse/remove the filter.
Removing a filter stops future grants but does not unprotect existing processes.

## On-connect broker

Run in a second console; this command blocks. `--once` exits after one client:

```powershell
& $PplCtl broker --signer am --once
```

Use `--admin-only` for elevated/SYSTEM clients; otherwise the pipe allows Everyone.
The **target process itself** must open `\\.\pipe\PplGrant` using `CreateFileW`, read
the reply with `ReadFile`, then close the handle. Retry briefly on `ERROR_PIPE_BUSY` or
`ERROR_FILE_NOT_FOUND`. Require `OK pid=<targetPid> protection=0x31 ...`; treat `ERR ...`
or an unavailable broker as test failure when PPL is required. `--pipe <name>` overrides
the pipe name; both sides must agree.

`pplctl connect` protects the CLI itself, not another application. It is only a smoke
test; it waits for Enter unless `--hold N` is supplied. Do not inject helpers into a target;
use PID/filter instead. Closing the pipe or stopping the broker does not remove PPL.

## Remove the blockdll mitigation

If the target was created with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` /
`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` (or enabled
`ProcessSignaturePolicy/MicrosoftSignedOnly` at runtime), unsigned DLLs are refused with
error 577. Remove that state only for the test target:

```powershell
& $PplCtl allow-dlls --pid $targetPid
& $PplCtl query --pid $targetPid   # block non-MS DLLs: off
```

The change is tracked; `clear --pid` and driver unload restore it. `allow-dlls` returns
`STATUS_NOT_SUPPORTED` on builds without a MitigationFlags offset.

## Clear ACG for Detours

Detours must make the target's image code pages writable. If ACG
(`ProcessDynamicCodePolicy`) is enabled, `DetourTransactionCommit` fails with
`ERROR_DYNAMIC_CODE_BLOCKED` (1655). Clear it only for the test target:

```powershell
& $PplCtl allow-dynamic-code --pid $targetPid
& $PplCtl query --pid $targetPid   # MitigationFlags1 bit 8 (0x100) clear
```

This is tracked and shares the same entry as `allow-dlls`; one `clear --pid` restores
both. Use `injector.exe ... --allow-dynamic-code` to clear it as part of an injection.

## Verify every grant

```powershell
& $PplCtl query --pid $targetPid
& $PplCtl probe --pid $targetPid
```

Require successful `query`, `protection : 0x31 (type=ppl, signer=antimalware, audit=0)`,
and `PsIsProtectedProcessLight: TRUE` for signer `am`. Run `probe` elevated when possible
so it can enable `SeDebugPrivilege`: expect `PROCESS_ALL_ACCESS` and
`VM_READ|QUERY_INFORMATION` denied; `QUERY_LIMITED_INFORMATION` usually opens.
`probe` exits 0 even on denial—inspect its output. Unelevated denials are weaker evidence.

If protection is `0x00`, recheck PID, filter match, and driver readiness. Existing handles
are not revoked, an attached debugger may retain access, and children do not inherit PPL.

## Cleanup and report

First remove any filters added for this test to prevent new grants, then clear every
protected PID, including filter/broker clients:

```powershell
& $PplCtl filter remove --name 'test_target.exe'
& $PplCtl clear --pid $targetPid
```

Stop the test broker/clients (Ctrl+C, or a specific recorded PID). Leave the driver loaded.
Clear protection before attempting to terminate a protected target. `STATUS_NOT_FOUND`
is harmless if it exited; `STATUS_ACCESS_DENIED` on clear means untracked protection—do
not force removal. `clear --pid` also restores an `allow-dlls` or
`allow-dynamic-code` change. Report failures or
remaining PPL to the user; never reboot to fix them.
For `STATUS_NOT_SUPPORTED`, stop and report an unsupported build or missing callback.

Report method/signer, target PIDs/patterns/pipe, verification results, and cleanup or
remaining protection. Further command and failure details: [README](./README.md).
