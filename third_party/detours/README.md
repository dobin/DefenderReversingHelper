# third_party/detours

`DetoursLib.vcxproj` compiles Microsoft Detours from source into
`bin\<Configuration>\detours.lib`. The Detours source itself is **not** copied
into this repository; it stays in its own checkout.

Default location: `C:\Repos\Detours` (the checkout used by this lab).

Override it either way:

```powershell
# Command line
.\scripts\Build.ps1 -Configuration Release -DetoursDir C:\src\Detours

# Or an environment variable before building
$env:DETOURS_DIR = 'C:\src\Detours'
```

`scripts\Build.ps1` forwards `-DetoursDir` as the MSBuild property.

The library is linked by `dll_injector\detours_payload\MpEngineHook.vcxproj`.
Detours is MIT-licensed; see the `LICENSE.md` in the Detours checkout.
