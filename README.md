# DseDisabler
Disabler for Driver Signature Enforcement

### Features list
- [X] Patching g_CiOptions using ring0 driver
- [ ] Patching using UEFI

### Usage
Driver supports Manual mapping, so you can use for example kdmapper for mapping driver or just create it using new service (but you need to sign it):
```
sc create dse type=kernel binPath=<path/to/KernelMode.sys>
sc start dse
```
After that start UserMode.exe with `disable` or `enable` arguments.

### Bypassing PatchGuard
Now CI.dll is protected by PatchGuard, to bypass it you have many ways:
- Load NoBsodDriver (Very meme way)
- Disable PatchGuard for example using [EfiGuard](https://github.com/Mattiwatti/EfiGuard)
- After your manipulations, turn DSE back off

### Pictures
![](assets/image.png)
