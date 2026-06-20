# Synology DS918+ Deployment Notes

## System

```
Linux njord 4.4.180+ #42962 SMP Tue Jul 29 14:30:39 CST 2025 x86_64 GNU/Linux
Model: Synology DS918+ (apollolake)
CPU:   Intel Celeron J3455 (Apollo Lake / Goldmont microarchitecture)
```

## Zig Target

**Target triple:** `x86_64-linux-gnu`  
**CPU model:** `goldmont`

```bash
zig build-exe foo.zig -target x86_64-linux-gnu -mcpu=goldmont
```

In `build.zig`:

```zig
.target = b.resolveTargetQuery(.{
    .cpu_arch = .x86_64,
    .os_tag = .linux,
    .abi = .gnu,
    .cpu_model = .{ .explicit = &std.Target.x86.cpu.goldmont },
}),
```

## Platform Constraints

- **No AVX** — Goldmont is an in-order Atom-class core. Binaries compiled with `native` or any AVX-enabled CPU on a dev machine will crash on the NAS.
- **Kernel 4.4** — avoid syscalls added after kernel 4.4.
- **ABI is `gnu`** (glibc) — Synology DSM ships glibc but an older version. Linking against a too-new glibc will fail at runtime. For a fully static binary with no glibc dependency, use `-Dtarget=x86_64-linux-musl` instead.
