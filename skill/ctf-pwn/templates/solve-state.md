# Solve State

## Binary

- name:
- arch:
- PIE:
- Canary:
- NX:
- RELRO:
- libc:
- loader:
- seccomp:

## Runtime

- local command:
- remote:
- patched binary:
- notes:

## Interface

- prompts:
- operations:
- limits:
- special parsing:

## Reverse Engineering

- main path:
- vulnerability function:
- data structures:
- important globals:
- important offsets:

## Primitive

- type:
- trigger:
- controlled data:
- constraints:
- proven in GDB:

## Known Values

- PIE base:
- libc base:
- heap base:
- stack leak:
- canary:
- saved RIP offset:
- target addresses:

## Heap / glibc (fill before choosing a heap route)

- glibc version:
- live mitigations: tcache key (2.29+)? safe-linking (2.32+)? hooks present (<=2.33)?
  vtable check? top/largebin checks? tcache_max raised (2.42+)? fastbins present?
- heap leak (needed for safe-linking forgery):
- chosen route / House-of:
- control target (must exist on this version):

## Heap Layout

```text
index | size | state | notes
```

## Plan

- leak:
- strengthen primitive:
- hijack target:
- final payload:

## Debug Breakpoints

```gdb
# add breakpoints here
```

## Failed Routes

- route:
  reason:
