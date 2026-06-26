# Technique Index

Use this as a routing table after the primitive and constraints are known.

## Stack

Signals:

- linear overflow into saved RIP
- canary leak available
- small overflow that controls saved RBP
- enough ROP gadgets or useful PLT

Routes:

- ret2win: PIE off or leaked PIE, direct win/backdoor function.
- ret2libc: leak libc, call `system('/bin/sh')`, add `ret` for amd64 stack alignment when needed.
- ret2syscall: static binary or rich gadgets; set syscall registers and use `syscall` or `int 0x80`.
- ret2csu: amd64 binary lacks normal `pop rdx`; use `__libc_csu_init` gadgets to call a function pointer.
- stack pivot: limited overflow controls saved RBP/RIP; pivot to `.bss`, heap, or controlled stack.
- ret2mprotect + shellcode: NX bypass when writable memory can be made executable.
- SROP: syscall gadget and control over a fake sigreturn frame.
- BROP: remote blind service restarts with stable mappings.

Verify:

```gdb
x/gx $rbp+8
tele $rsp 40
p/d ($rbp+8)-BUFFER
vmmap
rop --grep 'pop rdi'
```

Pitfalls:

- IDA stack offsets can be wrong; measure in GDB.
- `system` may require stack alignment on amd64.
- Canary must be preserved unless bypassing the epilogue.
- One-gadget constraints must be checked against live registers and stack.

## Format String

Signals:

- user-controlled string passed to `printf`-like function as format.
- output includes pointers with `%p`.
- `%n`, `%hn`, or `%hhn` not blocked.

Routes:

- leak stack, PIE, libc, or canary using `%p` or `%s`.
- arbitrary read: place address after the format and use `%k$s`.
- arbitrary write: `fmtstr_payload` or staged `%hn/%hhn`.
- overwrite return address, GOT if RELRO permits, fini_array, hooks if present, FILE fields, or loop control variable.

Verify:

```text
AAAA-%p-%p-%p-%p-%p-%p-%p-%p
```

Pitfalls:

- On amd64, addresses containing NUL bytes may need to be placed after the format string and referenced with a later argument index.
- Sort writes from small to large for `%hn`.
- Full RELRO blocks GOT overwrite but not return address or writable control data.

## Shellcode and Seccomp

Signals:

- NX off, RWX mmap, JIT buffer, or executable stack.
- seccomp blocks `execve`.
- input restricts bytes, length, or visible characters.

Routes:

- normal `/bin/sh` shellcode if `execve` allowed.
- ORW: `open/openat`, `read`, `write`.
- `sendfile` if allowed and convenient.
- `mmap` or `mprotect` to place executable second-stage shellcode.
- visible-character shellcode with AE64/alpha encoders.
- retfq/int 0x80 mode switch if 64-bit seccomp misses 32-bit syscalls.
- socket exfiltration if fd 0/1/2 are closed.

Verify:

```bash
seccomp-tools dump "$BIN"
```

```gdb
vmmap
info registers
```

Pitfalls:

- `open` may be blocked while `openat` is allowed.
- Shellcode length and forbidden-byte constraints decide the payload shape.
- If stdout is closed, ORW must write to a valid fd or exfiltrate.

## Heap (edit-primitive routing)

Before choosing a House-of, ask **where your edit/write lands inside a freed chunk** — that
decides which metadata you can forge, and it constrains you more than the glibc version does:

| Your write reaches | You can forge | Route to |
|---|---|---|
| `user+0` (fd / tcache-next / fastbin fd) | freelist `fd` | tcache poisoning, fastbin dup, fd-based unsorted/largebin |
| ONLY `user+8..` (`bk`, `fd_nextsize`, `bk_nextsize`) — never `user+0` | `bk` + nextsize | **bk-based only**: unsorted-bin attack; largebin only if the 2.30+ insertion checks and size ordering are satisfiable |
| full chunk contents (big overflow/edit) | everything | overlap, fake FILE/FSOP, anything |

Key consequence: **if the edit cannot touch `user+0`, tcache/fastbin fd-poison is impossible.**
A 0x18-byte write at `user+8` that hits exactly `bk | fd_nextsize | bk_nextsize` used to be
a strong hint for **largebin / House of Storm**, but on glibc 2.30+ it is only a candidate:
the allocator validates nextsize back-links and the write happens only on the right
different-size insertion path. Prove the write in GDB before building the exploit around it.

Match the technique to an available **post-leak trigger** — as important as the write itself:

| Trigger you have | Write target | Technique |
|---|---|---|
| `free()` (release/delete menu) | `__free_hook = one_gadget` (≤2.33) | simplest; needs no printf/exit |
| `malloc()` | `__malloc_hook = one_gadget` (≤2.33) | similar |
| a `printf("%…")` that runs again | `__printf_arginfo_table` / `__printf_function_table` | House of Husk |
| `exit()` / `main` return | `_IO_list_all` fake FILE | FSOP (Orange/Apple/Cat/…) |

If your only leak and the only reachable trigger **collide** (classic trap: a *one-time*
`%s` leak that is also the only printf you could use to fire House of Husk), do not force
that technique — pivot to a `free()`/`malloc()` hook write, which needs no printf/exit
trigger at all. Spending hours on Husk/FSOP when `__free_hook` was right there is avoidable.

Reachability check before committing to FSOP / House of Husk: with smallest carve size `S`,
edits reach victim offsets `{fixed_window} + S*k` only. The FILE vtable is at `+0xd8` and
`_allocate_buffer` at `+0xe0`; if those are off the grid (e.g. S=0x50 → reachable offsets
`{0x18,0x20,0x28} mod 0x50`, which miss `0xd8`) you cannot plant a vtable and FSOP is dead
regardless of version. Likewise House of Husk needs the gadget at `table[conv_char]*8`,
reachable only if that offset is on the grid AND that conv char belongs to a usable trigger.

## IO_FILE and FSOP

Signals:

- libc leak plus arbitrary write to libc/heap.
- stdout/stderr/stdin structures reachable.
- glibc 2.24+ vtable checks affect classic fake vtable paths.
- glibc 2.34+ hooks are gone, making FILE/exit/rtld paths more important.

Routes (full details and per-version viability in `references/house-of-techniques.md`):

- **data-only FILE arbitrary read/write (no vtable, all glibc — go-to leak/write on 2.34+)**:
  - stdout arbitrary read: `_IO_2_1_stdout_._flags=0xfbad1800`, `_IO_read_end=_IO_write_base`,
    `_IO_write_base=addr`, `_IO_write_ptr=_IO_write_end=addr+len` -> next flush leaks `[addr,+len)`.
    1-byte form: only `_flags=0xfbad1800` + partial-overwrite `_IO_write_base` LSB -> libc leak.
  - stdin arbitrary write: `_IO_2_1_stdin_._flags=0xfbad0000`, `_IO_read_base=_IO_read_ptr=
    _IO_read_end=addr`, `_IO_buf_base=addr`, `_IO_buf_end=addr+len` -> next scanf/fread refill
    does `read(0, addr, len)`. Full recipe + offsets in `house-of-techniques.md`.
- House of Orange on older libc with `_IO_list_all`; House of Tangerine is the modern successor.
- House of Apple 2 is the default 2.35+ FSOP RIP hijack; House of Cat for clean RDX ->
  setcontext/ORW; plus Kiwi/Husk/Banana/Emma/Obstack/Pig depending on version and trigger.
- setcontext + ORW when shell is blocked or seccomp exists.

The `_IO_vtable_check` (since 2.24) forces the real `vtable` into `__libc_IO_vtables`. The
key modern bypass: the **wide** vtable `_IO_wide_data->_wide_vtable` is NOT validated, so
set the FILE's `vtable = _IO_wfile_jumps` and let a `_IO_wfile_*` function dereference your
controlled `_wide_vtable->__doallocate/overflow`. This is why House of Apple 2 still works
on the latest libc.

Verify:

```gdb
p/x &_IO_2_1_stdout_
p/x &_IO_2_1_stdin_
p/x &_IO_wfile_jumps
x/40gx &_IO_2_1_stdout_
```

Pitfalls:

- Pointer mangling and vtable validation matter on newer glibc.
- Modern FILE techniques are version-sensitive; confirm offsets and call path under GDB.
- Exit-handler and `_IO_cookie` function pointers are PTR_MANGLE'd (xor with `fs:[0x30]`);
  you need the pointer guard before forging them.

## Reverse and Protocol

Signals:

- custom packet format or serialized messages.
- protobuf-c descriptors.
- crypto/checksum gate before the vulnerable operation.

Routes:

- Rebuild protocol helpers in Python.
- For protobuf-c, search for magic `0x28AAEEF9` and reconstruct descriptors.
- Recognize common algorithms:
  - MD5 constants: `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`.
  - SHA constants and 64/80-round compression.
  - TEA family: delta `0x9e3779b9`.
  - RC4: 256-byte S-box and KSA/PRGA loops.
  - Base64 table and 3-to-4 byte encoding.
  - CRC32 polynomial `0xedb88320`.

Pitfalls:

- Do not hand-concatenate complex protocol data when a generated encoder is practical.
- Verify endian and length prefixes with GDB or packet logs.

## Special Tricks

Use only when the normal path is blocked by constraints:

- fini_array loop to regain multiple bug triggers.
- overwrite TLS `stack_guard` if a large overflow in a thread reaches TLS.
- `__environ` leak for stack address.
- partial overwrite when ASLR leaves low bytes stable.
- scanf `+` behavior to preserve old stack data in some inputs.
- anti-debug/ptrace bypass by patching or interrupt tricks.
- SUID payloads may need `setuid(geteuid())` before `execve`.
