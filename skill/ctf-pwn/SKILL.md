---
name: ctf-pwn
description: CTF pwn solving workflow for Codex with tmux-CLI-driven persistent-GDB live debugging: protection checks, libc/loader matching, IDA or idalib reverse engineering, pwntools wrappers, mandatory GDB-pwndbg inferior-tty step debugging, heap/stack/libc state inspection, and exploit strategy selection by primitive, glibc version, and challenge limits.
---

# CTF Pwn

This skill follows the portable `SKILL.md` convention and runs unchanged under Codex (`~/.codex/skills/ctf-pwn`), Claude Code (`~/.claude/skills/ctf-pwn` or project `./.claude/skills/ctf-pwn`), and any other agent that loads SKILL.md skills. Reference files under `references/` are loaded on demand; read them when the topic matches.

Use this skill for local or remote CTF pwn challenges. Work like a pwn player: reproduce the remote runtime, reverse the binary, wrap the protocol/menu, then prove the vulnerability with a persistent GDB/pwndbg session before committing to an exploit route. For live debugging the primary path is a persistent GDB driven through plain `tmux` CLI from Bash (`tmux send-keys` to issue commands, `tmux capture-pane -p -S -` to read the full output), so you can step, inspect, and decide the next command adaptively — no MCP server required. Keep GDB, normal shell, and inferior stdin/stdout in separate tmux panes, feed the inferior through its TTY, and inspect state after each meaningful step. Use one-shot/batch GDB only to verify a known hypothesis.

## Mandatory References

Read these reference files when the topic is relevant:

- `references/ctf-workflow.md`: end-to-end solve order, state tracking, environment matching, reverse engineering, and debug loop.
- `references/tmux-debugging.md`: tmux-CLI persistent-GDB pane layout (plus batch-GDB for verification), inferior-tty setup, step debugging loop, and stdin redirection discipline.
- `references/exploit-templates.md`: pwntools skeletons, menu wrappers, GDB attach patterns, and state notes.
- `references/technique-index.md`: stack, format string, shellcode, seccomp, IO_FILE, reverse/protocol, and special trick routing.
- `references/glibc-heap-version-map.md`: heap exploitation choices by glibc version, allocator protection, primitive, and challenge limits. Read this first for any heap challenge.
- `references/house-of-techniques.md`: the full "House of" catalog (and modern FSOP foundation) — applicable versions, preconditions, core idea, target, and how to drive each one, current through glibc 2.43. Read this whenever a heap route involves a House-of, FILE/FSOP, largebin, or `_rtld_global` technique.

## Core Rules

- During dynamic analysis, drive a persistent GDB through a `tmux` CLI session first. Create or reuse `work`, `gdb`, and `inferior-tty` panes; run GDB in the GDB pane; set `inferior-tty` to the inferior pane TTY; send program input to the inferior pane with `tmux send-keys`; issue GDB commands to the GDB pane and read output with `tmux capture-pane -p -S -` (full scrollback).
- Do not replace first-pass debugging with a one-shot pwntools script, GDB heredoc, or static reasoning. Use scripts to reproduce states, but drive a persistent GDB/pwndbg (tmux CLI) to observe registers, stack, heap chunks, bins, mappings, and crash sites step by step. Batch/one-shot GDB is for verifying a known hypothesis, not for exploring.
- If a command or exploit crashes, returns EOF, desynchronizes prompts, or hits an allocator abort, stop and inspect the live tmux/GDB state before editing the exploit. Do not guess the next payload from source alone.
- Do not jump straight to exploit writing. First record protections, libc/loader, I/O protocol, vulnerability site, primitive, and constraints.
- Match the remote runtime before relying on offsets: use the provided `libc.so.6` and loader when present, or identify/download the matching libc if needed.
- If the user provides an IDA path, IDB path, or IDA MCP connection, use IDA for first-pass reverse engineering before objdump-style static disassembly. `objdump` is only for quick sanity checks, symbol/protection inventory, or when IDA is unavailable. Use dynamic GDB verification for every important reverse-engineering assumption.
- Build small pwntools wrappers for the challenge interface before exploitation. Heap/menu challenges should have `add`, `edit`, `show`, `delete/free`, and `choice` helpers when those actions exist.
- Use a persistent GDB driven via direct `tmux` CLI (`send-keys` / `capture-pane -p -S -`) as the interface for interactive debugging whenever live debugging is needed. Keep normal shell, GDB, and inferior stdin/stdout separate.
- Do not drive GDB with large one-shot heredoc scripts when the inferior needs stdin. Prefer `set inferior-tty /dev/pts/N`; use `gdb.attach` only after the tmux/GDB state has already proved the primitive or when inferior-tty is impractical.
- After a crash, EOF, wrong leak, allocator abort, unstable shell, or heap-layout-dependent failure, attach GDB or stop in tmux/GDB and inspect the exact memory state before changing the exploit. For heap challenges, build the next step from the current chunks, bins, pointer arrays, safe-linking values, and mapped target addresses observed in memory.
- Choose exploitation techniques by evidence: glibc version, available leaks, write primitive, allocation/free limits, size restrictions, RELRO, PIE, NX, canary, seccomp, and whether hooks exist.
- Keep a solve state file or notes. Record exact offsets, bases, chunk addresses, target addresses, constraints, failed approaches, and why each exploit path is still viable.

## Standard Solve Flow

1. Inventory files and protections.
2. Reproduce runtime with the supplied libc/loader or patch/run with the right environment.
3. Reverse main paths, menu actions, data structures, and vulnerability site.
4. Write minimal pwntools wrappers for the real interaction model.
5. Use a persistent GDB (tmux CLI) + pwndbg + inferior-tty to validate the bug and measure offsets/state before relying on `exp.py`.
6. Classify the primitive: overflow, OOB, UAF, double free, off-by-one/null, format string, arbitrary read/write, shellcode, seccomp, protocol bug, etc.
7. Select a route using `technique-index.md` and `glibc-heap-version-map.md`.
8. Implement only the next tested step in `exp.py`: leak, base calculation, primitive strengthening, control-flow hijack, ORW, or shell.
9. Re-run under GDB at the dangerous instruction/allocator operation and inspect memory.
10. Repeat until the exploit succeeds locally with the matched libc, then adapt remote host/port.

## Heap Challenge Protocol

Heap exploitation is version-gated: the same primitive maps to different routes per glibc
version, because each release adds allocator checks and removes targets. For any heap
challenge, work in this order and record each result in the solve-state file.

1. **Fingerprint the glibc version first**, before choosing any technique. Use
   `strings libc.so.6 | grep 'GLIBC_2\.'`, `gnu_get_libc_version`, and symbol presence in
   GDB (`p &__free_hook`, `p &__libc_csu_init`, `p &_IO_wfile_jumps`).
2. **Enumerate the live mitigations for that version** using
   `references/glibc-heap-version-map.md`. Key inflection points to settle explicitly:
   - tcache introduced at **2.26**; tcache double-free **key at 2.29** (not 2.32).
   - top-chunk size check at **2.29** (House of Force dead).
   - largebin ordering checks at **2.30** (House of Storm dead).
   - **Safe-Linking + alignment check at 2.32** (fd is `(pos>>12) ^ ptr`; need a heap leak;
     target must be 16-byte aligned).
   - **malloc/free hooks removed at 2.34** (and `__libc_csu_init` gone); pivot to FSOP /
     exit handlers / `_rtld_global` / setcontext.
   - IO vtable check since **2.24**; House of Apple 2 / Cat bypass it via the unchecked
     **wide vtable** (`_IO_wfile_jumps`), still working on the latest libc.
   - **2.42** lets tcache cache large blocks (tunable `glibc.malloc.tcache_max`, up to 4 MB):
     if raised, large frees no longer fall into the unsorted bin — verify before leaking.
   - **Fastbins are NOT removed as of 2.43 (Jan 2026)**; removal is a proposed Oct 2025
     patch series for a future release. On bleeding-edge libc, confirm fastbins exist in GDB.
3. **Classify the primitive and constraints** (UAF/overflow/off-by-null/double-free; show?
   edit count? free count? size class limits? seccomp?).
4. **Pick a route** by crossing off whatever the version killed. For any House-of, FILE/FSOP,
   largebin, or `_rtld_global` route, use `references/house-of-techniques.md` to get the
   preconditions, the exact fields/offsets to forge, and current viability.
5. **Decide what you still need**: heap leak (mandatory for safe-linking on 2.32+), libc
   leak, and a control target that still exists in this version.
6. **Prove each heap step in GDB** (chunks, bins, safe-linked fd, target writability) before
   committing it to `exp.py`. Derive the next allocation/poison/overlap from observed memory.

## Initial Recon Commands

Run the relevant commands from a normal shell pane:

```bash
BIN=./<target-elf>
file ./*
checksec --file="$BIN"
readelf -hW "$BIN"
readelf -lW "$BIN"
readelf -sW "$BIN" | grep -E ' main| win| vuln| malloc| calloc| realloc| free| read| write| puts| printf| scanf| open| seccomp| mprotect| mmap'
readelf -rW "$BIN"
strings -a "$BIN" | head -200
strings -a ./libc.so.6 2>/dev/null | grep -E 'GNU C Library|GLIBC'
```

Set `BIN` to the actual target ELF from the current task. Do not assume the binary is named `chal`; identify it from the supplied files or the user's stated path.

If seccomp may exist:

```bash
seccomp-tools dump "$BIN"
```

If a custom libc/loader exists, prefer running the binary like this instead of exporting `LD_LIBRARY_PATH=.` globally:

```bash
./ld-linux-x86-64.so.2 --library-path . "$BIN"
```

Patch only when useful for repeatability:

```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 "$BIN"
patchelf --replace-needed libc.so.6 ./libc.so.6 "$BIN"
```

If patching changes the original challenge binary, keep an untouched copy.

## Reverse Engineering Expectations

Use IDA/idat/idalib when available. If the user gave an IDA path, IDB path, or IDA MCP connection, that is an explicit requirement to use IDA as the main reverse-engineering path:

- Identify menu actions, object arrays, size tables, indexes, and global pointers.
- Name functions and structs as they become clear.
- For each input path, record destination buffer, maximum read length, signedness, terminator behavior, and whether NUL bytes are accepted.
- For heap challenges, reconstruct chunk lifecycle: allocation size, pointer storage, edit length, show behavior, free behavior, UAF/nulling, and count limits.
- For protocol challenges, write encode/decode helpers instead of hand-concatenating bytes.
- For leak/write *offsets and bit math*, confirm against the disassembly, not just Hex-Rays. The decompiler often misrenders bitfield extraction — e.g. it printed `(ptr>>40)&0xff` (`WORD2(x)>>8`) where the actual instruction was `movzbl %al` = `ptr&0xff`. Misreading what a token/leak exposes (which bits, how wide) can send you down the wrong strategy for hours.
- Verify decompiler assumptions in GDB at the relevant `read`, `malloc`, `free`, comparison, return, or syscall.

## Live Debugging Setup (tmux CLI)

Default interactive path: a **persistent GDB driven through plain `tmux` CLI from Bash** — issue
a command with `tmux send-keys`, read the result with `tmux capture-pane -p -S -` (full
scrollback, not just the visible screen), decide the next command, repeat. This lets you step
and adapt like a human pwner, needs no MCP server, and survives long sessions; each step is one
Bash call. Reserve one-shot/**batch GDB** (`gdb -batch -p PID -ex ...`, or `... -ex 'run < in'
BIN`) for verifying a known target, not for exploration.

```bash
tmux new-session -d -s pwn -x 200 -y 50
tmux set-option -t pwn history-limit 100000        # keep full scrollback
# pane 0 = inferior TTY: run `tty` there, note the /dev/pts/N it prints
# pane 1 = gdb:  gdb -q "$BIN"   then configure:
#   set pagination off / confirm off / disassemble-next-line on / disable-randomization on
#   set inferior-tty /dev/pts/N           # program I/O and GDB input never share stdin
# per step (one Bash call): send, settle, read everything
tmux send-keys -t pwn 'b *vuln+OFF' Enter; tmux send-keys -t pwn 'run' Enter; sleep .3
tmux capture-pane -p -t pwn -S -
```

Send program input to the inferior pane, GDB commands to the GDB pane; wait for the prompt
before `send-keys` (poll the pane, don't fixed-sleep). Full command templates, the step loop,
the batch/gate alternative, and a stripped-libc `main_arena` note are in
`references/tmux-debugging.md` — read it before any substantial live debugging session.

## Pwndbg Commands

General:

```gdb
context
nearpc
vmmap
piebase
got
plt
info functions
xinfo ADDRESS
tele $rsp 30
x/40gx $rsp
hexdump ADDRESS 0x100
rop --grep 'pop rdi'
rop --grep 'syscall'
```

Stack:

```gdb
canary
b *vuln+OFFSET
x/gx $rbp+8
tele $rbp-0x100 80
p/x $rbp
p/x $rsp
p/d ($rbp+8)-BUFFER_ADDRESS
```

Heap:

```gdb
heap
vis_heap_chunks
bins
arena
chunk PTR
heap_config
x/32gx PTR-0x10
```

Libc/ROP/ORW:

```gdb
vmmap
p/x system
p/x open
p/x read
p/x write
p/x mprotect
x/s ADDRESS
```

## Exploit Script Discipline

Start with wrappers, not a final exploit. The first script should make repeated debugging easy:

```python
from pwn import *
import os

BIN = args.BIN or './<target-elf>'
context.binary = elf = ELF(BIN)
libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else None
ld = './ld-linux-x86-64.so.2'

def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    argv = [elf.path]
    if os.path.exists(ld) and libc:
        argv = [ld, '--library-path', '.', elf.path]
    io = process(argv)
    if args.GDB:
        gdb.attach(io, gdbscript='''
set pagination off
set disassemble-next-line on
continue
''')
    return io
```

For menu binaries, add exact wrappers:

```python
def choice(n):
    io.sendlineafter(b'> ', str(n).encode())

def add(size, data=b''):
    choice(1)
    io.sendlineafter(b'Size:', str(size).encode())
    io.sendafter(b'Data:', data)

def edit(idx, data):
    choice(2)
    io.sendlineafter(b'Index:', str(idx).encode())
    io.sendafter(b'Data:', data)

def show(idx):
    choice(3)
    io.sendlineafter(b'Index:', str(idx).encode())

def delete(idx):
    choice(4)
    io.sendlineafter(b'Index:', str(idx).encode())
```

Adjust prompts to the real binary. Do not hide protocol uncertainty behind broad `sendline()` calls.

When `exp.py` starts failing, add `gdb.attach`, a `PAUSE` point, or a tmux/GDB breakpoint at the operation that changes state. Inspect live memory before editing the payload. Heap exploits often require constructing the next allocation, poison, overlap, or write from the current heap layout rather than from a static plan. Debugger memory writes and `/proc/<pid>/mem` edits are forbidden as exploit steps; they are only acceptable for temporary diagnosis if clearly labeled and then replaced with a real attack primitive.

## Crash and Failure Loop

When the exploit fails:

1. Reproduce with the same payload locally.
2. Break before the suspected failing operation: vulnerable return, `free`, `malloc`, `unlink`, `printf`, syscall, or indirect call.
3. Inspect registers, stack, heap chunks, bins, pointer arrays, mapped pages, and target addresses; for heap bugs, dump the exact chunks involved before and after the operation.
4. Confirm whether the failure is offset, wrong base, alignment, allocator check, safe-linking, bad size class, exhausted menu count, bad prompt sync, or remote libc mismatch.
5. Patch only the specific false assumption, using the observed memory state to choose the next payload or heap operation. Do not patch target memory with `/proc/<pid>/mem` or debugger writes to make the exploit pass.

Do not replace a failing route with a new route until you can state why the current route is blocked by protections or challenge limits.

## Common Pitfalls

- Do not set `LD_LIBRARY_PATH=.` globally when an old libc is present; it can break shell, GDB, and helper tools.
- Do not assume IDA stack offsets are exact. Measure saved RIP/canary/buffer distances in GDB.
- Do not assume hook targets exist on glibc 2.34+ (`__free_hook`/`__malloc_hook` are gone). Check symbols and version, then use FSOP/exit/rtld/setcontext targets.
- Do not poison a tcache/fastbin fd on glibc 2.32+ without a heap leak and 16-byte alignment: fd is `(chunk_addr>>12) ^ target` (Safe-Linking) and a misaligned target aborts.
- Do not attribute the tcache double-free key to 2.32 (it is 2.29) or claim fastbins are removed in 2.41 (they are not; removal is only a proposed future patch). Confirm version-specific behavior in GDB.
- Do not assume a 0x420+ free reaches the unsorted bin on glibc 2.42+ if `glibc.malloc.tcache_max` was raised; verify the chunk's destination bin in GDB.
- Do not ignore allocation limits, edit limits, free limits, size filters, or one-shot vulnerabilities. They often decide the viable technique.
- Do not type binary payloads with NUL bytes into tmux panes. Use pwntools or files. Do not use `/proc/<pid>/mem`, GDB `set`, or debugger memory writes to change target memory as part of the exploit; use the normal vulnerable input/menu/protocol path.
- Do not keep sending shell commands to a pane that is at `pwndbg>`.
