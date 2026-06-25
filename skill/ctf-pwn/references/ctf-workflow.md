# CTF Pwn Workflow

Follow this order unless the user asks for a narrow debugging task.

## 1. File and Runtime Inventory

Identify every supplied file:

- challenge binary
- libc
- loader
- Dockerfile or run script
- remote host/port
- flag path hints
- source or headers

Record protections and ABI:

```bash
BIN=./<target-elf>
file "$BIN"
checksec --file="$BIN"
strings -a ./libc.so.6 2>/dev/null | grep -E 'GNU C Library|GLIBC'
readelf -hW "$BIN"
readelf -lW "$BIN"
readelf -rW "$BIN"
```

Set `BIN` to the actual ELF for this task. Do not assume a default name such as `chal`.

Runtime rule:

- If libc and loader are supplied, run with `./ld-linux-x86-64.so.2 --library-path . "$BIN"`.
- If only libc is supplied, identify the matching loader or use a tool such as glibc-all-in-one.
- If no libc is supplied, first solve with system libc but treat offsets as non-final for remote.
- Keep an original copy if using `patchelf`.

## 2. Reverse Engineering

Use IDA/idat/idalib when available. If the user provides an IDA path, IDB path, or IDA MCP connection, use IDA for first-pass reverse engineering; do not substitute objdump as the main analysis path. The goal is not perfect decompilation; the goal is an exploitable model.

Record:

- input functions and max lengths
- menu choices and prompts
- pointer arrays, counters, index checks, and size checks
- allocation and free lifecycle
- output/leak paths
- return paths and indirect calls
- seccomp, sandbox, chroot, close(0/1/2), alarm, fork, ptrace
- one-shot restrictions: only one edit, limited add/delete/show, max size, forbidden bytes

Name functions and data as soon as they are understood. For structures, infer fields from access patterns and verify in GDB.

## 3. Interaction Wrapper First

Before exploitation, write stable helpers in `exp.py`:

- `start()`
- `choice()`
- protocol encoders/decoders
- menu operations such as `add`, `edit`, `show`, `delete`
- `leak()` helpers only after the leak is proven

This lets GDB reproduce a state exactly instead of manually retyping a long sequence.

## 4. Dynamic Proof

Use tmux-mcp/GDB as the first-choice proof path. Create or reuse separate `work`, `gdb`, and `inferior-tty` panes, set `inferior-tty` inside GDB, and feed the program through the inferior pane. This is mandatory for first-pass live debugging unless tmux-mcp is unavailable.

Use tmux/GDB to prove the bug:

- stack overflow: stop after the input and before return; measure buffer to saved RIP/canary.
- format string: find argument offset and prove one read/write target.
- heap: stop after each malloc/free/edit/show; inspect chunks, bins, and pointer array.
- shellcode: inspect mapped permissions and register state before jumping.
- seccomp: dump rules and prove which syscalls are allowed.

Never treat a primitive as real until the GDB state shows it. Do not use a one-shot exploit script as a substitute for this proof; scripts should reproduce states that tmux/GDB can inspect.

## 5. State Notes

Maintain notes in the challenge directory when the solve is non-trivial:

```text
binary:
  arch:
  pie:
  canary:
  nx:
  relro:
  libc:
  loader:
  seccomp:

interface:
  prompts:
  operations:
  limits:

bug:
  location:
  primitive:
  trigger:
  constraints:

known:
  pie_base:
  libc_base:
  heap_base:
  stack_leak:
  canary:
  saved_rip_offset:
  chunk_layout:

plan:
  leak:
  write:
  hijack:
  final:

failed:
  - route:
    reason:
```

## 6. Route Selection

Select exploitation by constraints:

- No leak: prefer fixed binary addresses if PIE off, format-string leak, stdout leak, unsorted leak, stack leak, BROP, or partial overwrite.
- Canary: leak it, overwrite TLS `stack_guard` only when the primitive permits, or avoid returning.
- NX off or executable mmap: shellcode may be simplest.
- Seccomp blocks execve: use ORW, sendfile, openat/openat2, mmap/read/write, or socket exfiltration if stdio is closed.
- Full RELRO: GOT overwrite is not viable; use stack/heap control, hooks if present, IO_FILE, exit handlers, rtld targets, or return address.
- glibc 2.34+: malloc/free hooks are removed; prefer IO/FSOP, tcache struct, exit/rtld, setcontext/ORW, stack return, or FILE-based paths.

## 7. Iteration Rule

Implement one step at a time:

1. reach vulnerable state
2. leak one base
3. prove base calculation
4. build stronger primitive
5. hijack control
6. execute shell or ORW

After each step, verify with local output or GDB state. If an `exp.py` stage fails, attach GDB or break in tmux/GDB and inspect current memory; heap stages must be adjusted from the observed chunks, bins, pointer arrays, and target addresses. Do not use `/proc/<pid>/mem` or debugger memory writes as exploit steps.
