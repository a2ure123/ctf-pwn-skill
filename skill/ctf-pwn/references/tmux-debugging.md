# tmux-mcp First Debugging

Use this file whenever the task requires live debugging, exploit crash analysis, heap/stack inspection, or validating a primitive. The model must operate tmux-mcp tools directly instead of only suggesting commands.

## Priority Rule

For pwn debugging, the default path is:

1. create or reuse a tmux session,
2. use separate panes/windows for `work`, `gdb`, and `inferior-tty`,
3. run the target under GDB with `set inferior-tty /dev/pts/N`,
4. feed the program through the inferior pane,
5. step and inspect with pwndbg in the GDB pane,
6. only then update `exp.py`.

Do not use a single heredoc-driven GDB session for interactive programs. Do not let GDB commands and inferior input share stdin. Do not make exploit changes after a crash until the crash site has been inspected in GDB.

## Tool Use Pattern

Use tmux-mcp in this order:

```text
find_session(name="pwn") or create_session(name="pwn")
create_window(name="work")
create_window(name="inferior-tty")
create_window(name="gdb")
execute_command(paneId=..., command="cd /path/to/challenge-dir && tty")
capture_pane(paneId=...)
execute_command(paneId=..., command="cd /path/to/challenge-dir && gdb -q ./<target-elf>", rawMode=true)
execute_command(paneId=..., command="set pagination off", rawMode=true)
execute_command(paneId=..., command="set confirm off", rawMode=true)
execute_command(paneId=..., command="set disassemble-next-line on", rawMode=true)
execute_command(paneId=..., command="set disable-randomization on", rawMode=true)
execute_command(paneId=..., command="set inferior-tty /dev/pts/N", rawMode=true)
```

Use `capture_pane` frequently: after startup, after each breakpoint hit, after input, after `heap/bins/context`, and after crashes.

## Inferior TTY Workflow

In the inferior pane:

```bash
cd /path/to/challenge-dir
tty
```

Use the printed `/dev/pts/N` in GDB:

```gdb
set inferior-tty /dev/pts/N
run
```

After `run`, the binary's prompts appear in `inferior-tty`. Send menu choices, format strings, cyclic patterns, and simple text payloads to the inferior pane. Send GDB commands only to the GDB pane.

For binary payloads containing NUL bytes, use pwntools or a file. Do not type raw binary into a tmux pane.

## Step Debugging Loop

Use this loop for each hypothesis:

1. Set one or more high-signal breakpoints.
2. Run or continue until the breakpoint.
3. Feed exactly the input needed for this step through the inferior pane or a small wrapper script.
4. Inspect the live state.
5. Record the observed offset, address, bin state, or register condition.
6. Continue or step the dangerous operation.
7. Update the exploit only after the observation explains the next edit.

High-signal breakpoints:

```gdb
b *main
b *vuln+OFFSET_AFTER_READ
b *vuln+OFFSET_RET
b malloc
b free
b calloc
b realloc
b malloc_printerr
b __libc_message
b *edit_func+OFFSET_AFTER_READ
b *show_func+OFFSET_BEFORE_WRITE
b *CALL_OR_JMP_REG_ADDR
catch syscall open
catch syscall openat
catch syscall read
catch syscall write
```

## Heap Observation Points

After every relevant allocation/free/edit/show, inspect:

```gdb
context
heap
vis_heap_chunks
bins
arena
chunk PTR
x/32gx PTR-0x10
x/32gx POINTER_ARRAY
x/32gx TARGET_ADDRESS
heap_config
vmmap
```

If `exp.py` fails or the next heap step depends on layout, attach or break at the state-changing call and inspect memory directly before editing. Derive the next allocation size, tcache/bin poison value, overlap target, fake chunk, or arbitrary write from the current heap state, not from an assumed layout. Do not use `/proc/<pid>/mem`, GDB `set`, or debugger writes to mutate target memory as a substitute for the exploit primitive.

For glibc 2.32+ safe-linking, verify encoded fd values from live chunk addresses:

```text
encoded_fd = target ^ (chunk_addr >> 12)
```

## Stack Observation Points

For stack bugs, inspect before and after input, then before return:

```gdb
context
canary
tele $rsp 40
tele $rbp-0x100 80
x/gx $rbp+8
p/x $rbp
p/x $rsp
p/d ($rbp+8)-BUFFER_ADDRESS
```

Use cyclic patterns only to measure; confirm the final offset in GDB.

## Exploit Script Interaction

`exp.py` is for reproducibility, not for hiding the state. A good pattern is:

1. use tmux/GDB manually to understand the first bug,
2. write wrappers and a function to reproduce the state,
3. run `python3 exp.py GDB` or attach GDB,
4. break at the next dangerous operation,
5. inspect state again.

If `sendafter()` gets EOF or hangs, capture the inferior and GDB panes. Check prompt sync before changing exploitation logic.

## When gdb.attach Is Acceptable

Use `gdb.attach` after the tmux/inferior-tty workflow has already established:

- the vulnerability site,
- the needed breakpoints,
- the interaction wrappers,
- at least one observed memory/register state.

For first-pass analysis and confusing crashes, return to tmux-mcp with explicit `set inferior-tty`.
