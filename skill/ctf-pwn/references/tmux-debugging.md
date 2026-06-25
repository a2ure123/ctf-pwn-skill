# Live GDB Debugging (tmux CLI first, batch for verification)

Use this file whenever the task requires live debugging, exploit crash analysis, heap/stack inspection, or validating a primitive. The model must drive a real, persistent GDB session — not just suggest commands — by default through plain `tmux` CLI from Bash (`tmux send-keys` to issue commands, `tmux capture-pane -p -S -` to read output).

## Priority Rule

For pwn debugging, the default path is:

1. create or reuse a tmux session,
2. use separate panes/windows for `work`, `gdb`, and `inferior-tty`,
3. run the target under GDB with `set inferior-tty /dev/pts/N`,
4. feed the program through the inferior pane,
5. step and inspect with pwndbg in the GDB pane,
6. only then update `exp.py`.

Do not use a single heredoc-driven GDB session for interactive programs. Do not let GDB commands and inferior input share stdin. Do not make exploit changes after a crash until the crash site has been inspected in GDB.

## Transport: a persistent tmux-CLI GDB session first, batch only for verification

The valuable thing is a **persistent, adaptive GDB session** — set a breakpoint, look, decide
the next command from what you just saw, step again. That's how you understand an unknown
crash or watch the heap evolve. A one-shot script cannot do this; it can only confirm a
hypothesis you already have.

1. **Persistent GDB via direct `tmux` CLI from Bash** — the default. No MCP server, no extra
   dependency; the session stays alive across the whole solve and each step is one Bash call.
   ```bash
   tmux new-session -d -s dbg -x 200 -y 50
   tmux set-option -t dbg history-limit 100000              # keep full scrollback
   tmux send-keys -t dbg 'gdb -q -p PID' Enter ; sleep 1.2  # WAIT for the prompt first
   # each step = one Bash call: send, settle, read
   tmux send-keys -t dbg 'b *0xADDR' Enter; tmux send-keys -t dbg 'c' Enter; sleep .3
   tmux capture-pane -p -t dbg -S -          # -S - = the ENTIRE history, not just the screen
   tmux send-keys -t dbg 'ni' Enter; sleep .2; tmux capture-pane -p -t dbg -S -200
   ```
   - `capture-pane -p -S -` returns the **whole scrollback** (verified: 500/500 lines, vs ~55
     for the default visible-screen capture). Use `-S -N` to bound to the last N lines. Always
     use `-S` for long `bins` / `vis_heap_chunks` / backtrace output — the default truncates.
   - **Always wait for the prompt before `send-keys`** (a fresh shell/gdb needs ~1s to init);
     otherwise keys are typed before the target is ready and the step silently does nothing.
     Prefer polling the pane over a fixed `sleep` — it is faster and never races:
     ```bash
     until tmux capture-pane -p -t dbg | grep -q 'pwndbg>'; do sleep .1; done   # wait for prompt
     tmux send-keys -t dbg 'x/8gx $rsp' Enter
     until tmux capture-pane -p -t dbg | tail -1 | grep -q 'pwndbg>'; do sleep .1; done  # cmd done
     tmux capture-pane -p -t dbg -S -
     ```
   - Never type NUL-containing binary into a pane; feed the inferior via pwntools or a file.
2. **batch GDB — verification only, never exploration.** When you already know which addresses
   to dump, or you're regression-checking a known state, one shot is fastest and survives any
   MCP/tmux issue:
   ```bash
   # gate: the exploit pauses, writes its pid, spins on a file
   #   open('pid','w').write(str(io.pid)); open('gate','w').close()
   #   while os.path.exists('gate'): time.sleep(0.3)
   gdb -q -batch -p $(cat pid) -ex 'x/4gx <unsorted>' -ex 'x/8gx <chunk>' -ex 'vmmap libc'; rm gate
   # fully non-interactive when input is deterministic:
   gdb -q -batch -ex 'b *0xADDR' -ex 'run < in' -ex 'bins' -ex 'x/16gx $rsp' ./BIN
   # whole trace in one run via auto-dumping breakpoints:
   #   b *0xADDR \ commands \ silent \ bins \ x/8gx PTR \ continue \ end
   ```
   Batch cannot adapt mid-run or single-step — use it to confirm a hypothesis, not to form one.

**Rule of thumb:** confused / forming a hypothesis / watching heap evolve → the persistent
tmux-CLI session. Verifying a known target / regression → batch. Do not fall back to one-shot
scripts for exploration — they throw away the ability to step.

> An MCP-based tmux driver exists but is intentionally not used here — it dropped mid-session in
> real solves. The direct `tmux` CLI above does the same job with no MCP server, and is the
> default. (A reliable tmux MCP, if you have one, can drive the same panes, but it is never required.)

**Stripped libc:** pwndbg `heap`/`bins` need `main_arena`; if it can't auto-locate it, set it
yourself (`set $ma = <libc_base>+0x3ebc40` for 2.27) or read bins with raw
`x/20gx <libc_base>+0x3ebc40` instead of waiting on auto-detection.

## GDB session config

Three panes: `work` (shell), `gdb`, `inferior-tty`. In the inferior pane run `tty` and note the
`/dev/pts/N`. In the gdb pane start `gdb -q "$BIN"` and configure once:

```gdb
set pagination off
set confirm off
set disassemble-next-line on
set disable-randomization on
set inferior-tty /dev/pts/N      # so program I/O and GDB input never share stdin
```

Re-read the gdb pane with `tmux capture-pane -p -S -` after startup, after each breakpoint hit,
after input, after `heap/bins/context`, and after every crash.

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

For first-pass analysis and confusing crashes, return to the persistent tmux-CLI GDB session with explicit `set inferior-tty`.
