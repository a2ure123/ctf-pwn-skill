# House of … Techniques Catalog

The "House of" family is the core of glibc heap exploitation. This file gives a clear,
version-gated picture: which house applies to which glibc, what it needs, the core idea,
the target it hits, and how to drive it. **Pick a house only after fingerprinting the
version** (see `glibc-heap-version-map.md`) and confirm every check in GDB — offsets and
mitigations move between builds.

How to read each entry: **Versions** = where it works · **Needs** = preconditions ·
**Idea** = the mechanism abused · **Target/Result** = what you get · **Steps/Notes** =
how to drive it and current caveats.

---

## Choosing a House (quick decision)

- Need to **allocate at an arbitrary address** (then write):
  - leaked heap + UAF/edit: tcache poisoning (not a "house", but first choice 2.26+).
  - leakless / partial overwrite: House of Roman, House of Rust, **House of Water**.
  - via fastbin->tcache stash: fastbin-reverse-into-tcache (needs fastbins to exist).
- Need to **write a heap/libc pointer to a chosen address**: **largebin attack** (2.30+
  ordering-safe single write) -> then House of Banana / FSOP / `mp_.tcache_bins`.
- Need **code execution on 2.34+ (hooks gone)**: FSOP — **House of Apple 2** (default),
  **House of Cat** (clean RDX for setcontext/ORW), House of Emma, House of Obstack,
  House of Pig; or **House of Banana** (hijack `_rtld_global` at exit); or House of Kiwi
  (assert path).
- **No free / control top chunk**: House of Orange (<=2.26 FSOP) / **House of Tangerine**
  (modern top-chunk-to-unsorted).
- **Off-by-null / one-byte overflow**: House of Einherjar (<=2.28) or modern unsorted-bin
  assisted overlap (2.29+).
- **Old glibc with hooks (<=2.31)**: fastbin attack / unsorted bin attack / House of
  Force(<=2.28) / House of Spirit / House of Lore -> `__malloc_hook`/`__free_hook`.

---

## Modern FSOP Foundation (read before Apple / Cat / Obstack)

Since 2.34 removed the malloc/free hooks, most code-exec routes go through a corrupted
`FILE` (`_IO_FILE_plus`) processed by `exit`/`fflush`/`puts`/`printf` or by
`_IO_flush_all_lockp` at program end.

Key facts:

- **vtable check (`_IO_vtable_check`, since 2.24)**: the `vtable` pointer must lie inside
  the read-only `__libc_IO_vtables` section, else abort. You cannot point `vtable` at the heap.
- **The wide-char bypass (the heart of House of Apple 2 / Cat)**: the *wide* vtable
  `_IO_wide_data->_wide_vtable` is **NOT** validated by `_IO_validate_vtable`. So you set
  the FILE's real `vtable` to a legitimate in-range table (`_IO_wfile_jumps`), let it call
  a `_IO_wfile_*` function, and that function dereferences `_wide_vtable->__doallocate`
  (or `overflow`) — a pointer you fully control on the heap. That is how you hijack RIP on
  the latest libc without defeating the vtable check.
- Common driver: corrupt `_IO_2_1_stdout_` / `_IO_2_1_stderr_`, or chain a fake FILE via
  the `_chain` field of an existing one, or via `_IO_list_all` (largebin/unsorted attack).

Inspect:

```gdb
p &_IO_2_1_stdout_
p &_IO_wfile_jumps
p &_IO_file_jumps
x/40gx &_IO_2_1_stdout_
```

---

## Era 1 — Classic / pre-tcache (glibc <= 2.23, some live forever)

### House of Spirit
- **Versions**: 2.23 — present (size checks tightened over time).
- **Needs**: control a fake chunk's `size` and the ability to `free` that pointer.
- **Idea**: forge a fastbin/tcache-sized chunk at a target (stack/bss/heap) and free it so
  the next malloc of that size returns your target.
- **Notes**: fake `size` must match the bin and be aligned; `next` chunk size must be in
  `[2*SIZE_SZ, av->system_mem]`; ISMMAP bit clear; not already the bin head. In the tcache
  era ("tcache House of Spirit") there is almost no size check, so it is trivial.

### House of Force
- **Versions**: 2.23 — **2.28 (dead at 2.29)**.
- **Needs**: overflow the **top chunk size**, free control of malloc size, unlimited allocs.
- **Idea**: set top size to `0xffffffffffffffff`, malloc the (target - top - 0x20) distance
  so top "moves" to your target, then malloc to land there.
- **Dead at 2.29**: sysmalloc added a top-chunk size sanity check. Use House of Orange/
  Tangerine instead.

### House of Einherjar
- **Versions**: 2.23 — **~2.28 easy; 2.29+ hard** (strict `prev_size`).
- **Needs**: off-by-null (clear `PREV_INUSE`) on a chunk, plus a forged `prev_size`.
- **Idea**: backward consolidation — free a chunk whose `prev_inuse=0` and `prev_size`
  points far back, merging into a fake chunk and producing a near-arbitrary `malloc`/overlap.
- **2.29+**: `prev_size == size` consistency is checked; build the layout with an
  unsorted-bin assisted overlap and an exactly correct fake `prev_size`.

### House of Lore
- **Versions**: 2.23 — present (smallbin integrity must be satisfied).
- **Needs**: control a smallbin chunk's `bk`, satisfy `bck->fd == victim`.
- **Idea**: redirect the smallbin `bk` to a fake chunk so the next smallbin malloc returns
  your target.

### House of Orange
- **Versions**: 2.23 — **~2.26** (FSOP form; vtable check at 2.24 limits the fake vtable).
- **Needs**: no `free` available; ability to overwrite top size; later a libc leak.
- **Idea**: shrink/forge top size so a larger malloc forces `sysmalloc` to retire the old
  top into the **unsorted bin** (free without `free`). Then unsorted-bin attack
  `_IO_list_all` and FSOP. Modern successor: **House of Tangerine**.

### House of Storm
- **Versions**: 2.23 — **2.29 (dead at 2.30)**.
- **Needs**: an unsorted chunk and a largebin chunk colliding in one largebin index,
  controllable `bk` (unsorted) and `bk`/`bk_nextsize` (largebin). This maps *exactly* onto a
  write that reaches only `user+8..+0x20` (`bk|fd_nextsize|bk_nextsize`) — see the heap
  edit-primitive routing in `technique-index.md`.
- **Idea**: combine unsorted-bin attack + largebin attack to allocate a chunk at `target`.
- **Trigger**: call **`calloc`** (not `malloc`) for the placement — `calloc` skips tcache so
  the allocator is forced to scan the unsorted bin and run the malicious insert/return.
- **Fake size**: the vended chunk's size field overlaps a written pointer's bytes (the
  classic `bk_nextsize = fake - 0x18 - 5` trick makes the size = the heap **high byte**). You
  usually cannot leak that byte, so the placement is **probabilistic** (size must fall in the
  requested bin, e.g. high byte `0x50..0x57` for a 0x50 request) — **wrap the solve in a
  silent retry loop**.
- **Endgame (≤2.33)**: vend the chunk so its `user+8` lands on `__free_hook`
  (`fake = __free_hook - 0x18` → user = `__free_hook - 8`), engrave `one_gadget` into
  `__free_hook`, then any `free()` → shell. Leak (one-time `%s`) is only the libc source;
  the trigger is `free()`, so there is no leak/trigger conflict.
- **Dead at 2.30**: largebin insertion ordering checks. Use a plain largebin attack instead.

### House of Rabbit
- **Versions**: 2.23 — **~2.28**.
- **Needs**: edit a fastbin chunk's `fd`/`size`; trigger `malloc_consolidate`.
- **Idea**: `malloc_consolidate` merges fastbin chunks without a size check, so a forged
  huge fastbin chunk becomes an overlapping unsorted chunk — overlap without a leak.
- **Caveat**: dies whenever fastbins / `malloc_consolidate` are removed (proposed post-2.43).

---

## Era 2 — Tcache transition (glibc 2.26 – 2.31)

### House of Botcake
- **Versions**: 2.26 — present (the standard way past the **2.29 tcache double-free key**).
- **Needs**: fill 7 tcache of a size, plus a victim and a neighbor you can free twice;
  ability to merge two physically adjacent chunks into the unsorted bin.
- **Idea**: free 7 to fill tcache; free `victim` (goes to unsorted, key dropped); free
  neighbor `prev` to consolidate; malloc one back from tcache to make room; re-free
  `victim` -> now it is BOTH in unsorted and tcache = overlap + tcache poisoning vector.
- **Result**: overlap a big unsorted chunk over a tcache chunk, edit its `next`, poison.

### House of Atum / Kauri
- **Versions**: 2.26 — ~2.30/2.32.
- **Idea**: free a chunk through both fastbin and tcache (Atum), or change a tcache chunk's
  `size` so it appears in two different tcache bins (Kauri) — both yield overlap / metadata
  corruption on the transition-era allocators.

### fastbin-reverse-into-tcache
- **Versions**: 2.26 — present (while fastbins exist).
- **Needs**: fill tcache, push extra frees into fastbin, edit a fastbin `fd`.
- **Idea**: empty tcache; next malloc pulls from fastbin and **stashes** the rest into
  tcache, so a forged fastbin `fd` becomes a tcache entry -> arbitrary alloc. On 2.32+ the
  `fd` is safe-linked; supply the encoded value.

### House of Roman / House of Rust
- **Versions**: ~2.23 — ~2.29 (Roman); Rust extends the leakless idea.
- **Needs**: a partial-overwrite primitive; no leak.
- **Idea**: leakless — partially overwrite a single fd byte (12-bit brute) to aim a
  fastbin/tcache chunk at `__malloc_hook`, then partial-overwrite again to a one_gadget.
- **Caveat**: hook-based, so <= 2.33; Rust-style leakless ideas live on inside House of Water.

---

## Era 3 — Modern, post-hook FSOP (glibc 2.34+)

These are the workhorses on 2.35/2.39/2.41-class targets. All assume a libc leak and an
arbitrary write (or a largebin/unsorted write into a FILE).

### House of Kiwi
- **Versions**: ~2.29 — ~2.36 (assert path); changes at 2.37 (`__malloc_assert` dropped).
- **Needs**: trigger `__malloc_assert` / an allocator abort that calls `fflush(stderr)`;
  control over `stderr` FILE (or the `_IO_file_jumps` it reaches).
- **Idea**: an allocator assertion calls `__fxprintf(NULL, …)` then `fflush(stderr)`; by
  forging `stderr` (or its vtable target) you redirect that flush into your chain.
- **Notes**: forge so `flags & 0x8000` (skip `_lock`), `flags & ~(0x2|0x8)`, `mode=0`,
  vtable = `_IO_xxx_jumps - 0x20` to land on `_IO_xxx_overflow`. On 2.37+ adapt to the
  `__libc_message` form. Often used to convert "program never calls exit/printf" into a
  controllable IO call.

### House of Apple 1
- **Versions**: 2.23 — present.
- **Needs**: one largebin/IO write; trigger a wide-string IO path.
- **Idea**: abuse `_IO_wstrn_jumps` / `_IO_wstr_overflow` to write a known heap pointer to
  a chosen address (e.g. a tcache var or the `pointer_guard`). A primitive, not direct RIP.
- **Setup (from field notes)**: `_flags2 = 8`, `_lock` writable, `_mode = 0`, `_wide_data`
  -> address to write, `vtable = _IO_wstrn_jumps`.

### House of Apple 2  (the default modern FSOP)
- **Versions**: 2.23 — present (tested working through the latest libc; the wide-vtable
  is never validated). Primary route on **2.35+**.
- **Needs**: libc leak; a controllable FILE that gets `_IO_OVERFLOW`'d (corrupt
  `_IO_2_1_stdout_`, chain a fake FILE, or via `_IO_list_all`); ability to set its fields.
- **Idea**: set the FILE's real `vtable = _IO_wfile_jumps (+/- offset)` so an overflow goes
  to `_IO_wfile_overflow`, which calls `_IO_wdoallocbuf -> _wide_vtable->__doallocate` —
  an unchecked heap pointer = RIP.
- **Field-tested fp setup** (offsets are from the FILE base `fp`):

  ```
  _flags   = 0          (or "  sh;" with two leading spaces if you want rdi=&flags for system)
  vtable   = _IO_wfile_jumps           # so _IO_OVERFLOW -> _IO_wfile_overflow
  _wide_data (fp+0xa0) = A             # controllable heap addr
  A->_IO_write_base (A+0x18) = 0
  A->_IO_buf_base   (A+0x30) = 0
  A->_wide_vtable   (A+0xe0) = B       # controllable heap addr
  B->__doallocate   (B+0x68) = C       # C hijacks RIP (e.g. setcontext+61 / a gadget)
  ```
  Keep `_IO_write_ptr` non-zero so the path is taken. On older 2.27 it also works but
  needs `*(fp+0x130)=B`.
- **Stack pivot variant** (call ORW instead of a single gadget): pwntools'
  `IO_FILE_plus_struct().house_of_apple2_stack_pivoting_when_exit` template, or set
  `vtable=_IO_wfile_jumps-0x20`, `_IO_read_ptr=pop_rbp`, `chain=leave_ret`,
  `_wide_data=stdout-0x48`, etc. Field note: 2.35 can stack-pivot via this chain; **2.38
  may not pivot** (RIP hijack still works) — verify per build.
- **Variants by trigger function**: `_IO_wfile_underflow_mmap` (set `vtable=_IO_wfile_jumps_mmap`,
  `_flags=~4`, `_IO_read_ptr<_IO_read_end`, `A->_IO_save_base=0`); `_IO_wdefault_xsgetn`
  (needs rdx!=0 at call, `_flags=0x800`, `vtable=_IO_wstrn/wmem/wstr_jumps`,
  `_mode>0`, `B->overflow (B+0x18) = C`). Pick the one whose call site the program reaches.

### House of Cat
- **Versions**: 2.35+ (also reported on 2.32).
- **Needs**: two largebin attacks (one on `stderr`/the FILE, one to forge top size), libc+heap
  leak, and an `__malloc_assert`/IO trigger.
- **Idea**: an Apple-2 cousin that routes through `_IO_wfile_seekoff` ->
  `_IO_switch_to_wget_mode`, which leaves **RDX pointing at your controlled FILE** — perfect
  for `setcontext` (2.29+ reads the ucontext from RDX) -> one clean ORW frame. This is why
  Cat is favored for seccomp/ORW on modern libc.
- **Steps**: leak libc+heap; largebin-attack `stderr`; largebin-attack the top size; forge
  the fake `_IO_FILE`; trigger `__malloc_assert` -> `_IO_wfile_seekoff` -> setcontext -> ORW.

### House of Emma
- **Versions**: 2.35+.
- **Needs**: arbitrary write AND the TLS `pointer_guard` (leak it or overwrite it).
- **Idea**: hijack `_IO_cookie_jumps`; its function pointers are PTR_MANGLE'd
  (`rol`+xor with `fs:[0x30]` guard), so you must first neutralize/leak the guard, then
  forge the cookie read/write function pointer.

### House of Obstack
- **Versions**: 2.23 — present (chain shifts at 2.37+).
- **Needs**: one largebin attack; an IO flush that reaches the obstack path.
- **Idea**: vtable = `_IO_obstack_jumps` -> `_IO_obstack_xsputn` -> `obstack_grow` ->
  `_obstack_newchunk` -> `CALL_CHUNKFUN` calls `chunkfun(extra_arg, size)` — a controlled
  function pointer with controlled rdi.
- **fp/obstack layout (field notes)**: at the fake FILE `A`: `A+0xd8 = _IO_obstack_jumps+0x20`;
  `A+0xe0 = A` (obstack struct = self); `A+0x18 = 1` (next_free); `A+0x20 = 0` (chunk_limit);
  `A+0x48 = &/bin/sh`; `A+0x38 = system`; `A+0x28 = 1`; `A+0x30 = 0`; `A+0x50 = 1` (use_extra_arg).
  On 2.37+: `__printf_buffer_as_file_overflow -> __printf_buffer_flush -> __printf_buffer_flush_obstack -> __obstack_newchunk`.

### House of Pig
- **Versions**: 2.23 — present.
- **Idea**: abuse `_IO_str_overflow`'s internal `malloc`+`memcpy`+`free` combined with a
  largebin attack to overwrite a hook/GOT/FILE — an IO-driven write+exec primitive.

### House of Husk
- **Versions**: ~2.27 — present (table offsets move at 2.37 printf refactor).
- **Needs**: arbitrary write; the program calls a `printf`-family function with a custom
  format specifier (`%` + registered conversion).
- **Idea**: overwrite `__printf_function_table` and `__printf_arginfo_table` so a custom
  `%` specifier calls your function pointer during `printf`.

### House of Banana
- **Versions**: ~2.31 — ~2.38 (the post-hook `exit`/`_dl_fini` route); idea generalizes
  2.23+ wherever `_rtld_global` is reachable.
- **Needs**: one largebin attack (write a known heap addr to a target), libc + ld.so leaks,
  and the program returns from `main` / calls `exit()` (triggers `_dl_fini`).
- **Idea**: at exit, `ld.so` walks `_rtld_global._dl_ns[0]._ns_loaded` (a `link_map`)
  and runs each library's `.fini_array`. Largebin-attack `_ns_loaded` to point at a fake
  `link_map` on the heap whose `DT_FINI_ARRAY` runs your `setcontext`+ORW chain.
- **Critical gotcha**: largebin attack writes the **chunk header** address (incl. prev_size/
  size), not the user `mem` address — compute every `link_map` offset from that header.
- **fake link_map essentials** (64-bit; verify per version): `l_addr(0x00)=0`,
  `l_next(0x18)=0` (stop the walk), `l_real(0x28)=target` (self), `l_info[DT_FINI_ARRAY]`
  at `0x110 = 0x40 + 26*8` -> a fake `Elf64_Dyn{d_tag=26, d_ptr=&fini_ptr}`; `fini_ptr`
  = `setcontext+61`; place the SROP/ucontext frame right after. The libc<->ld offset for
  `_rtld_global` can shift in the 2nd address byte between local and remote — brute 256 if needed.

### House of Mind / Muney / Gods (niche)
- **Mind** (2.23—present): forge `heap_info`/`malloc_state` to hijack a non-main-arena free.
- **Muney** (2.23—present): abuse an mmap'd chunk adjacent to `libc.so`; resize+free to
  reclaim/realloc sensitive libc regions (symbol tables, GOT-like data).
- **Gods** (2.23—~2.27): hijack `main_arena.next` to forge a fake arena via `arena_get_retry`.

---

## Leakless / no-ASLR-leak houses

### House of Corrosion
- **Versions**: 2.23 — present.
- **Idea**: overwrite `global_max_fast` so almost any size is treated as a fastbin, turning
  ordinary frees into fastbin writes for arbitrary read/write — works without a libc leak by
  writing into known-offset libc data (`stdout`, `tls`, etc.).

### House of Water
- **Versions**: modern (2.34+ post-hook), demonstrated 2023/2024 (team Blue Water).
- **Needs**: UAF and the ability to allocate fairly large chunks. **No leak, no overflow.**
- **Idea**: forge a fake unsorted chunk of size `0x10001` on top of the
  `tcache_perthread_struct`, drive it through unsorted->largebin sorting so the allocator
  writes **libc pointers** into tcache metadata, then largebin/tcache-attack to allocate
  on libc — a leakless path to arbitrary libc allocation on hookless glibc.
- **Skeleton** (verify live): alloc+free 0x3e0 and 0x3f0 chunks so their freed fd/bk
  (0x10001) seed the fake size; stage 0x90 chunks into tcache; place `unsorted_start/middle/
  end` and forge 0x20/0x30 fake chunks above them, free them to leave fd/bk pointers into
  the fake unsorted chunk; forge the `0x10001` size + a 0x20 next size over the
  `tcache_perthread_struct`; free the three unsorted chunks, fix `unsorted_start->fd` and
  `unsorted_end->bk` to the fake chunk; alloc `<0x10000` to trigger the unsorted walk so the
  fake chunk lands in largebin with libc fd/bk filled in. **Requires a 4-bit brute (1/16)**
  when fixing the start/end pointers (randomized low address bits).

### House of Blindness
- **Versions**: ~2.35 — 2.38, very effective.
- **Needs**: a largebin attack; program exits via `_dl_fini`. **No address leak at all.**
- **Idea**: with no leak, largebin-attack offsets inside `ld.so`'s `link_map` so `_dl_fini`
  jumps to a chosen address — a fully blind exit-time hijack.

### House of Minho
- **Versions**: 2.35+.
- **Needs**: severe size restriction (only tiny allocs); a `scanf("%d"/"%u"/"%lx")` that
  takes attacker input; UAF/overflow.
- **Idea**: `_IO_vfscanf` mallocs a temporary buffer when fed a very long numeric string
  (e.g. thousands of leading zeros), then frees it — "summon" a 0x420 unsorted chunk for a
  libc leak / heap-feng-shui even when the program only lets you allocate 0x20 blocks.
  Combine with smallbin stashing unlink + largebin attack -> arbitrary alloc -> House of Apple.

### House of Tangerine
- **Versions**: modern (2023), successor to House of Orange.
- **Needs**: control of the top chunk size; no `free` required.
- **Idea**: adapt House of Orange to new top-chunk checks — force the old top into the
  unsorted bin via `sysmalloc`, then tcache-poison from the resulting layout to take control
  on hookless glibc.

---

## Largebin / mp_ targets (where the houses point on 2.34+)

- **`mp_.tcache_bins`**: largebin-attack it to a huge value so large frees index far past
  `tcache_perthread_struct` into controllable heap data -> forge tcache entries ->
  unrestricted arbitrary allocation. (`mp_.tcache_bins` plays the role `global_max_fast`
  plays for fastbins.)
- **`global_max_fast`**: largebin/unsorted-attack it so big chunks act as fastbins (House of
  Corrosion).
- **`_IO_list_all` / `stderr` / `_IO_2_1_stdout_`**: largebin/unsorted attack to plant a
  fake FILE for an Apple-2/Cat chain.
- **`_rtld_global._dl_ns[0]._ns_loaded`**: House of Banana / Blindness at exit.

---

## setcontext + ORW (shared building block)

Most 2.34+ houses end by calling `setcontext` to load a full register frame and run an ORW
chain (open/read/write the flag) — essential under seccomp.

- **glibc <= 2.28**: `setcontext+53` reads the ucontext pointer from **rdi**; put the gadget
  in `__free_hook`/`__malloc_hook` and the freed/allocated chunk header becomes rdi.
- **glibc 2.29+**: `setcontext` reads the ucontext from **rdx**. You need a
  `mov rdx, [reg+..]; ... call/jmp` "magic gadget", or a chain (House of Cat) that already
  leaves rdx pointing at your frame. Common entry `setcontext+61`.
- Build the frame with pwntools `SigreturnFrame()` (set `rsp`, `rip`, and arg registers),
  then place your ORW ROP after it. Verify the exact `setcontext` offset for the target libc
  in GDB — it differs across versions.

---

## Compact lookup table

| Technique | Versions | One-line role |
|---|---|---|
| House of Spirit | 2.23+ | free a forged chunk -> alloc at target |
| House of Force | 2.23–2.28 | top size = -1 -> alloc anywhere (dead 2.29) |
| House of Einherjar | 2.23–2.28 (hard 2.29+) | off-by-null backward consolidate -> overlap |
| House of Lore | 2.23+ | smallbin bk -> alloc at target |
| House of Orange | 2.23–2.26 | no-free -> top into unsorted -> FSOP |
| House of Storm | 2.23–2.29 | unsorted+largebin -> alloc at target (dead 2.30) |
| House of Rabbit | 2.23–2.28 | consolidate forged fastbin -> overlap |
| House of Botcake | 2.26+ | bypass 2.29 tcache key -> overlap + poison |
| fastbin-reverse-into-tcache | 2.26+ | fastbin fd -> tcache entry -> arbitrary alloc |
| House of Roman/Rust | 2.23–2.29 | leakless partial-overwrite to hook |
| House of Corrosion | 2.23+ | global_max_fast -> fastbin everywhere (leakless) |
| House of Kiwi | 2.29–2.36 | assert -> fflush(stderr) -> IO hijack |
| House of Husk | 2.27+ | printf function/arginfo tables -> call |
| House of Apple 1 | 2.23+ | wide-string IO -> write known heap ptr |
| House of Apple 2 | 2.23+ (go-to 2.35+) | `_IO_wfile_jumps` wide-vtable -> RIP |
| House of Cat | 2.35+ (also 2.32) | wfile_seekoff -> clean RDX -> setcontext/ORW |
| House of Emma | 2.35+ | `_IO_cookie_jumps` (needs pointer_guard) |
| House of Obstack | 2.23+ | `_IO_obstack_jumps` -> CALL_CHUNKFUN |
| House of Pig | 2.23+ | `_IO_str_overflow` malloc/memcpy/free + largebin |
| House of Banana | 2.31–2.38 | largebin -> fake link_map -> `_dl_fini` |
| House of Blindness | 2.35–2.38 | leakless link_map hijack at exit |
| House of Minho | 2.35+ | scanf-spawned big chunk under tiny-size limits |
| House of Tangerine | modern | no-free top -> unsorted -> tcache poison |
| House of Water | 2.34+ | leakless tcache-struct -> libc ptrs -> arbitrary alloc |
| House of Mind/Muney/Gods | various | non-main arena / mmap-libc / fake arena |

Always validate the chosen house's preconditions and offsets in GDB before writing `exp.py`.
