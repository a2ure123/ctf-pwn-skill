# glibc Heap Version Map

Heap exploitation is version-gated. The same primitive (UAF, double free, overflow)
maps to completely different routes depending on the glibc version, because each
release adds allocator checks and removes targets. **For any heap challenge, resolve
the version FIRST, then map mechanisms, then pick a route.** Always confirm behavior
in GDB: distro patches, static builds, and challenge rebuilds can move offsets or
backport/disable checks.

## Heap Challenge Decision Procedure

1. **Fingerprint the libc version** (see below). Write it in the solve-state file.
2. **List the live mitigations for that version** from the timeline below: tcache key,
   safe-linking, alignment check, hook removal, vtable check, top/largebin checks.
3. **Classify the primitive and the I/O** (show? edit? free count? size class limits?).
4. **Map primitive -> route** using "Primitive to Route" while crossing off anything the
   version killed. For House-of / FSOP routes use `references/house-of-techniques.md`.
5. **Decide what you still need**: heap leak (mandatory for safe-linking forgery on
   2.32+), libc leak, and a control target that still exists in this version.
6. **Prove each step in GDB** before committing it to `exp.py`.

## Fingerprint the libc Version

```bash
strings -a ./libc.so.6 | grep -E 'GNU C Library|GLIBC_2\.' | head
./libc.so.6 2>/dev/null | head -1            # many libcs print their version banner
readelf -p .rodata ./libc.so.6 | grep -i 'release version'
```

In GDB on the running target:

```gdb
info sharedlibrary
p (char*)gnu_get_libc_version()
# presence of symbols tells you the era:
p &__free_hook          # exists <= 2.33, gone 2.34+
p &__malloc_hook        # exists <= 2.33, gone 2.34+
p &_IO_wfile_jumps      # wide vtable, needed for House of Apple 2 / Cat
p &__libc_csu_init      # gone 2.34+
```

If only the binary is given, the libc is the remote's; identify it (libc-database /
blukat / patchelf with glibc-all-in-one) before trusting any offset.

## Version Timeline (mechanisms, what dies, what to use)

Confirm every check in GDB; this is the routing prior, not ground truth for a given build.

### glibc <= 2.23

- No tcache. Allocator = fastbin / smallbin / unsorted / largebin only.
- `__malloc_hook`, `__free_hook`, `__realloc_hook` present and are the easiest targets.
- No safe-linking, no fd encryption, no tcache key.
- Live: unsafe unlink (fd/bk integrity check exists since 2.3.4, so fake `fd`=P-0x18,
  `bk`=P-0x10), fastbin attack to hook/stack, unsorted bin attack, House of
  Spirit/Force/Lore/Orange/Einherjar/Storm, classic FSOP via `_IO_list_all`.
- No `_IO_vtable_check` yet (added 2.24), so you can point a FILE vtable straight at the heap.

### glibc 2.24

- `_IO_vtable_check`: a FILE vtable must lie inside the `__libc_IO_vtables` section or
  the process aborts. Pointing a vtable at the heap dies here.
- Classic House of Orange FSOP must now reuse an in-range jumps table
  (`_IO_str_jumps`, later `_IO_wfile_jumps`) instead of a fully fake vtable.

### glibc 2.26 (Aug 2017) — tcache introduced

- tcache (per-thread, LIFO, 7 entries/bin, sizes 0x20..0x410 i.e. request <= 0x408).
- tcache poisoning: overwrite `next` (a.k.a. fd), no size check, malloc to anywhere.
- tcache dup: free the same chunk twice (NO key yet) -> duplicate, easiest UAF win.
- tcache has priority over fastbin on both alloc and free; a freed fastbin/smallbin
  chunk can be stashed into tcache, enabling fastbin-reverse-into-tcache.

### glibc 2.27 (Feb 2018) — the forgiving baseline

- Most common "easy heap" target. tcache present, **no key, no safe-linking, hooks present.**
- Canonical wins: tcache poison `__free_hook = system` (put `/bin/sh` in the freed chunk),
  or `__free_hook = setcontext+53` for ORW; tcache stashing unlink attack with calloc.
- Unsorted-bin libc leak via a 0x90..0x3f0 chunk freed into unsorted then shown.

### glibc 2.29 (Feb 2019) — tcache key + top/unsorted hardening

- **tcache double-free key**: `tcache_entry.key = tcache` on free; refree walks the bin
  and aborts ("free(): double free detected in tcache 2"). Simple tcache dup dies.
  Bypass: clear/overwrite the key via UAF, or use **House of Botcake** (free into
  unsorted to drop the key, re-free for the dup), or cross-cache.
- **top chunk size sanity** in sysmalloc -> **House of Force dead**.
- Unsorted bin integrity: `bck->fd != victim` -> "corrupted ... unsorted chunks";
  the naive unsorted-bin attack is constrained (target+0x10 must be writable, and the
  write side is checked). Last-remainder split also validated.
- setcontext shifts: pre-2.29 `setcontext+53` takes the ucontext from **rdi**; 2.29+ it
  is taken from **rdx**, so you need a `mov rdx,[reg]; call` magic gadget (often
  `setcontext+61`). See house-of-techniques.md "setcontext + ORW".

### glibc 2.30 (Aug 2019) — largebin checks

- **largebin insertion ordering checks** (`fd_nextsize`/`bk_nextsize`) -> **House of
  Storm dead**. Do not treat "largebin attack" as a generic arbitrary write on 2.30+:
  the nextsize path validates both the size ordering and the opposite link
  (`fwd->bk_nextsize->fd_nextsize == fwd` or `fwd->fd->bk_nextsize->fd_nextsize == fwd->fd`).
  A single-write largebin primitive can still exist, but only for the exact insertion path,
  chunk-size relation, and writable target shape observed in GDB. If the second chunk has
  the same size or lands in the wrong side of the skip-list insertion, the expected
  `target = victim` write will not happen.
- `tcache->counts` widened to `uint16_t`.

### glibc 2.31 (Feb 2020) — common modern target, hooks still alive

- tcache key + checks present, **no safe-linking yet, hooks still present.**
- Best of both worlds for the attacker: poison without a heap leak, land on
  `__free_hook`/`__malloc_hook`. Very frequent CTF version.

### glibc 2.32 (Aug 2020) — Safe-Linking + alignment check

- **Safe-Linking**: tcache and fastbin `fd` are mangled.
  `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`, where `pos` is the address of the fd field.
  You MUST leak a heap address first to forge a poisoned fd:
  `encoded_fd = (chunk_addr >> 12) ^ target`.
- **Alignment check** on tcache/fastbin fetch: "malloc(): unaligned tcache chunk
  detected" — the forged target must be 16-byte aligned.
- Everything else from 2.31 still holds (hooks present until 2.34).

### glibc 2.34 (Aug 2021) — hooks removed, csu removed

- **`__malloc_hook` / `__free_hook` / `__realloc_hook` / `__memalign_hook` removed**
  (compat symbols remain but have no effect). Do NOT plan around hooks at 2.34+.
- **`__libc_csu_init` / `__libc_csu_fini` removed** — classic ret2csu gadget set is gone;
  use other universal gadgets or a libc leak + one_gadget/ROP.
- Pivot targets become: FILE/FSOP (House of Apple 2, Cat), exit handlers
  (`__run_exit_handlers` / `tls_dtor_list`), `_rtld_global` (House of Banana),
  `__environ`-based stack return, setcontext+ORW, `tcache_perthread_struct`.

### glibc 2.35 (Feb 2022) — mainstream modern target

- The current "hard heap" baseline for many CTFs. Go-to routes: **House of Apple 2**
  (`_IO_wfile_jumps` wide-vtable), **House of Cat** (RDX-clean setcontext into ORW),
  **House of Kiwi** (assert path), large/tcache-struct attacks, House of Banana on exit.
- Exit-handler function pointers are PTR_MANGLE'd (rol + xor with `fs:[0x30]` guard);
  to hijack them you need the pointer guard (leak `fs:[0x30]`) or House of Emma's approach.

### glibc 2.36 - 2.40 — incremental, keep offsets fresh

- 2.37: `__malloc_assert` removed/changed; House of Kiwi's assert-trigger path needs the
  version-correct flow (2.36 uses `__libc_message`, 2.37 drops the function). vfprintf/
  printf internals refactored — **House of Husk still works** but table offsets move.
- 2.38: `__printf_buffer` machinery added — House of Obstack chain becomes
  `__printf_buffer_as_file_overflow -> __printf_buffer_flush -> ...`. Some House of
  Apple 2 stack-pivot variants stop pivoting (RIP hijack still works; the `leave;ret`
  pivot through that exact path may fail — 2.35 still pivots). Verify in GDB.
- 2.39 / 2.40: no offense-relevant structural change; treat as "modern, hookless,
  safe-linked, vtable-checked." House of Apple 2 / Cat / Banana remain the staples.

### glibc 2.41 (Feb 2025)

- **Dumped-heap support removed**: `malloc_set_state()` always returns -1. No exploitation
  impact. **Fastbins are NOT removed in 2.41** — a common myth; verify in GDB, the
  fastbins array still exists.

### glibc 2.42 (Aug 2025) — large-block tcache (IMPORTANT)

- **tcache has separate small and large classes**: `TCACHE_SMALL_BINS=64` plus
  `TCACHE_LARGE_BINS=12` (up to about 4 MB), with large tcache indexed logarithmically.
- The default threshold is near the old small-tcache maximum (`MAX_TCACHE_SMALL_SIZE + 1`),
  but the tunable `glibc.malloc.tcache_max` can raise it. If it is raised, large frees may
  be captured by tcache before they ever become an unsorted/largebin leak or largebin-write
  candidate. Check `mp_.tcache_max_bytes`, `mp_.tcache_small_bins`, and the actual bin after
  `free` in GDB before assuming a 0x420+ chunk reaches unsorted.

### glibc 2.43 (Jan 2026)

- C23 `free_sized` / `free_aligned_sized` / `memset_explicit` / `memalignment`; `mseal`
  (mappings can be sealed against mprotect/munmap/remap — relevant if a target seals
  pages you wanted to ret2mprotect); `openat2`. No fastbin removal.

### Future / bleeding-edge master — fastbin removal

- The Oct 2025 "malloc: Remove fastbins" work has appeared on glibc master after the
  release branches tracked above: `malloc.c` no longer contains fastbin paths or
  `global_max_fast`, Safe-Linking text only mentions tcache, and `TCACHE_FILL_COUNT` is 16.
  Treat this as bleeding-edge/future-release behavior unless the provided libc proves it.
- When it lands, every fastbin-based route dies: fastbin attack, fastbin dup, House of
  Rabbit, fastbin-reverse-into-tcache, malloc_consolidate-overlap tricks. Everything
  routes through tcache and normal bins. **Always confirm the fastbins array actually exists
  in GDB (`bins` / `p main_arena.fastbinsY`) before planning a fastbin route on a
  bleeding-edge libc.**

## Primitive to Route

Cross off whatever the resolved version killed.

### UAF with Show

- Leak heap from a freed tcache/fastbin `fd` (mandatory groundwork on 2.32+ for safe-linking).
- Leak libc from a chunk that entered the unsorted bin (size 0x90..0x3f0 by default; on
  2.42 with raised `tcache_max`, force unsorted differently).
- Then: tcache poisoning, fastbin attack (if fastbins exist), largebin attack, FILE/FSOP,
  hook overwrite if <= 2.33, or stack-return via `__environ`.

### UAF with Edit

- tcache poisoning for 2.26+; on 2.32+ encode fd with the leaked heap addr and keep 16-align.
- <= 2.33: `__free_hook = system` / `setcontext` or one_gadget.
- 2.34+: FILE structures, `tcache_perthread_struct`, exit handlers, `_rtld_global`,
  stack return. See house-of-techniques.md for the FSOP chains.

### Double Free

- 2.26-2.28: simple tcache dup.
- 2.29+: key blocks direct dup -> House of Botcake, key-clobber via UAF, cross-cache,
  consolidation overlap.
- Fastbin double free still needs the size-match and "not list head" checks (and a live
  fastbins array on bleeding-edge libc).

### Off-by-One / Off-by-Null

- <= 2.28: House of Einherjar and overlap-via-unsorted are easy.
- 2.29+: stricter `prev_size`/`size` consistency; build the overlap with an unsorted-bin
  assisted layout and exact fake `prev_size`. See house-of-techniques.md "off-by-null overlap".
- Use the overlap to create a leak, tcache poison, or arbitrary write.

### Overflow into Top Chunk

- House of Force only on <= 2.28 (2.29 top size check kills it).
- 2.29+: House of Orange / House of Tangerine style (force the old top into unsorted),
  only if version and no-free conditions fit.

### Largebin Write

- Potentially writes a heap chunk pointer through the largebin nextsize insertion path, but
  it is not a default arbitrary write on modern glibc.
- 2.30+ ordering checks: House of Storm is dead; a single-write form is version- and
  layout-dependent. Confirm the exact write in GDB at the largebin insertion site before
  choosing FILE/rtld/mp_ targets.
- Follow-ups: `_IO_list_all`, `stderr`/FILE, `mp_.tcache_bins`, `global_max_fast`,
  `_rtld_global`, tcache metadata. See house-of-techniques.md.

### Arbitrary Write — target by version

- Partial RELRO: GOT overwrite.
- <= 2.33: `__free_hook` / `__malloc_hook` / `__realloc_hook`.
- 2.34+: FILE (House of Apple 2 / Cat), exit handlers, `tcache_perthread_struct`,
  `_rtld_global` (House of Banana), `__environ` stack return, setcontext chain, vtables.
- Seccomp present: prefer ORW (setcontext+ORW, or FSOP -> ORW), not `system('/bin/sh')`.

## Challenge-Limit Routing

- **Limited add count**: reuse chunks — UAF edit/show, overlap, largebin write, FILE
  corruption. Avoid routes that fill many tcache bins.
- **Limited free/delete count**: avoid Botcake / tcache-fill-heavy routes; prefer direct
  overflow, format string, top-chunk, or a single largebin/arbitrary write.
- **Limited edit count**: spend each edit on the highest-value mutation (poison fd,
  corrupt size, write FILE fields, plant final frame). Do layout with alloc/free order.
- **Size restrictions**: map allowed sizes to tcache/fastbin/smallbin/largebin classes.
  Only small chunks -> tcache poison, fastbin (if present), tcache-struct, House of
  Minho (scanf-spawned big chunk). Large allowed -> unsorted/largebin leaks and writes
  (recheck `tcache_max` on 2.42+).
- **No show**: leak via stdout FILE corruption, format string, unsorted/IO side effects,
  stack leak, partial overwrite, or BROP.
- **No free**: House of Orange / Tangerine, direct overflow, format string, FILE
  corruption, or logic bug.
- **No leak at all (leakless)**: partial-overwrite poison, House of Roman/Rust,
  House of Water (tcache-struct, leakless), House of Blindness (link_map at exit).
- **Seccomp**: ORW only; build the syscall set from `seccomp-tools dump`.

## Verification Reminders

- For 2.32+ safe-linking, compute and check the encoded fd from the live chunk address:
  `encoded_fd = (chunk_addr >> 12) ^ target` and confirm 16-byte alignment of `target`.
- For any unsorted/largebin plan on 2.42+, confirm the free actually reaches the unsorted
  bin and was not captured by an enlarged tcache.
- For any fastbin plan, confirm the fastbins array is present and the size class matches.
- For FSOP, confirm the exact jumps-table offset and that the program actually reaches
  `exit`/`fflush`/`printf`/`malloc_assert`/FILE op that drives your chosen chain.
