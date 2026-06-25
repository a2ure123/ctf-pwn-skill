# Contributing

Keep `SKILL.md` concise. Put detailed exploitation notes in `skill/ctf-pwn/references/` and reusable files in `skill/ctf-pwn/templates/`.

Before opening a pull request, run:

```bash
python3 scripts/validate_skill_layout.py
```

When adding a new technique, prefer this shape:

- signals that identify the technique
- version and protection constraints
- GDB/pwndbg verification points
- common failure modes
- minimal exploit pattern or target selection notes
