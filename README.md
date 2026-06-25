# ctf-pwn Skill

A CTF pwn solving skill for agent CLIs (Codex, Claude Code, and other SKILL.md-compatible runtimes). It guides the agent through a workflow that mirrors a practical pwn player:

1. inspect protections and files,
2. reproduce the remote libc/loader environment,
3. reverse with IDA/idat/idalib,
4. write stable pwntools wrappers,
5. debug step by step with a persistent GDB (tmux CLI), inferior-tty, and pwndbg,
6. choose exploitation routes by primitive, glibc version, and challenge limits,
7. iterate until the local exploit is stable and then adapt remote.

## Repository Layout

```text
ctf-pwn-skill/
├── skill/ctf-pwn/        # installable skill (SKILL.md format)
│   ├── SKILL.md
│   ├── agents/openai.yaml   # Codex-specific agent metadata (ignored by other runtimes)
│   ├── references/
│   └── templates/
├── examples/challenge-workspace/
├── scripts/validate_skill_layout.py
└── .github/workflows/validate.yml
```

The skill itself is just a `SKILL.md` (YAML frontmatter `name`/`description` + body)
plus progressive-disclosure `references/`, so the same folder installs unchanged into
any agent that supports the SKILL.md convention. `agents/openai.yaml` only carries
optional Codex agent metadata; runtimes that do not understand it simply ignore it.

## Install Locally

The installer copies `skill/ctf-pwn/` into each target runtime's skills directory.

```bash
./scripts/install_local.sh            # default: install for codex AND claude
./scripts/install_local.sh claude     # Claude Code (user scope)  -> ~/.claude/skills/ctf-pwn
./scripts/install_local.sh codex      # Codex                      -> ~/.codex/skills/ctf-pwn
./scripts/install_local.sh claude-project  # project scope        -> ./.claude/skills/ctf-pwn
./scripts/install_local.sh ~/.config/agent/skills   # any custom skills dir
```

Override the runtime home with environment variables when needed:
`CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `GEMINI_CONFIG_DIR`.

Or copy the skill folder manually into whichever runtime you use:

```bash
# Codex
mkdir -p ~/.codex/skills && rm -rf ~/.codex/skills/ctf-pwn && cp -r skill/ctf-pwn ~/.codex/skills/

# Claude Code (user scope)
mkdir -p ~/.claude/skills && rm -rf ~/.claude/skills/ctf-pwn && cp -r skill/ctf-pwn ~/.claude/skills/

# Claude Code (project scope)
mkdir -p .claude/skills && rm -rf .claude/skills/ctf-pwn && cp -r skill/ctf-pwn .claude/skills/
```

In Claude Code, confirm it loaded with `/skills` (or just ask a pwn question that
matches the description). In Codex it auto-registers from `~/.codex/skills`.

## Validate

```bash
python3 scripts/validate_skill_layout.py
```

The validator checks the skill frontmatter, required references, templates, and ASCII-safe source content.

## Example Trigger Prompts

- `帮我分析这个 pwn 题并写 exp`
- `用 tmux gdb 调一下这个堆题`
- `这个 libc 2.31 的 UAF 题怎么选利用方式`
- `这是 glibc 2.35 的堆题，没有 hook 了，该用 House of Apple 2 还是 House of Cat`
- `2.39 的题想打 FSOP 拿 shell，帮我梳理 _IO_wfile_jumps 的伪造字段`
- `这个堆题只能申请 0x20 小块，怎么搞 libc leak`
- `看一下 IDA 反编译后帮我封装菜单和调试`
- `这个 seccomp pwn 题需要 ORW，帮我分步调试`

## Design Notes

`SKILL.md` stays focused on the mandatory workflow. The tmux-CLI persistent-GDB debugging path is intentionally first-class. Larger technique details live in `references/` so the agent loads only the relevant material: heap version map, House-of technique catalog, technique index, CTF workflow, and exploit templates.

Heap challenges are version-gated on purpose: `SKILL.md` forces the agent to fingerprint the glibc version first, then `references/glibc-heap-version-map.md` maps that version to its live mitigations and `references/house-of-techniques.md` lists which House-of / FSOP routes are still viable. The catalog is kept current through glibc 2.43 (Jan 2026) and flags the proposed fastbin removal that is still under review.
