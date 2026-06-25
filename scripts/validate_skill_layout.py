#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skill' / 'ctf-pwn'
REQUIRED = [
    SKILL / 'SKILL.md',
    SKILL / 'agents' / 'openai.yaml',
    SKILL / 'references' / 'ctf-workflow.md',
    SKILL / 'references' / 'tmux-debugging.md',
    SKILL / 'references' / 'exploit-templates.md',
    SKILL / 'references' / 'technique-index.md',
    SKILL / 'references' / 'glibc-heap-version-map.md',
    SKILL / 'references' / 'house-of-techniques.md',
    SKILL / 'templates' / 'exp.py',
    SKILL / 'templates' / 'solve-state.md',
    ROOT / 'README.md',
]

errors = []

for path in REQUIRED:
    if not path.exists():
        errors.append(f'missing required file: {path.relative_to(ROOT)}')

skill_md = SKILL / 'SKILL.md'
if skill_md.exists():
    text = skill_md.read_text(encoding='utf-8')
    if not text.startswith('---\n'):
        errors.append('SKILL.md must start with YAML frontmatter')
    if 'name: ctf-pwn' not in text:
        errors.append('SKILL.md frontmatter must include name: ctf-pwn')
    if 'description:' not in text:
        errors.append('SKILL.md frontmatter must include description')
    for ref in [
        'references/ctf-workflow.md',
        'references/tmux-debugging.md',
        'references/exploit-templates.md',
        'references/technique-index.md',
        'references/glibc-heap-version-map.md',
        'references/house-of-techniques.md',
    ]:
        if ref not in text:
            errors.append(f'SKILL.md does not mention {ref}')

openai = SKILL / 'agents' / 'openai.yaml'
if openai.exists():
    text = openai.read_text(encoding='utf-8')
    if '$ctf-pwn' not in text:
        errors.append('agents/openai.yaml default_prompt must mention $ctf-pwn')
    for key in ['display_name:', 'short_description:', 'default_prompt:']:
        if key not in text:
            errors.append(f'agents/openai.yaml missing {key}')

for path in SKILL.rglob('*'):
    if path.is_file():
        try:
            path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            errors.append(f'non-utf8 file: {path.relative_to(ROOT)}')

exp = SKILL / 'templates' / 'exp.py'
if exp.exists():
    text = exp.read_text(encoding='utf-8')
    for token in ['def start', 'def add', 'def edit', 'def show', 'def delete', 'gdb.attach']:
        if token not in text:
            errors.append(f'templates/exp.py missing {token}')

if errors:
    for err in errors:
        print(f'ERROR: {err}', file=sys.stderr)
    sys.exit(1)

print('skill layout ok')
