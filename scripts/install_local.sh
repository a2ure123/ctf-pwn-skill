#!/usr/bin/env bash
set -euo pipefail

# Install the ctf-pwn skill for one or more agent runtimes.
#
# Usage:
#   ./scripts/install_local.sh [target ...]
#
# Targets:
#   codex            ~/.codex/skills/ctf-pwn            (override dir with $CODEX_HOME)
#   claude           ~/.claude/skills/ctf-pwn           (override dir with $CLAUDE_CONFIG_DIR)
#   claude-project   ./.claude/skills/ctf-pwn           (project-local, in $PWD)
#   gemini           ~/.gemini/skills/ctf-pwn           (override dir with $GEMINI_CONFIG_DIR)
#   all              codex + claude (the default when no target is given)
#   <path>           any absolute/relative directory; the skill is copied to <path>/ctf-pwn
#
# Examples:
#   ./scripts/install_local.sh                 # install for codex and claude
#   ./scripts/install_local.sh claude          # claude only
#   ./scripts/install_local.sh codex claude    # both, explicitly
#   ./scripts/install_local.sh claude-project  # into ./.claude/skills for the current repo
#   ./scripts/install_local.sh ~/.config/agent/skills

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/skill/ctf-pwn"
SKILL_NAME="ctf-pwn"

install_to() {
  local skills_dir="$1"
  local dest="$skills_dir/$SKILL_NAME"
  mkdir -p "$skills_dir"
  rm -rf "$dest"
  cp -r "$SRC" "$dest"
  echo "installed $SKILL_NAME -> $dest"
}

resolve_target() {
  case "$1" in
    codex)          echo "${CODEX_HOME:-$HOME/.codex}/skills" ;;
    claude)         echo "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills" ;;
    claude-project) echo "$PWD/.claude/skills" ;;
    gemini)         echo "${GEMINI_CONFIG_DIR:-$HOME/.gemini}/skills" ;;
    /*|./*|../*|~*) echo "${1/#\~/$HOME}" ;;     # treat as a literal skills dir
    *)              return 1 ;;
  esac
}

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  targets=(all)
fi

# Expand the "all" convenience target.
expanded=()
for t in "${targets[@]}"; do
  if [ "$t" = "all" ]; then
    expanded+=(codex claude)
  else
    expanded+=("$t")
  fi
done

for t in "${expanded[@]}"; do
  if skills_dir="$(resolve_target "$t")"; then
    install_to "$skills_dir"
  else
    echo "unknown target: $t" >&2
    echo "valid targets: codex, claude, claude-project, gemini, all, or a directory path" >&2
    exit 1
  fi
done
