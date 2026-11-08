#!/usr/bin/env bash
# zapret-easy launcher.  Works from any directory and through a symlink
# in ~/.local/bin, for example:
#   ln -s /home/kyza/zapret-easy/run.sh ~/.local/bin/zapret-easy
set -euo pipefail

# Resolve symlinks so `cd` always lands in the project root, not in
# ~/.local/bin.
SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE" ]]; do
    DIR="$(cd -P -- "$(dirname -- "$SOURCE")" && pwd)"
    SOURCE="$(readlink -- "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
PROJECT_DIR="$(cd -P -- "$(dirname -- "$SOURCE")" && pwd)"
cd -- "$PROJECT_DIR"

PYTHON="${ZAPRET_EASY_PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
    if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
        PYTHON="$PROJECT_DIR/.venv/bin/python"
    else
        PYTHON="python3"
    fi
fi

# Rich and psutil are needed by the TUI; InquirerPy is optional (the UI has
# numbered-menu fallbacks), aiohttp is needed by the strategy tester.
if ! "$PYTHON" -c 'import rich, psutil' >/dev/null 2>&1; then
    cat >&2 <<EOF
zapret-easy: не найдены Python-зависимости.

Создайте окружение в проекте:
  cd "$PROJECT_DIR"
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt

Либо задайте интерпретатор:
  ZAPRET_EASY_PYTHON=/path/to/python ./run.sh
EOF
    exit 1
fi

exec "$PYTHON" "$PROJECT_DIR/main.py" "$@"
