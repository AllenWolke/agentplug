#!/usr/bin/env bash
# Platform stack launcher. All arguments remain literal process arguments.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PYTHON:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then python_bin=python; fi
if [[ $# -eq 0 ]]; then set -- up; fi
exec "$python_bin" "${script_dir}/compose.py" "$@"
