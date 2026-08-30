#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$#" -ne 2 ]; then
    echo "usage: $0 TOOL_DIRECTORY RESULT_DIRECTORY" >&2
    exit 64
fi

tool_dir=$1
result_dir=$2
source_dir="$tool_dir/sources/httpwookiee"
venv="$tool_dir/httpwookiee-venv"
python=${PYTHON:-python3}
mkdir -p "$result_dir"

"$python" -m venv "$venv"
"$venv/bin/pip" install --disable-pip-version-check --no-index --no-deps \
    "$tool_dir/downloads/six-1.17.0-py2.py3-none-any.whl" \
    "$tool_dir/downloads/termcolor-3.1.0-py3-none-any.whl" \
    >"$result_dir/httpwookiee-install.txt" 2>&1

HTTPWOOKIEE_CONF="$script_dir/fixture/httpwookiee.conf" \
    PYTHONPATH="$source_dir" \
    "$venv/bin/python" "$script_dir/run-httpwookiee.py" \
    "$source_dir" "$result_dir/httpwookiee-summary.json" \
    >"$result_dir/httpwookiee.txt" 2>&1
