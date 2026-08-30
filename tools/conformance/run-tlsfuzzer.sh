#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 TOOL_DIRECTORY RESULT_DIRECTORY" >&2
    exit 64
fi

tool_dir=$1
result_dir=$2
source_dir="$tool_dir/sources/tlsfuzzer"
venv="$tool_dir/tlsfuzzer-venv"
python=${PYTHON:-python3}
mkdir -p "$result_dir"

"$python" -m venv "$venv"
"$venv/bin/pip" install --disable-pip-version-check --no-index --no-deps \
    "$tool_dir/downloads/six-1.17.0-py2.py3-none-any.whl" \
    "$tool_dir/downloads/ecdsa-0.19.0-py2.py3-none-any.whl" \
    >"$result_dir/tlsfuzzer-install.txt" 2>&1

python_path="$source_dir:$tool_dir/sources/tlslite-ng"
status=0

PYTHONPATH="$python_path" "$venv/bin/python" \
    "$source_dir/scripts/test-invalid-client-hello.py" \
    -h 127.0.0.1 -p 18443 \
    "Client Hello type fuzz to 69" \
    "cipher suites len fuzz to 1225" \
    "extensions len fuzz to 619" \
    "compression methods len fuzz to 76 w/ext" \
    "session ID len fuzz to 252 w/ext" \
    >"$result_dir/tlsfuzzer-invalid-client-hello.txt" 2>&1 || status=1

PYTHONPATH="$python_path" "$venv/bin/python" \
    "$source_dir/scripts/test-tls13-version-negotiation.py" \
    -h 127.0.0.1 -p 18443 sanity \
    >"$result_dir/tlsfuzzer-tls13-sanity.txt" 2>&1 || status=1

PYTHONPATH="$python_path" "$venv/bin/python" \
    "$source_dir/scripts/test-tls13-version-negotiation.py" \
    -h 127.0.0.1 -p 18443 \
    "tls 1.3 negotiation with SSL 3.0 in record layer" \
    "tls 1.3 negotiation with SSL 3.1 in record layer" \
    "tls 1.3 negotiation with SSL 3.2 in record layer" \
    "tls 1.3 negotiation with SSL 3.3 in record layer" \
    "tls 1.8 only" \
    "SSL 3.0 in supported version" \
    >"$result_dir/tlsfuzzer-version-boundaries.txt" 2>&1 || status=1

exit "$status"
