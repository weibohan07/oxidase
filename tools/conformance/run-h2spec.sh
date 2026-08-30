#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 TOOL_DIRECTORY RESULT_DIRECTORY" >&2
    exit 64
fi

tool_dir=$1
result_dir=$2
python=${PYTHON:-python3}
mkdir -p "$tool_dir/bin" "$result_dir"

(
    cd "$tool_dir/sources/h2spec"
    go build -trimpath -o "$tool_dir/bin/h2spec" ./cmd/h2spec
)

status=0
cargo test -p oxidase-server --test security_tls_h2 \
    rejects_closed_stream_reuse_and_non_terminating_trailer_headers_after_queued_data \
    --locked \
    >"$result_dir/h2spec-timing-regression.txt" 2>&1 || status=1

"$tool_dir/bin/h2spec" \
    --host 127.0.0.1 \
    --port 18443 \
    --tls \
    --insecure \
    --strict \
    --junit-report "$result_dir/h2spec.xml" \
    >"$result_dir/h2spec.txt" 2>&1 || true

"$python" "$(dirname -- "$0")/validate-h2spec.py" \
    "$result_dir/h2spec.xml" "$result_dir/h2spec-summary.json" || status=1
exit "$status"
