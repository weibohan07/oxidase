#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/versions.env"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 RESULT_DIRECTORY" >&2
    exit 64
fi

result_dir=$1
python=${PYTHON:-python3}
mkdir -p "$result_dir/autobahn"
result_dir=$(CDPATH= cd -- "$result_dir" && pwd)
container_name="oxidase-autobahn-echo-$$"

cleanup() {
    docker stop "$container_name" >"$result_dir/autobahn-echo-stop.txt" 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

echo_id=$(docker run --detach --rm --platform linux/amd64 \
    --name "$container_name" \
    --publish 127.0.0.1:19001:19001 \
    "$AUTOBAHN_IMAGE" \
    wstest --mode echoserver --wsuri ws://0.0.0.0:19001 --webport 0)
printf '%s\n' "$echo_id" >"$result_dir/autobahn-echo-container.txt"
"$python" "$script_dir/wait-for-ports.py" 19001

status=0
docker run --rm --platform linux/amd64 \
    --add-host host.docker.internal:host-gateway \
    --volume "$script_dir/fixture:/config:ro" \
    --volume "$result_dir/autobahn:/reports" \
    "$AUTOBAHN_IMAGE" \
    wstest --mode fuzzingclient --spec /config/autobahn-fuzzingclient.json \
    >"$result_dir/autobahn.txt" 2>&1 || status=$?

"$python" "$script_dir/validate-autobahn.py" \
    "$result_dir/autobahn/index.json" \
    "$result_dir/autobahn-summary.json" || status=$?
exit "$status"
