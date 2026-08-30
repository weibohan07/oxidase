#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/versions.env"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 INSTALL_DIRECTORY" >&2
    exit 64
fi

install_dir=$1
downloads="$install_dir/downloads"
sources="$install_dir/sources"
mkdir -p "$downloads" "$sources"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

fetch_one() {
    name=$1
    url=$2
    expected=$3
    destination="$downloads/$name.tar.gz"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --retry 3 --output "$destination" "$url"
    actual=$(sha256_file "$destination")
    if [ "$actual" != "$expected" ]; then
        echo "$name archive checksum mismatch: expected $expected, got $actual" >&2
        exit 65
    fi
    printf '%s  %s\n' "$actual" "$name.tar.gz"
}

fetch_file() {
    filename=$1
    url=$2
    expected=$3
    destination="$downloads/$filename"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --retry 3 --output "$destination" "$url"
    actual=$(sha256_file "$destination")
    if [ "$actual" != "$expected" ]; then
        echo "$filename checksum mismatch: expected $expected, got $actual" >&2
        exit 65
    fi
    printf '%s  %s\n' "$actual" "$filename"
}

extract_one() {
    name=$1
    destination="$sources/$name"
    if [ -e "$destination" ]; then
        echo "refusing to replace existing source directory: $destination" >&2
        exit 73
    fi
    mkdir "$destination"
    tar -xzf "$downloads/$name.tar.gz" -C "$destination" --strip-components=1
}

fetch_one h2spec "$H2SPEC_URL" "$H2SPEC_SHA256"
fetch_one autobahn-testsuite "$AUTOBAHN_URL" "$AUTOBAHN_SHA256"
fetch_one tlsfuzzer "$TLSFUZZER_URL" "$TLSFUZZER_SHA256"
fetch_one httpwookiee "$HTTPWOOKIEE_URL" "$HTTPWOOKIEE_SHA256"
fetch_one tlslite-ng "$TLSLITE_NG_URL" "$TLSLITE_NG_SHA256"
fetch_file ecdsa-0.19.0-py2.py3-none-any.whl "$ECDSA_URL" "$ECDSA_SHA256"
fetch_file six-1.17.0-py2.py3-none-any.whl "$SIX_URL" "$SIX_SHA256"
fetch_file termcolor-3.1.0-py3-none-any.whl "$TERMCOLOR_URL" "$TERMCOLOR_SHA256"

extract_one h2spec
extract_one autobahn-testsuite
extract_one tlsfuzzer
extract_one httpwookiee
extract_one tlslite-ng
