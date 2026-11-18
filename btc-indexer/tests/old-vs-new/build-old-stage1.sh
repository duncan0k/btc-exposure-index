#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 <old-source-dir> <work-dir>" >&2
    exit 1
fi
source_dir=$1
work=$2
mkdir -p -- "$work"
work=$(cd -- "$work" && pwd)
target=$work/old-stage1
if [[ -e "$target" ]]; then
    echo "FAIL fresh old-stage1 directory required" >&2
    exit 1
fi
cp -R -- "$source_dir" "$target"
python3 -I - "$target/src/main.rs" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_bytes()
anchor = b"    // Step 1B: Reduce h32_00..15.bin immediately to free 33 GB SSD space"
lines = source.splitlines(keepends=True)
matches = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == anchor]
if len(matches) != 1:
    sys.exit(f"FAIL {path}: expected exactly one stage-1 anchor, found {len(matches)}")
index = matches[0]
newline = b"\r\n" if lines[index].endswith(b"\r\n") else b"\n"
lines.insert(index, b'    if std::env::var_os("BTC_INDEXER_STOP_AFTER_STAGE1").is_some() { return; }' + newline)
path.write_bytes(b"".join(lines))
PY
(cd -- "$target" && CARGO_TARGET_DIR="$target/target" cargo build --release --locked)
printf '%s\n' "$target/target/release/btc-indexer"
