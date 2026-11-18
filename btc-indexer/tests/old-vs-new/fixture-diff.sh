#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "Usage: $0 <old-binary> <new-binary> <fixture-dir> <work-dir> <old-stage1-binary>" >&2
    exit 1
fi
old=$1
new=$2
fixture=$3
work=$4
old_stage1=$5
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p -- "$work"
if [[ -e "$work/old" || -e "$work/new" || -e "$work/old-stage1-scan" ]]; then
    echo "FAIL fresh output directories required" >&2
    exit 1
fi
if ! "$old" --scan-blocks "$fixture/blocks" "$work/old" >"$work/old.log" 2>&1; then
    echo "FAIL old fixture scan"
    exit 1
fi
if ! "$new" --scan-blocks "$fixture/blocks" "$work/new" "$fixture/chain-list.txt" >"$work/new.log" 2>&1; then
    echo "FAIL new fixture scan"
    exit 1
fi
if ! BTC_INDEXER_STOP_AFTER_STAGE1=1 "$old_stage1" --scan-blocks "$fixture/blocks" "$work/old-stage1-scan" >"$work/old-stage1.log" 2>&1; then
    echo "FAIL old stage-1 fixture scan"
    exit 1
fi
failed=0
python3 -I "$script_dir/state-oracle.py" "$work/old-stage1-scan/shards" "$work/new" || failed=1
if ! python3 -I - "$work" <<'PY'
import hashlib
import json
import pathlib
import struct
import sys

work = pathlib.Path(sys.argv[1])
failed = False
def check(ok, label):
    global failed
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    failed |= not ok

def ripemd160_python(data):
    # Standard RIPEMD-160: two parallel 80-step lanes over little-endian words.
    left_words = (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    )
    right_words = (
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    )
    left_shifts = (
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    )
    right_shifts = (
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    )
    left_constants = (0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e)
    right_constants = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0)
    mask = 0xffffffff

    def rol(value, shift):
        value &= mask
        return ((value << shift) | (value >> (32 - shift))) & mask

    def mix(round_index, b, c, d):
        if round_index == 0:
            return b ^ c ^ d
        if round_index == 1:
            return (b & c) | (~b & d)
        if round_index == 2:
            return (b | ~c) ^ d
        if round_index == 3:
            return (b & d) | (c & ~d)
        return b ^ (c | ~d)

    bit_length = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((56 - len(data)) % 64)
    data += struct.pack("<Q", bit_length)
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    for offset in range(0, len(data), 64):
        words = struct.unpack("<16I", data[offset:offset + 64])
        a, b, c, d, e = state
        aa, bb, cc, dd, ee = state
        for step in range(80):
            round_index = step // 16
            t = (rol(a + mix(round_index, b, c, d) + words[left_words[step]]
                     + left_constants[round_index], left_shifts[step]) + e) & mask
            a, b, c, d, e = e, t, b, rol(c, 10), d
            t = (rol(aa + mix(4 - round_index, bb, cc, dd) + words[right_words[step]]
                     + right_constants[round_index], right_shifts[step]) + ee) & mask
            aa, bb, cc, dd, ee = ee, t, bb, rol(cc, 10), dd
        state = [
            (state[1] + c + dd) & mask,
            (state[2] + d + ee) & mask,
            (state[3] + e + aa) & mask,
            (state[4] + a + bb) & mask,
            (state[0] + b + cc) & mask,
        ]
    return struct.pack("<5I", *state)

try:
    hashlib.new("ripemd160")
except ValueError:
    ripemd160 = ripemd160_python
else:
    def ripemd160(data):
        return hashlib.new("ripemd160", data).digest()

# Test the fallback even when hashlib supports RIPEMD-160.
check(all(digest(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
          for digest in (ripemd160, ripemd160_python)), "RIPEMD-160 self-test")
if failed:
    sys.exit(1)

def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())

for name in (
    "pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin",
    "cross_format_diff_20.bin", "cross_format_diff_32.bin",
):
    ok = (work / "old" / name).read_bytes() == (work / "new" / name).read_bytes()
    print(f"{'PASS' if ok else 'FAIL'} {name}")
    failed |= not ok
old = json.loads((work / "old/stats.json").read_bytes())
new = json.loads((work / "new/stats.json").read_bytes())
new.pop("scan_height", None)
new.pop("scan_block_hash", None)
for label, value in (("old", old), ("new", new)):
    (work / f"{label}-stats-normalized.json").write_bytes(
        json.dumps(value, sort_keys=True, indent=2).encode("utf-8")
    )
ok = (work / "old-stats-normalized.json").read_bytes() == (work / "new-stats-normalized.json").read_bytes()
print(f"{'PASS' if ok else 'FAIL'} stats.json")
failed |= not ok
for key, minimum in (
    ("unique_published_x_coords", 24), ("exposed_h160_entries", 24),
    ("revealed_p2sh_20_entries", 6), ("revealed_p2wsh_32_entries", 6),
    ("cross_format_diff_20_entries", 2), ("cross_format_diff_32_entries", 2),
):
    actual = new.get(key, 0)
    check(actual >= minimum, f"{key} >= {minimum} (actual={actual})")
for key in (
    "keys_in_both_p2pk_and_p2pkh", "keys_in_both_p2pkh_and_p2wpkh",
    "keys_in_both_compressed_and_uncompressed",
):
    actual = new.get("cross_type_reuse", {}).get(key, 0)
    check(actual >= 1, f"cross_type_reuse.{key} >= 1 (actual={actual})")
for key in (
    "keys_funded_p2pk", "keys_funded_p2pkh", "keys_funded_p2wpkh", "keys_funded_p2sh_p2wpkh",
    "keys_comp_and_uncomp_any_type", "keys_hybrid_encoding_funded",
    "published_x_only_as_p2tr_output_key", "published_x_only_in_unrecognized_output_push",
    "published_x_in_key_position",
):
    actual = new.get("census", {}).get(key, 0)
    check(actual >= 1, f"census.{key} >= 1 (actual={actual})")
# stats.json has no invalid-point count; check the same x values directly using state/x.bin and finite-field arithmetic.
xs = (work / "new/state/x.bin").read_bytes()
prime = 2**256 - 2**32 - 977
invalid = 0
for offset in range(0, len(xs), 33):
    x = int.from_bytes(xs[offset:offset + 32], "big")
    rhs = (pow(x, 3, prime) + 7) % prime
    invalid += x >= prime or (rhs != 0 and pow(rhs, (prime - 1) // 2, prime) != 1)
check(invalid >= 2, f"off-curve published x >= 2 (actual={invalid})")
table = (work / "new/pubkey_hash_index.bin").read_bytes()
if len(xs) % 33 or len(table) % 20:
    check(False, "twelve-form input record widths (x=33, pubkey_hash=20)")
    sys.exit(1)
pubkey_hashes = {table[offset:offset + 20] for offset in range(0, len(table), 20)}
counts = [0] * 12
explained = set()
for offset in range(0, len(xs), 33):
    x_bytes = xs[offset:offset + 32]
    x = int.from_bytes(x_bytes, "big")
    if x >= prime:
        continue
    rhs = (pow(x, 3, prime) + 7) % prime
    y = pow(rhs, (prime + 1) // 4, prime)
    if pow(y, 2, prime) != rhs:
        continue
    if y & 1:
        y = prime - y
    even_y = y.to_bytes(32, "big")
    odd_y = ((prime - y) % prime).to_bytes(32, "big")
    encodings = (
        b"\x02" + x_bytes, b"\x03" + x_bytes,
        b"\x04" + x_bytes + even_y, b"\x04" + x_bytes + odd_y,
        b"\x06" + x_bytes + even_y, b"\x07" + x_bytes + odd_y,
    )
    key_hashes = [hash160(encoding) for encoding in encodings]
    wrapped_hashes = [hash160(b"\x00\x14" + key_hash) for key_hash in key_hashes]
    for form, form_hash in enumerate(key_hashes + wrapped_hashes):
        counts[form] += form_hash in pubkey_hashes
        explained.add(form_hash)
for form, count in enumerate(counts):
    label = f"K_{form}" if form < 6 else f"W_{form - 6}"
    check(count > 0, f"twelve-form {label} (count={count})")
unexplained = sum(table[offset:offset + 20] not in explained for offset in range(0, len(table), 20))
check(unexplained == 0, f"unexplained pubkey table entries (count={unexplained})")
sys.exit(int(failed))
PY
then
    failed=1
fi
exit "$failed"

