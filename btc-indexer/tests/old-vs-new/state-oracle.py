#!/usr/bin/env python3
"""Compare the persisted scan state with the old scanner's stage-1 shards."""
import pathlib
import sys


def read_shards(directory, prefix, count, key_size):
    merged = {}
    width = key_size + 1
    for index in range(count):
        path = directory / f"{prefix}_{index:02}.bin"
        data = path.read_bytes()
        if len(data) % width:
            raise ValueError(f"{path}: length {len(data)} is not a multiple of {width}")
        for offset in range(0, len(data), width):
            key = data[offset:offset + key_size]
            merged[key] = merged.get(key, 0) | data[offset + key_size]
    return sorted(merged.items())


def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <shards-dir> <new-out-dir>")
    shards, output = map(pathlib.Path, sys.argv[1:])
    try:
        xs = read_shards(shards, "x", 64, 32)
        h20 = read_shards(shards, "h20", 64, 20)
        h32 = read_shards(shards, "h32", 16, 32)
    except (OSError, ValueError) as error:
        print(f"FAIL state oracle: {error}")
        return 1
    expected = (
        ("x.bin", 33, b"".join(key + bytes([mask]) for key, mask in xs)),
        ("f20.bin", 21, b"".join(key + bytes([mask & 7]) for key, mask in h20 if mask & 7)),
        ("r20.bin", 21, b"".join(key + bytes([mask & 24]) for key, mask in h20 if mask & 24)),
        ("f32.bin", 32, b"".join(key for key, mask in h32 if mask & 1)),
        ("r32.bin", 33, b"".join(key + bytes([mask & 6]) for key, mask in h32 if mask & 6)),
    )
    failed = False
    for name, width, reference in expected:
        path = output / "state" / name
        try:
            actual = path.read_bytes()
            ok = actual == reference
            counts = f"old={len(reference) // width} new={len(actual) // width}"
            if len(actual) % width:
                counts += f" trailing_bytes={len(actual) % width}"
        except OSError as error:
            ok = False
            counts = f"old={len(reference) // width} new=unavailable ({error})"
        print(f"{'PASS' if ok else 'FAIL'} state/{name} {counts}")
        failed |= not ok
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
