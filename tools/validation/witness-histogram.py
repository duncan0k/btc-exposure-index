"""Witness-program histogram of a Bitcoin Core UTXO snapshot.

Usage:
    python3 -I witness-histogram.py SNAPSHOT OUT_JSON [--expect NAME=COUNT:SATS ...] [--progress N]

SNAPSHOT is a UTXO snapshot that you export yourself with the dumptxoutset RPC of Bitcoin Core at block height
975019 (block hash 0000000000000000000158c9898f947463d71d98c97f1dad1639e25114a1dae6). Only snapshot format
version 2 is read. The script does not check which block a snapshot belongs to: compare snapshot.base_hash in
the output with the hash above. OUT_JSON must not exist yet. Each --expect compares one entry of "aggregates"
in the output (output count and amount in satoshis) with a value you supply, for example a total taken from
utxo-census-stats.json. Python 3 standard library only, tested with Python 3.12; parsing the height-975019
snapshot (163,658,747 coins) took about 7 minutes on one CPU core.

The script is independent of utxo-census and shares no code with it. It follows only the Bitcoin Core
serialization:
  header: the bytes "utxo" and 0xff, uint16 version (2), 4-byte network magic, 32-byte base block hash,
          uint64 coin count (all little endian);
  body:   groups of [32-byte txid, CompactSize n, n times (CompactSize vout, Coin)];
  Coin:   VARINT(height * 2 + coinbase), VARINT(CompressAmount(value)), ScriptCompression(scriptPubKey);
  ScriptCompression: VARINT(k); k 0..5 are the special forms (20 bytes follow for 0 and 1, 32 bytes for 2..5),
          otherwise k - 6 raw script bytes follow.
A witness program is a raw script of 4..42 bytes whose first byte is OP_0 or OP_1..OP_16 and whose second byte
equals the script length minus 2 (CScript::IsWitnessProgram). The output holds aggregate counts and amounts,
plus one short list: every P2PK output whose key starts with 06 or 07 (hybrid encoding), with its outpoint,
height and amount, and whether the key is a curve point whose y parity matches the prefix. Such keys can only
appear as raw scripts, because Core compresses P2PK keys with prefixes 02, 03 and valid 04 only.

Exit status. When the file is run as a script, it passes the value that main() returns to sys.exit(). main()
returns only 0, 1 or 2. If SNAPSHOT does not change during the run and standard output and standard error can
be written, main() returns each value only in these cases:
  0  The parse read exactly the coin count of the header, ended exactly at the end of the file, and every
     --expect matched. The JSON has been written.
  1  The parse finished but at least one of those checks failed. The JSON has been written.
  2  No JSON is written. The arguments are wrong (including a malformed --expect), or -h or --help was given;
     or something exists at OUT_JSON (os.path.exists is true); or SNAPSHOT cannot be opened, its size cannot
     be read or is reported as 0, it cannot be mapped into memory, or closing it fails; or the parser stopped
     on the input: a file shorter than the 51-byte header, magic bytes other than "utxo" and 0xff, a version
     other than 2, a file that ends before the data of the last coin of the header count is complete (also
     when the 20- or 32-byte script data of that coin would run past the end of the file), a coin group with
     no coins, or a coin group that goes past the coin count of the header.
CPython then usually exits with the value that main() returned, unless a signal ends the process first or
interactive mode was requested, for example with -i. Other outcomes depend on the interpreter, the operating
system or the environment:
  - An exception that the script does not handle usually ends CPython with a traceback and status 1, for
    example an OUT_JSON in a directory that does not exist, a dangling symbolic link at OUT_JSON on Linux, or
    a write error on OUT_JSON. OUT_JSON may then be missing, partly written or complete, depending on when the
    error happened.
  - When the script runs in the foreground of a terminal, Ctrl-C usually sends it SIGINT. Unless SIGINT was
    ignored when the script started, CPython usually turns SIGINT into KeyboardInterrupt, prints a traceback
    and, in version 3.8 and later on POSIX systems, ends the process by SIGINT, which bash, for example,
    reports as status 130. If SIGINT was ignored when the script started, SIGINT usually does not interrupt
    the script. After an interrupt, OUT_JSON may be missing, partly written or complete.
  - Signals can end the process at any point, for example SIGBUS, which Linux can send when the snapshot is
    truncated while it is being read, or SIGKILL from an out-of-memory killer.
  - When standard output cannot be written, the status depends on buffering and on when the failure is
    noticed, for example 1, 2, or 120 (which CPython usually uses when it cannot flush standard output at
    exit), and the JSON can be missing even when the snapshot is good.
Treat a run as good only with exit status 0 and a JSON whose all_checks_ok is true.

Limits: the script does not check that CompactSize and VARINT values are canonically encoded, and it does not
limit VARINT values to the widths that Bitcoin Core uses. A file that Core would refuse for these reasons can
still be parsed and can end with exit status 0. The script is meant to cross-check snapshots written by
Bitcoin Core: a misaligned or mismatched file shows up as a coin count that differs from the header, a parse
that does not end exactly at the end of the file, or totals that differ from the values given with --expect.
It is not a general validator of the snapshot format.
"""
import argparse
import json
import mmap
import os
import sys
import time

MAGIC = b"utxo" + bytes([0xFF])
P2PKH_HEAD = bytes([0x76, 0xA9, 0x14])
P2PKH_TAIL = bytes([0x88, 0xAC])
SECP256K1_P = 2 ** 256 - 2 ** 32 - 977
NAMES = ("total", "p2pkh", "p2sh", "p2pk", "v0_20", "v0_32", "v0_other", "v1_32", "v1_other", "v2_v16", "v2_32",
         "p2pk_hybrid_valid")


def decompress_amount(x):
    """Bitcoin Core DecompressAmount (compressor.cpp)."""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = x % 9 + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e:
        n *= 10
        e -= 1
    return n


def read_varint(buf, pos):
    """Bitcoin Core VARINT (serialize.h ReadVarInt): 7 bits per byte, high bit continues, plus one per continuation."""
    n = 0
    while True:
        b = buf[pos]
        pos += 1
        n = n * 128 + (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n, pos


def read_compact(buf, pos):
    """Bitcoin Core CompactSize."""
    b = buf[pos]
    if b < 253:
        return b, pos + 1
    width = 2 if b == 253 else (4 if b == 254 else 8)
    return int.from_bytes(buf[pos + 1:pos + 1 + width], "little"), pos + 1 + width


def is_raw_p2pk(buf, pos, length, first):
    return ((length == 35 and first == 33 and buf[pos + 34] == 0xAC)
            or (length == 67 and first == 65 and buf[pos + 66] == 0xAC))


def hybrid_key_status(key):
    """For a 65-byte key with prefix 06 or 07: is (x, y) on secp256k1, and does the parity of y match the prefix."""
    x = int.from_bytes(key[1:33], "big")
    y = int.from_bytes(key[33:65], "big")
    on_curve = x < SECP256K1_P and y < SECP256K1_P and (y * y - x * x * x - 7) % SECP256K1_P == 0
    return on_curve, (y & 1) == (key[0] & 1)


def scan(buf, size, progress=10_000_000, out=sys.stdout):
    if size < 51 or buf[0:5] != MAGIC:
        raise ValueError("not a UTXO snapshot (magic)")
    version = int.from_bytes(buf[5:7], "little")
    if version != 2:
        raise ValueError("unsupported snapshot version %d" % version)
    header = {"magic_hex": buf[0:5].hex(), "version": version, "network_magic": buf[7:11].hex(),
              "base_hash": buf[11:43][::-1].hex(), "coins_count": int.from_bytes(buf[43:51], "little")}
    count = header["coins_count"]
    pos, coins, sats = 51, 0, 0
    special = [[0, 0] for _ in range(6)]
    raw_p2pkh, raw_p2sh, raw_p2pk, raw_other = [0, 0], [0, 0], [0, 0], [0, 0]
    witness = {}
    hybrid = []
    start = time.monotonic()
    next_report = progress
    try:
        while coins < count:
            if pos + 32 > size:
                raise ValueError("truncated: %d of %d coins read" % (coins, count))
            txid_pos = pos
            pos += 32
            n, pos = read_compact(buf, pos)
            if n == 0:
                raise ValueError("empty coin group at offset %d" % pos)
            for _ in range(n):
                vout, pos = read_compact(buf, pos)
                code, pos = read_varint(buf, pos)
                amount_code, pos = read_varint(buf, pos)
                amount = decompress_amount(amount_code)
                kind, pos = read_varint(buf, pos)
                if kind < 6:
                    pos += 20 if kind < 2 else 32
                    cell = special[kind]
                else:
                    length = kind - 6
                    end = pos + length
                    if end > size:
                        raise ValueError("truncated script at offset %d" % pos)
                    first = buf[pos] if length else -1
                    if 4 <= length <= 42 and (first == 0 or 0x51 <= first <= 0x60) and buf[pos + 1] == length - 2:
                        key = (first - 0x50 if first else 0, length - 2)
                        cell = witness.get(key)
                        if cell is None:
                            cell = witness[key] = [0, 0]
                    elif length == 25 and buf[pos:pos + 3] == P2PKH_HEAD and buf[pos + 23:pos + 25] == P2PKH_TAIL:
                        cell = raw_p2pkh
                    elif length == 23 and first == 0xA9 and buf[pos + 1] == 0x14 and buf[pos + 22] == 0x87:
                        cell = raw_p2sh
                    elif is_raw_p2pk(buf, pos, length, first):
                        cell = raw_p2pk
                        if buf[pos + 1] in (0x06, 0x07):
                            entry = {"txid": buf[txid_pos:txid_pos + 32][::-1].hex(), "vout": vout,
                                     "height": code // 2, "coinbase": bool(code & 1), "amount_sats": amount,
                                     "key_length": length - 2, "prefix": "%02x" % buf[pos + 1]}
                            if length == 67:
                                on_curve, parity = hybrid_key_status(buf[pos + 1:pos + 66])
                                entry.update(on_curve=on_curve, parity_matches=parity, valid_hybrid=on_curve and parity)
                            else:
                                entry.update(on_curve=None, parity_matches=None, valid_hybrid=False)
                            hybrid.append(entry)
                    else:
                        cell = raw_other
                    pos = end
                cell[0] += 1
                cell[1] += amount
                sats += amount
                coins += 1
                if coins > count:
                    raise ValueError("more coins than the header count %d" % count)
            if coins >= next_report:
                print("coins %d offset %d elapsed %.1fs" % (coins, pos, time.monotonic() - start), file=out, flush=True)
                next_report += progress
    except IndexError:
        raise ValueError("truncated: %d of %d coins read" % (coins, count)) from None
    if pos > size:
        raise ValueError("parse ran past the end of the file")

    def total(cells):
        return [sum(c[0] for c in cells), sum(c[1] for c in cells)]

    def wit(pred):
        return total([c for k, c in witness.items() if pred(k)])

    valid_hybrid = [e for e in hybrid if e["valid_hybrid"]]
    agg = {
        "total": [coins, sats],
        "p2pkh": total([special[0], raw_p2pkh]),
        "p2sh": total([special[1], raw_p2sh]),
        "p2pk": total(special[2:6] + [raw_p2pk]),
        "v0_20": wit(lambda k: k == (0, 20)),
        "v0_32": wit(lambda k: k == (0, 32)),
        "v0_other": wit(lambda k: k[0] == 0 and k[1] not in (20, 32)),
        "v1_32": wit(lambda k: k == (1, 32)),
        "v1_other": wit(lambda k: k[0] == 1 and k[1] != 32),
        "v2_v16": wit(lambda k: k[0] >= 2),
        "v2_32": wit(lambda k: k == (2, 32)),
        "p2pk_hybrid_valid": [len(valid_hybrid), sum(e["amount_sats"] for e in valid_hybrid)],
    }
    table = {}
    for (v, length), cell in sorted(witness.items()):
        table.setdefault("v%d" % v, {})["%d" % length] = cell
    return {
        "snapshot": dict(header, size=size),
        "parsed": {"coins": coins, "sats": sats, "end_offset": pos, "trailing_bytes": size - pos,
                   "elapsed_seconds": round(time.monotonic() - start, 1)},
        "aggregates": agg,
        "special_forms": {str(i): special[i] for i in range(6)},
        "raw_non_witness": {"p2pkh": raw_p2pkh, "p2sh": raw_p2sh, "p2pk": raw_p2pk, "other": raw_other},
        "witness_programs": table,
        "hybrid_prefix_p2pk": sorted(hybrid, key=lambda e: (e["height"], e["txid"], e["vout"])),
    }


def parse_expect(text):
    name, _, value = text.partition("=")
    count, _, amount = value.partition(":")
    if name not in NAMES or not count.isdigit() or not amount.isdigit():
        raise argparse.ArgumentTypeError("expected NAME=COUNT:SATS with NAME in %s" % ", ".join(NAMES))
    return name, [int(count), int(amount)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Witness-program histogram of a UTXO snapshot.")
    parser.add_argument("snapshot")
    parser.add_argument("out_json")
    parser.add_argument("--expect", action="append", default=[], type=parse_expect)
    parser.add_argument("--progress", type=int, default=10_000_000)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if os.path.exists(args.out_json):
        print("error: %s exists" % args.out_json, file=sys.stderr)
        return 2
    try:
        with open(args.snapshot, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size == 0:
                raise ValueError("empty file")
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                result = scan(buf, size, args.progress)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    checks = [{"name": "coins_equal_header", "expected": result["snapshot"]["coins_count"],
               "got": result["parsed"]["coins"]},
              {"name": "ends_at_end_of_file", "expected": 0, "got": result["parsed"]["trailing_bytes"]}]
    for name, want in args.expect:
        checks.append({"name": "expect_" + name, "expected": want, "got": result["aggregates"][name]})
    for c in checks:
        c["ok"] = c["expected"] == c["got"]
    result["checks"] = checks
    result["all_checks_ok"] = all(c["ok"] for c in checks)
    with open(args.out_json, "x", encoding="ascii", newline="") as f:
        json.dump(result, f, indent=1)
        f.write(chr(10))
    a = result["aggregates"]
    print("v2_32 count %d sats %d" % tuple(a["v2_32"]))
    print("v2_v16 count %d sats %d" % tuple(a["v2_v16"]))
    print("hybrid-prefix P2PK outputs %d, valid hybrid keys %d (%d sats)"
          % (len(result["hybrid_prefix_p2pk"]), a["p2pk_hybrid_valid"][0], a["p2pk_hybrid_valid"][1]))
    for c in checks:
        print("check %s %s" % (c["name"], "ok" if c["ok"] else "FAILED expected %s got %s" % (c["expected"], c["got"])))
    return 0 if result["all_checks_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
