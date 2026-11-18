#!/usr/bin/env python3
"""Integrity check of the exposure index tables (read-only).

For each fixed-width table: size is a multiple of the width, records are strictly
ascending (sorted, no duplicates), first-byte histogram is roughly uniform.
Also checks that cross_format_diff_20 entries appear in pubkey_hash_index or
script_hash_index_20, and that cross_format_diff_32 entries appear in
script_hash_index_32. Finally validates delta_blocks.jsonl structure.
Usage: python3 table-check.py <index_dir>
"""
import json
import os
import sys
import time

INDEX = sys.argv[1]
TABLES = [
    ('pubkey_hash_index.bin', 20),
    ('script_hash_index_20.bin', 20),
    ('script_hash_index_32.bin', 32),
    ('cross_format_diff_20.bin', 20),
    ('cross_format_diff_32.bin', 32),
]
CHUNK_RECORDS = 1_000_000


def log(msg):
    print(time.strftime('%H:%M:%S'), msg, flush=True)


def load_small(name, width):
    data = open(os.path.join(INDEX, name), 'rb').read()
    assert len(data) % width == 0, name
    return [data[i:i + width] for i in range(0, len(data), width)]


def scan(name, width, probes=None, flags=None):
    """Stream the table; verify order; mark probes found (probes must be sorted)."""
    path = os.path.join(INDEX, name)
    size = os.path.getsize(path)
    result = {'table': name, 'width': width, 'bytes': size, 'size_multiple_ok': size % width == 0,
              'records': size // width, 'unsorted': 0, 'duplicates': 0}
    hist = [0] * 256
    prev = None
    pi = 0
    found = 0
    nprobes = len(probes) if probes else 0
    t0 = time.time()
    done = 0
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(width * CHUNK_RECORDS)
            if not chunk:
                break
            for i in range(0, len(chunk), width):
                cur = chunk[i:i + width]
                hist[cur[0]] += 1
                if prev is not None:
                    if cur == prev:
                        result['duplicates'] += 1
                    elif cur < prev:
                        result['unsorted'] += 1
                prev = cur
                if pi < nprobes:
                    while pi < nprobes and probes[pi] < cur:
                        pi += 1
                    if pi < nprobes and probes[pi] == cur:
                        flags[pi] = 1
                        found += 1
                        pi += 1
            done += len(chunk) // width
            if done % (50 * CHUNK_RECORDS) == 0:
                log(f'  {name}: {done:,}/{result["records"]:,} records, unsorted={result["unsorted"]} dups={result["duplicates"]}')
    result['seconds'] = round(time.time() - t0, 1)
    result['first_byte_min'] = min(hist)
    result['first_byte_max'] = max(hist)
    result['first_byte_expected'] = result['records'] / 256
    if probes is not None:
        result['probes_found_here'] = found
    return result


def check_delta():
    path = os.path.join(INDEX, 'delta_blocks.jsonl')
    out = {'file': 'delta_blocks.jsonl', 'exists': os.path.exists(path)}
    if not out['exists']:
        return out
    heights = []
    hashes = set()
    bad_hex = 0
    counts = {'kh20': 0, 'wrapped20': 0, 'sh20': 0, 'wsh32': 0, 'mr32': 0}
    with open(path, 'r') as f:
        for line in f:
            rec = json.loads(line)
            heights.append(rec['height'])
            hashes.add(rec['block_hash'])
            for key, width in (('kh20', 40), ('wrapped20', 40), ('sh20', 40), ('wsh32', 64), ('mr32', 64)):
                for h in rec.get(key, []):
                    counts[key] += 1
                    if len(h) != width:
                        bad_hex += 1
                    else:
                        try:
                            bytes.fromhex(h)
                        except ValueError:
                            bad_hex += 1
    out['blocks'] = len(heights)
    out['height_range'] = [min(heights), max(heights)] if heights else None
    out['heights_contiguous'] = heights == list(range(min(heights), max(heights) + 1)) if heights else None
    out['unique_block_hashes'] = len(hashes) == len(heights)
    out['bad_hex_entries'] = bad_hex
    out['entry_counts'] = counts
    out['bytes'] = os.path.getsize(path)
    return out


def main():
    report = {'index_dir': INDEX, 'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    manifest_path = os.path.join(INDEX, '..', 'snapshots', 'manifest.json')
    try:
        report['manifest_counts'] = json.load(open(manifest_path))['counts']
    except Exception as e:  # noqa: BLE001
        report['manifest_counts'] = f'unavailable: {e}'
    stats_path = os.path.join(INDEX, 'stats.json')
    try:
        report['stats_json'] = json.load(open(stats_path))
    except Exception as e:  # noqa: BLE001
        report['stats_json'] = f'unavailable: {e}'

    log('loading diff tables')
    diff20 = load_small('cross_format_diff_20.bin', 20)
    diff32 = load_small('cross_format_diff_32.bin', 32)
    flags20 = bytearray(len(diff20))
    flags32 = bytearray(len(diff32))

    tables = []
    log('scanning pubkey_hash_index.bin')
    tables.append(scan('pubkey_hash_index.bin', 20, diff20, flags20))
    log('scanning script_hash_index_20.bin')
    tables.append(scan('script_hash_index_20.bin', 20, diff20, flags20))
    log('scanning script_hash_index_32.bin')
    tables.append(scan('script_hash_index_32.bin', 32, diff32, flags32))
    log('scanning cross_format_diff_20.bin')
    tables.append(scan('cross_format_diff_20.bin', 20))
    log('scanning cross_format_diff_32.bin')
    tables.append(scan('cross_format_diff_32.bin', 32))
    report['tables'] = tables
    report['diff20_in_pubkey_or_sh20'] = {'total': len(diff20), 'covered': sum(flags20),
                                          'uncovered': len(diff20) - sum(flags20)}
    report['diff32_in_sh32'] = {'total': len(diff32), 'covered': sum(flags32),
                                'uncovered': len(diff32) - sum(flags32)}
    log('checking delta journal')
    report['delta'] = check_delta()
    report['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    print('REPORT_JSON ' + json.dumps(report, sort_keys=True), flush=True)
    log('DONE')


if __name__ == '__main__':
    main()
