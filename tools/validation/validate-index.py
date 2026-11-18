#!/usr/bin/env python3
"""Accuracy check of the exposure index against chain facts from an Esplora API.

Sections:
  A  recall: every revealed key/script in the inputs of a block below the base
     height must be present in the base tables (binary search on the .bin files).
  B  equivalence sample: funded outputs of an older block; for each address compare
     table exposure with (self spent before base height) OR (in cross-format diff).
  C  negative controls: random hashes must not be found.
  D  early coinbase P2PK keys: derived P2PKH hashes, found or not (informative).
  E  API agreement: a few probes compared with the HTTP API.
Usage: python3 validate-index.py <index_dir> <api_base> <recall_height> <recall_pages> <equiv_height> <equiv_max_addrs>
"""
import hashlib
import json
import os
import random
import struct
import sys
import time
import urllib.request
import urllib.error

INDEX = sys.argv[1]
API = sys.argv[2].rstrip('/')
RECALL_HEIGHT = int(sys.argv[3])
RECALL_PAGES = int(sys.argv[4])
EQUIV_HEIGHT = int(sys.argv[5])
EQUIV_MAX = int(sys.argv[6])
ESPLORA = 'https://mempool.space/api'
BASE_HEIGHT = 975019


def log(msg):
    print(time.strftime('%H:%M:%S'), msg, flush=True)


# ---------- hashing ----------
def sha256(b):
    return hashlib.sha256(b).digest()


def _ripemd160_pure(message):
    # Pure-Python RIPEMD-160 (used when OpenSSL lacks the legacy digest).
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KK = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    R = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
         4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    S = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    SS = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(message)
    ml = len(message) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', ml)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack('<16L', msg[off:off + 64]))
        a, b, c, d, e = h
        aa, bb, cc, dd, ee = h
        for j in range(80):
            t = (a + f(j, b, c, d) + X[R[j]] + K[j // 16]) & 0xffffffff
            t = (rol(t, S[j]) + e) & 0xffffffff
            a, e, d, c, b = e, d, rol(c, 10), b, t
            t = (aa + f(79 - j, bb, cc, dd) + X[RR[j]] + KK[j // 16]) & 0xffffffff
            t = (rol(t, SS[j]) + ee) & 0xffffffff
            aa, ee, dd, cc, bb = ee, dd, rol(cc, 10), bb, t
        t = (h[1] + c + dd) & 0xffffffff
        h[1] = (h[2] + d + ee) & 0xffffffff
        h[2] = (h[3] + e + aa) & 0xffffffff
        h[3] = (h[4] + a + bb) & 0xffffffff
        h[4] = (h[0] + b + cc) & 0xffffffff
        h[0] = t
    return struct.pack('<5L', *h)


def ripemd160(b):
    try:
        return hashlib.new('ripemd160', b).digest()
    except ValueError:
        return _ripemd160_pure(b)


def hash160(b):
    return ripemd160(sha256(b))


def tagged(tag, data):
    th = sha256(tag.encode())
    return sha256(th + th + data)


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def pushes(script):
    """Return data pushes of a script (None data for non-push opcodes is skipped)."""
    out = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op == 0:
            out.append(b'')
        elif op <= 75:
            out.append(script[i:i + op])
            i += op
        elif op == 76:
            size = script[i]
            i += 1
            out.append(script[i:i + size])
            i += size
        elif op == 77:
            size = struct.unpack('<H', script[i:i + 2])[0]
            i += 2
            out.append(script[i:i + size])
            i += size
        elif op == 78:
            size = struct.unpack('<I', script[i:i + 4])[0]
            i += 4
            out.append(script[i:i + size])
            i += size
    return out


# ---------- table lookups ----------
TABLE_FILES = {
    'pk': ('pubkey_hash_index.bin', 20),
    'sh20': ('script_hash_index_20.bin', 20),
    'sh32': ('script_hash_index_32.bin', 32),
    'diff20': ('cross_format_diff_20.bin', 20),
    'diff32': ('cross_format_diff_32.bin', 32),
}
_handles = {}


def in_table(key, target):
    name, width = TABLE_FILES[key]
    if key not in _handles:
        path = os.path.join(INDEX, name)
        _handles[key] = (open(path, 'rb'), os.path.getsize(path) // width, width)
    f, count, width = _handles[key]
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi) // 2
        f.seek(mid * width)
        rec = f.read(width)
        if rec == target:
            return True
        if rec < target:
            lo = mid + 1
        else:
            hi = mid
    return False


# ---------- esplora ----------
def get(url, retries=4):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'btc-exposure-index-validation/1.0'})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read()
            time.sleep(0.25)
            try:
                return json.loads(body)
            except ValueError:
                return body.decode().strip()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(2 * (attempt + 1))
        except Exception:  # noqa: BLE001
            time.sleep(2 * (attempt + 1))
    raise RuntimeError('esplora failed: ' + url)


def block_txs(height, pages):
    bhash = get(f'{ESPLORA}/block-height/{height}')
    txs = []
    for p in range(pages):
        page = get(f'{ESPLORA}/block/{bhash}/txs/{p * 25}')
        if not page:
            break
        txs.extend(page)
        if len(page) < 25:
            break
    return bhash, txs


# ---------- sections ----------
def section_a():
    log(f'A: fetching block {RECALL_HEIGHT} ({RECALL_PAGES} pages)')
    bhash, txs = block_txs(RECALL_HEIGHT, RECALL_PAGES)
    stats = {}
    misses = []

    def tally(kind, ok, detail):
        s = stats.setdefault(kind, {'checked': 0, 'found': 0})
        s['checked'] += 1
        if ok:
            s['found'] += 1
        elif len(misses) < 30:
            misses.append({'kind': kind, **detail})

    for tx in txs:
        for vin in tx.get('vin', []):
            if vin.get('is_coinbase'):
                continue
            prev = vin.get('prevout') or {}
            ptype = prev.get('scriptpubkey_type')
            spk = bytes.fromhex(prev.get('scriptpubkey', ''))
            ss = bytes.fromhex(vin.get('scriptsig') or '')
            wit = [bytes.fromhex(w) for w in (vin.get('witness') or [])]
            if ptype == 'v0_p2wpkh' and len(wit) >= 2 and len(wit[-1]) in (33, 65):
                h = hash160(wit[-1])
                tally('p2wpkh_key_in_pk', in_table('pk', h), {'txid': tx['txid'], 'hash': h.hex()})
                tally('p2wpkh_program_matches_key', spk[2:22] == h, {'txid': tx['txid']})
            elif ptype == 'p2pkh':
                ps = pushes(ss)
                if ps and len(ps[-1]) in (33, 65):
                    h = hash160(ps[-1])
                    tally('p2pkh_key_in_pk', in_table('pk', h), {'txid': tx['txid'], 'hash': h.hex()})
                    tally('p2pkh_hash_matches_key', spk[3:23] == h, {'txid': tx['txid']})
            elif ptype == 'p2sh':
                ps = pushes(ss)
                if ps:
                    redeem = ps[-1]
                    h = hash160(redeem)
                    tally('p2sh_redeem_in_sh20', in_table('sh20', h), {'txid': tx['txid'], 'hash': h.hex()})
                    tally('p2sh_hash_matches_redeem', spk[2:22] == h, {'txid': tx['txid']})
                    if len(redeem) == 22 and redeem[:2] == b'\x00\x14' and len(wit) >= 2:
                        tally('p2sh_p2wpkh_wrapped_in_pk', in_table('pk', h), {'txid': tx['txid'], 'hash': h.hex()})
                        tally('p2sh_p2wpkh_key_in_pk', in_table('pk', hash160(wit[-1])), {'txid': tx['txid']})
                    if len(redeem) == 34 and redeem[:2] == b'\x00\x20' and wit:
                        tally('p2sh_p2wsh_script_in_sh32', in_table('sh32', sha256(wit[-1])), {'txid': tx['txid']})
            elif ptype == 'v0_p2wsh' and wit:
                h = sha256(wit[-1])
                tally('p2wsh_script_in_sh32', in_table('sh32', h), {'txid': tx['txid'], 'hash': h.hex()})
                tally('p2wsh_program_matches_script', spk[2:34] == h, {'txid': tx['txid']})
            elif ptype == 'v1_p2tr' and wit:
                stack = wit[:]
                if len(stack) >= 2 and stack[-1][:1] == b'\x50':
                    stack = stack[:-1]
                if len(stack) >= 2 and len(stack[-1]) >= 33 and (len(stack[-1]) - 33) % 32 == 0:
                    script = stack[-2]
                    control = stack[-1]
                    version = control[0] & 0xfe
                    leaf = tagged('TapLeaf', bytes([version]) + compact_size(len(script)) + script)
                    tally('p2tr_leaf_in_sh32', in_table('sh32', leaf), {'txid': tx['txid'], 'hash': leaf.hex()})
                else:
                    tally('p2tr_keypath_seen', True, {})
    return {'block_hash': bhash, 'txs_checked': len(txs), 'stats': stats, 'misses': misses}


def section_b():
    log(f'B: fetching block {EQUIV_HEIGHT} outputs')
    bhash, txs = block_txs(EQUIV_HEIGHT, 12)
    seen = set()
    sample = []
    per_type_cap = max(10, EQUIV_MAX // 4)
    per_type = {}
    for tx in txs:
        for vout in tx.get('vout', []):
            t = vout.get('scriptpubkey_type')
            addr = vout.get('scriptpubkey_address')
            if t not in ('p2pkh', 'v0_p2wpkh', 'p2sh', 'v0_p2wsh') or not addr or addr in seen:
                continue
            if per_type.get(t, 0) >= per_type_cap:
                continue
            seen.add(addr)
            per_type[t] = per_type.get(t, 0) + 1
            sample.append((t, addr, bytes.fromhex(vout['scriptpubkey'])))
            if len(sample) >= EQUIV_MAX:
                break
        if len(sample) >= EQUIV_MAX:
            break
    log(f'B: {len(sample)} addresses, querying esplora')
    outcomes = {}
    details = []
    for t, addr, spk in sample:
        info = get(f'{ESPLORA}/address/{addr}')
        cs = info['chain_stats']
        spent = cs['spent_txo_count'] > 0
        if t == 'p2pkh':
            h = spk[3:23]
            exposed = in_table('pk', h)
            diff = in_table('diff20', h)
        elif t == 'v0_p2wpkh':
            h = spk[2:22]
            exposed = in_table('pk', h)
            diff = in_table('diff20', h)
        elif t == 'p2sh':
            h = spk[2:22]
            exposed = in_table('pk', h) or in_table('sh20', h)
            diff = in_table('diff20', h)
        else:
            h = spk[2:34]
            exposed = in_table('sh32', h)
            diff = in_table('diff32', h)
        first_spend_height = None
        if spent:
            txs_addr = get(f'{ESPLORA}/address/{addr}/txs') or []
            heights = []
            for tx in txs_addr:
                if any((v.get('prevout') or {}).get('scriptpubkey_address') == addr for v in tx.get('vin', [])):
                    bh = (tx.get('status') or {}).get('block_height')
                    if bh:
                        heights.append(bh)
            first_spend_height = min(heights) if heights else None
        spent_before_base = spent and first_spend_height is not None and first_spend_height <= BASE_HEIGHT
        if exposed and spent_before_base:
            cat = 'exposed_self_spent'
        elif exposed and diff:
            cat = 'exposed_via_diff'
        elif exposed and spent and not spent_before_base:
            cat = 'exposed_spent_after_base_only'
        elif exposed:
            cat = 'exposed_unexplained'
        elif spent_before_base:
            cat = 'MISMATCH_spent_before_base_not_exposed'
        elif spent:
            cat = 'not_exposed_spent_after_base'
        elif diff:
            cat = 'MISMATCH_diff_but_not_exposed'
        else:
            cat = 'not_exposed_unspent'
        outcomes[cat] = outcomes.get(cat, 0) + 1
        details.append({'type': t, 'address': addr, 'spent_txo_count': cs['spent_txo_count'],
                        'funded_txo_count': cs['funded_txo_count'], 'first_spend_height': first_spend_height,
                        'exposed': exposed, 'in_diff': diff, 'category': cat})
    return {'block_hash': bhash, 'sampled': len(sample), 'outcomes': outcomes,
            'flagged': [d for d in details if d['category'].startswith('MISMATCH') or d['category'] == 'exposed_unexplained']}


def section_c():
    rng = random.Random(362)
    hits20 = sum(1 for _ in range(200) if in_table('pk', rng.randbytes(20)) or in_table('sh20', rng.randbytes(20)))
    hits32 = sum(1 for _ in range(100) if in_table('sh32', rng.randbytes(32)))
    return {'random20_probes': 400, 'random20_hits': hits20, 'random32_probes': 100, 'random32_hits': hits32}


def section_d():
    log('D: early coinbase P2PK keys')
    rows = []
    for height in range(1, 13):
        bhash = get(f'{ESPLORA}/block-height/{height}')
        txs = get(f'{ESPLORA}/block/{bhash}/txs/0')
        spk = bytes.fromhex(txs[0]['vout'][0]['scriptpubkey'])
        ps = pushes(spk)
        if not ps or len(ps[0]) not in (33, 65):
            continue
        key = ps[0]
        h = hash160(key)
        rows.append({'height': height, 'pubkey_prefix': key[:4].hex(), 'p2pkh_hash': h.hex(),
                     'in_pk': in_table('pk', h), 'in_diff20': in_table('diff20', h)})
    return rows


def section_e():
    log('E: API agreement')
    probes = ['62e907b15cbf27d5425399ebf6f0fb50ebb88f18', '751e76e8199196d454941c45d1b3a323f1433bd6',
              'bcfeb728b584253d5f3f70bcb780e9ef218a68f4', 'a0b0d60e5991578ed37cbda2b17d8b2ce23ab295',
              '53d13ba89f33a808a0abd4f2b3f4f0dbb85629b8',
              '2943522e2c3c220b66e94be4642b63c331b7c9a54353ff941244fdcc91cbffdf']
    rows = []
    for hx in probes:
        b = bytes.fromhex(hx)
        api = get(f'{API}/lookup/hash/{hx}')
        if len(b) == 20:
            local = {'pk': in_table('pk', b), 'sh20': in_table('sh20', b), 'diff': in_table('diff20', b)}
            agree = (api['in_pubkey_hash_index'] == local['pk'] and api['in_script_hash_20_index'] == local['sh20']
                     and api['in_cross_format_diff'] == local['diff'])
        else:
            local = {'sh32': in_table('sh32', b), 'diff': in_table('diff32', b)}
            agree = api['in_script_hash_32_index'] == local['sh32'] and api['in_cross_format_diff'] == local['diff']
        rows.append({'hash': hx[:16], 'local': local, 'api_agrees_base': agree})
    return rows


def main():
    report = {'index_dir': INDEX, 'base_height': BASE_HEIGHT,
              'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    report['A_recall'] = section_a()
    report['B_equivalence'] = section_b()
    report['C_negative'] = section_c()
    report['D_early_p2pk'] = section_d()
    report['E_api'] = section_e()
    report['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    print('REPORT_JSON ' + json.dumps(report, sort_keys=True), flush=True)
    log('DONE')


if __name__ == '__main__':
    main()
