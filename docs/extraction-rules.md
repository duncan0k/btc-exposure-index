# Extraction rules and table semantics (snapshot 975019)

This document states how `btc-indexer --scan-blocks` (`btc-indexer/src/main.rs`) builds the exposure index from raw block files, and what each table and statistic of the snapshot at height 975,019 means. Appendix A maps each claim to the code or to the record it rests on.

## 1. Scope and snapshot

The index answers one question about an output commitment: has the public key or the script behind this 20-byte or 32-byte program already appeared on chain? Programs come from P2PKH, P2WPKH, P2SH and P2WSH outputs; P2TR outputs are a key source only. The index consists of five sorted hash tables, a height file and a statistics file.

- Snapshot: height 975,019. The published tables were built from the `blk*.dat` files of a Bitcoin Core mainnet node that completed its initial sync on 2026-11-07/08 and ran with `-blocksxor=0`. The scanner cannot read obfuscated files and stops if the blocks directory holds an `xor.dat` with a non-zero byte. The scanner in this repository reproduced the six checksummed files of Section 5.5 byte for byte on 2026-11-16 (Section 9).
- Block set: the scan takes the blocks named in a best-chain list, one line per height from 0 to 975,019 with the block hash, which `--export-chain-list` reads from a node (Section 9). Every listed block must be found exactly once in the block files and passes the checks of Section 2.1 before anything is taken from it. Records whose header hash is not on the list, such as stale blocks or blocks above the snapshot height, are skipped and counted. The list is only as good as the node it came from: the export requires the node to be out of initial block download and at least 100 blocks past the last listed height, and checks at the end that the last hash has not changed. The chain-list scan read 975,020 blocks and 1,476,123,483 transactions and skipped 1,164 records. The 2026-11-08 build, which checked no block hash, counted 975,020 blocks and 1,476,123,483 transactions; that total equals the `nchaintx` that Bitcoin Core reported for block 975,019 when it wrote the UTXO snapshot of Section 10 (the method page gives it; this repository does not record it).
- Published and revealed: a public key is published when its x-coordinate appears in a scanned block in one of the positions listed in Section 2.2. A script is revealed when it appears in one of the roles defined in Section 2.3.
- Funded: a program is funded when at least one output in a scanned block carries the matching standard output script (Section 4). This means ever funded up to the snapshot. Output values, later spends and the UTXO set are ignored.

## 2. Extraction rules

### 2.1 Reading blocks

`scan_blocks_dir` reads every `blk*.dat` file in the blocks directory, six files at a time, each entirely into memory. It searches byte by byte for the mainnet magic `f9 be b4 d9` and reads a 4-byte little-endian length. A record shorter than 80 bytes or running past the end of the file ends that file; otherwise the search resumes at the end of the record. The scanner hashes the record's 80-byte header and looks the hash up in the chain list: a record that is not on the list is skipped and counted, and a listed block found a second time stops the scan. `extract_block` then checks the listed block before anything is taken from it. Its header must hash to the listed hash, and its previous-block field must hold the listed hash of the height below, zero for height 0. Every transaction must parse, and the last one must end exactly at the end of the record. The Merkle root of the transaction ids must match, and where a level of the tree pairs two hashes, they must differ (an odd last hash is paired with itself, as usual). Where the block carries witness data, or from the segwit activation height 481,824 on has a coinbase output of at least 38 bytes that starts with `6a 24 aa 21 a9 ed`, the last such output must hold the double SHA256 of the witness Merkle root and of the coinbase's single 32-byte witness item. Any failed check stops the scan, and so does a listed height that is not found in any file. Proof of work, scripts, signatures and amounts are not checked. The output spent by an input is never looked up: spend types are inferred from the shape of the scriptSig and the witness.

A data push is an opcode from OP_0, an empty push, to OP_PUSHDATA4 with its data; OP_1 to OP_16 and other opcodes are not data pushes. A push running past the end of its script ends parsing, and earlier pushes are kept.

### 2.2 Public keys

A byte string is a key candidate if it is one of:

- 33 bytes beginning with `02` or `03`; bytes 1 to 32 are x.
- 65 bytes beginning with `04`, `06` or `07`; bytes 1 to 32 are x and bytes 33 to 64 are y. For all three prefixes (x, y) must lie on secp256k1, and for `06` and `07` the prefix must also match the parity of y (`06` even, `07` odd).
- 32 bytes (x-only), in positions 3, 6 and 7 only.

65-byte candidates, pushes inside a tapscript and the keys of positions 6 and 7 are checked against the curve when extracted. P2TR output keys and other 33-byte candidates are recorded unchecked; their x is checked only when hashes are derived (Section 3).

Candidates are taken from seven positions. Except for the internal key of position 6, each is a whole data push or witness element, never part of one:

1. Every data push in every output script, including OP_RETURN and non-standard scripts.
2. The key of every P2PK output and each key of every bare multisig output.
3. The witness program of every P2TR output (the tweaked output key), without a curve check.
4. Every data push in every scriptSig, coinbase included, and every witness stack element. The push or element must be a key candidate as a whole.
5. Every data push inside a revealed script (Section 2.3). Inside a tapscript of any leaf version, only 33-byte and 65-byte pushes that encode valid points are taken.
6. The internal key of a Taproot script-path spend (control block bytes 1 to 32), if valid.
7. In a tapscript with leaf version `c0`, each 32-byte push immediately followed by OP_CHECKSIG, OP_CHECKSIGVERIFY or OP_CHECKSIGADD, if valid.

Keys are deduplicated by x-coordinate, so a point and its negation are one key, and Section 3 derives the hashes of both. No key is recovered from a signature.

Each x carries a provenance mask, the bitwise OR of the flag values of its occurrences. Flag value 1 is always set and carries no information.

| Flag value | Set by positions | Meaning |
| --- | --- | --- |
| 2 | 1, 2, 3, 5, 6, 7 | seen somewhere other than as a bare scriptSig push or witness element |
| 4 | 2, P2PK only | key of a P2PK output |
| 8 | 3 | P2TR output key |
| 16 | 1 | push in an output script, so also set for P2PK and bare multisig keys |
| 32 | 2, 4, 5, 6, 7 | "key position": any position except 1 and 3 |

### 2.3 Revealed scripts

Four shape rules assign roles to byte strings of non-coinbase inputs. Here r is the last data push of the scriptSig, not necessarily its last opcode.

- Redeem script: r, when r is non-empty and the scriptSig does not have the P2PKH spend shape (exactly two data pushes, r a key candidate).
- Nested witness script: the last witness element, when r is `00 20` followed by 32 bytes (P2SH-P2WSH).
- Tapscript: the element before a control block, when the scriptSig is empty and the full witness does not have the P2WPKH spend shape (exactly two elements, the last a key candidate). For this rule only, a final element beginning with `50` is then dropped as an annex if at least two elements are present. A control block is a last element of 33 + 32k bytes (k at most 128) whose bytes 1 to 32 are a valid x-only key, with at least two elements remaining.
- Native witness script: the last element of the full witness, annex included, when the scriptSig is empty, the witness does not have the P2WPKH spend shape, no control block is found and the element is non-empty.

TapLeaf and TapBranch hashes are the BIP 341 tagged hashes with tags "TapLeaf" and "TapBranch". The TapLeaf hash covers the leaf version, the compact-size script length and the script; the leaf version is the first control-block byte with its low bit cleared. Each 32-byte path element after byte 32 of the control block adds a TapBranch hash over the previous hash and that element, sorted lexicographically. The leaf hash and every branch hash, up to and including the Merkle root, are recorded.

These rules match standard P2SH, P2SH-P2WSH, P2TR script-path and P2WSH spends. Without the spent output they also fire on non-scripts, such as the signature of a P2PK or Taproot key-path spend. Such strings reach a table only if one of their hashes equals a funded program (Section 8).

### 2.4 Not indexed

- Taproot script trees. TapLeaf and TapBranch hashes enter a table only if they equal a funded P2WSH program. P2TR outputs form no funded set; their output keys are published keys.
- Witness version 2 (P2MR, BIP 360) and other witness versions or program lengths not in Section 4. P2MR recognition is disabled, so these are neither funded programs nor key sources beyond position 1.
- Amounts, spending status, heights and transaction ids. The tables record membership only.

## 3. Derivation of key hashes

For each distinct x the scanner derives 12 hashes (`key_hashes_from_x`) if x is the x-coordinate of a curve point, that is, if `02 x` parses as a public key. Other x values yield no hashes. Let y_e be the even and y_o = p - y_e the odd square root of x^3 + 7 modulo the field prime p, each as 32 bytes big-endian.

| i | Encoding E_i(x) | Bytes |
| --- | --- | --- |
| 0 | `02 x` | 33 |
| 1 | `03 x` | 33 |
| 2 | `04 x y_e` | 65 |
| 3 | `04 x y_o` | 65 |
| 4 | `06 x y_e` | 65 |
| 5 | `07 x y_o` | 65 |

```
HASH160(m) = RIPEMD160(SHA256(m))
K_i(x)     = HASH160(E_i(x))               for i = 0..5
W_i(x)     = HASH160(00 14 K_i(x))         for i = 0..5
K(x)       = {K_0(x), ..., K_5(x)}
W(x)       = {W_0(x), ..., W_5(x)}

Forms of a revealed script s:
  P2SH        HASH160(s)
  P2SH-P2WSH  HASH160(00 20 SHA256(s))
  P2WSH       SHA256(s)
```

K_i(x) is the P2PKH or P2WPKH program for encoding i. W_i(x) is the P2SH program whose redeem script is the 22-byte P2WPKH script for encoding i (P2SH-P2WPKH).

## 4. Funded sets

`recognize` classifies output scripts by exact byte pattern. In the table h is the program.

| Type | Output script | Funded set |
| --- | --- | --- |
| P2PKH | `76 a9 14 h 88 ac`, 25 bytes | F_PKH |
| P2WPKH | `00 14 h`, 22 bytes | F_WPKH |
| P2SH | `a9 14 h 87`, 23 bytes | F_SH |
| P2WSH | `00 20 h`, 34 bytes | F_WSH |

Every output of every scanned transaction counts, coinbase and zero-value outputs included, and nothing is ever removed. A 20-byte value can be in several sets; the P2PKH and P2WPKH programs of one encoding of a key are identical. P2PK (a 33-byte or 65-byte key push, then OP_CHECKSIG), bare multisig (OP_m, n key pushes, OP_n, OP_CHECKMULTISIG, with m <= n <= 16) and P2TR (`51 20` followed by 32 bytes) are key sources only. P2PK and bare multisig are matched by structure alone: any push opcode is accepted, only the key length of 33 or 65 bytes is checked, m may be OP_0, and there is no curve check. A key is recorded only if it is a key candidate (Section 2.2). The `census` object of `stats.json` (Section 7) counts P2PK keys too, in `keys_funded_p2pk`.

Internally each value carries a mask of the flag values below. 20-byte values without flag value 1, 2 or 4 are dropped before any table is written.

| Width | Flag value | Meaning |
| --- | --- | --- |
| 20 | 1 | funded P2PKH |
| 20 | 2 | funded P2WPKH |
| 20 | 4 | funded P2SH |
| 20 | 8 | P2SH or P2SH-P2WSH form of a revealed script |
| 20 | 16 | cross-format (Section 6) |
| 32 | 1 | funded P2WSH |
| 32 | 2 | SHA256 of a revealed script, or a TapLeaf or TapBranch hash |
| 32 | 4 | cross-format (Section 6) |

## 5. Tables

The tables are header-less arrays of fixed-width records, sorted ascending by unsigned byte order, without duplicates. Each table is written into one file, shard by shard in order of the leading bits, and each shard is sorted and deduplicated. Lookups are binary searches over the file (`binary_search_file`). The HTTP server is outside the scope of this document; it uses the same search and then checks data added after the snapshot.

Notation: `&` is intersection, `|` is union, and X is the set of published x-coordinates of curve points.

### 5.1 pubkey_hash_index.bin

Each derived key hash funded as the matching type: K_i(x) funded as P2PKH or P2WPKH, and W_i(x) funded as P2SH.

```
M(x)              = (K(x) & (F_PKH | F_WPKH)) | (W(x) & F_SH)
pubkey_hash_index = union of M(x) over all x in X
```

A K_i(x) funded only as P2SH, or a W_i(x) funded only as P2PKH or P2WPKH, is excluded. Entries do not record which type or encoding matched.

### 5.2 script_hash_index_20.bin

Each funded P2SH program that is the P2SH or P2SH-P2WSH form of a script revealed in any role:

```
R20                  = { HASH160(s), HASH160(00 20 SHA256(s)) : s revealed in any role }
script_hash_index_20 = R20 & F_SH
```

This covers spent P2SH and P2SH-P2WSH outputs and spent P2SH-P2WPKH outputs, whose redeem script `00 14 K_i(x)` is revealed. A spent P2SH-P2WPKH program is also in `pubkey_hash_index.bin`, because the witness reveals the key and W_i(x) is funded as P2SH. It also covers P2SH programs whose script was revealed only in another role, such as a native witness script or a tapscript.

### 5.3 script_hash_index_32.bin

Each funded P2WSH program that is the SHA256 of a script revealed in any role, or a TapLeaf or TapBranch hash:

```
R32                  = { SHA256(s) : s revealed in any role } | { TapLeaf and TapBranch hashes }
script_hash_index_32 = R32 & F_WSH
```

Only native P2WSH programs qualify, so the inner SHA256 of a P2SH-P2WSH spend is included only if the same program was also funded natively. The three hash forms of a tapscript enter the tables when funded, like those of any revealed script, and all three are cross forms (Section 6). Its TapLeaf and TapBranch hashes match a P2WSH program only through a SHA256 collision or a witness script equal to the tagged message itself; how many entries they add was not measured.

### 5.4 Other files

The diff tables are defined in Section 6. `last_indexed_height` holds `975019` followed by a line feed. `stats.json` holds the entry counts, the census (Section 7) and two keys that the earlier scanner did not write, `scan_height` and `scan_block_hash`: the height and the hash of the last block on the chain list. The scanner writes these files, and also five state files under `state/` and `checkpoint.json`. The state files hold the sets that the scan collected and from which the tables are derived, each sorted by value with no value twice:

- `state/x.bin`: 33-byte records, an x value and its provenance flag values (Section 2.2), one record for each distinct x;
- `state/f20.bin`: 21-byte records, a 20-byte value and its funded flag values 1, 2 and 4 (Section 4);
- `state/f32.bin`: 32-byte records, the 32-byte values with funded flag value 1;
- `state/r20.bin` and `state/r32.bin`: 21-byte and 33-byte records, a 20-byte or 32-byte value and its revealed and cross flag values (8 and 16 for 20-byte values, 2 and 4 for 32-byte values).

`checkpoint.json` is written last. Before it is written, every other output file has been written, synced and renamed, and on Unix its directory has been synced. It records, for each of the other twelve files, the size, the number of records where the file has fixed-width records, and the SHA256; and `format` ("btc-indexer-checkpoint/1"), `height`, `block_hash`, `rules_version` ("btc-indexer/shape-rules-1") and `state_digest`. `state_digest` is the SHA256 of the length of the rules version as one byte, the rules version, the height as 8 bytes big-endian, the block hash in display order, and the SHA256 values of `state/x.bin`, `state/f20.bin`, `state/f32.bin`, `state/r20.bin`, `state/r32.bin`, `pubkey_hash_index.bin`, `script_hash_index_20.bin` and `script_hash_index_32.bin` in that order. The files that a `checkpoint.json` lists had therefore all been written before it was.

Whether a run succeeded is given by the scanner's exit status: 0 means success; on any error the scanner prints `ERROR:` and the reason to standard error and exits with status 1. When publishing `checkpoint.json` fails after its rename, the scanner removes it before exiting, but that removal is best effort: a crash, a kill or a filesystem error can leave it in place. A reader must check the listed hashes before using the files and must not take their presence as proof of a successful run.

### 5.5 Sizes and checksums

| File | Width (bytes) | Entries | Size (bytes) |
| --- | --- | --- | --- |
| `pubkey_hash_index.bin` | 20 | 1,279,711,199 | 25,594,223,980 |
| `script_hash_index_20.bin` | 20 | 384,687,335 | 7,693,746,700 |
| `script_hash_index_32.bin` | 32 | 39,243,253 | 1,255,784,096 |
| `cross_format_diff_20.bin` | 20 | 1,421,774 | 28,435,480 |
| `cross_format_diff_32.bin` | 32 | 185,269 | 5,928,608 |

```
36821d50c7b9d1511b9aabd462cfbbdbb4369894fc62a77fb18ed742ec7df5e6  pubkey_hash_index.bin
f8aaa8c3c7d3b583753ce7b703b2aa1aea78e3b8d7ea3cc790e95777e2f6e782  script_hash_index_20.bin
6ca074f9fa4f5b1cf4b9e0a7c02b0d8be102734cc6e27f60f8c25c91f48bf54b  script_hash_index_32.bin
6efa04890837b4fc62987ee0dba5c344428a96f1674d7999e9de08cb48dd0b84  cross_format_diff_20.bin
bec9e7cd57e58d344aa37efa2972f5152ade8eb083e7d320bd6cd75ddb9ed9fe  cross_format_diff_32.bin
4f361ccf790379771ed8bf8d1be6b9e36184e0aebe8ef0cbc8a29a3a98a0b8b9  last_indexed_height
```

`stats.json` is omitted from the checksum list. It holds no timestamp, and it differs between the first build and the 2026-11-08 rebuild only because the census object was added.

## 6. Cross-format diff tables

The diff tables are small subsets of the full tables. They target programs whose exposure may come from somewhere other than their own spends: a key reused across types or encodings, a script reused across wrappings, or a key that appears in an output, inside a script or as a Taproot internal key.

Cross-format flag. Each occurrence of a revealed script s has at most one own form for its role; tapscripts have none. Every other form is a cross form:

| Role | HASH160(s) | HASH160(00 20 SHA256(s)) | SHA256(s) |
| --- | --- | --- | --- |
| Redeem script | own | cross | cross |
| Nested witness script | cross | own | cross |
| Native witness script | cross | cross | own |
| Tapscript | cross | cross | cross |

TapLeaf and TapBranch hashes are also cross. Flags are combined over all occurrences, so a value is flagged if it is a cross form of any occurrence. C20 and C32 are the flagged 20-byte and 32-byte values.

Key spread. For x in X, B(x) is a 13-bit mask: bit index i (i = 0..5) is set if K_i(x) is in F_PKH, bit index 6 + i if K_i(x) is in F_WPKH, and bit index 12 if any W_i(x) is in F_SH. |B(x)| is the number of set bits. P2PK is not part of B(x). q(x) holds if provenance flag value 2 is set.

```
D20 = (C20 & F_SH)  |  union of M(x) over all x in X with |B(x)| >= 2 or q(x)
D32 = C32 & F_WSH
```

So `cross_format_diff_20.bin` holds every funded P2SH program that is a cross form of a revealed script. It also holds every `pubkey_hash_index.bin` entry of a key that is funded under two or more type-and-encoding combinations, or that was seen in an output, inside a revealed script or as a Taproot internal key. All P2SH-P2WPKH encodings count as one combination, and outputs include P2PK and P2TR output keys. `cross_format_diff_32.bin` holds every funded P2WSH program whose script was revealed as a P2SH redeem script, a nested witness script or a tapscript, and every funded P2WSH program equal to a TapLeaf or TapBranch hash.

The cross flag (flag value 16 for 20-byte values, 4 for 32-byte values) is only set together with the revealed flag (8 and 2 respectively, Section 4), so D20 is contained in the union of `pubkey_hash_index.bin` and `script_hash_index_20.bin`, and D32 in `script_hash_index_32.bin`. The definition is a heuristic and implements no condition of the draft discussed in Section 11.1. It includes every funded hash of a qualifying key, even one whose own spend revealed the key. It omits the funded hashes of a key funded under a single type-and-encoding combination and seen only as a bare scriptSig push or witness element, even in a spend of another program.

## 7. Census counters

The `census` object in `stats.json` counts distinct x values (unit x) or distinct programs (unit p), as defined in `census_row` and `Census`. Some x values are not x-coordinates of curve points (first note below), so the counters that can include them count x values, not public keys. A key is funded under a type if it is funded under that type in at least one encoding: P2PKH if some K_i(x) is in F_PKH, P2WPKH if some K_i(x) is in F_WPKH, P2SH-P2WPKH if some W_i(x) is in F_SH, and P2PK if provenance flag value 4 is set. These four are the script types of the multi-type counters.

| Counter | Unit | Definition | Value |
| --- | --- | --- | --- |
| `published_x_total` | x | distinct x recorded from any position | 1,776,932,637 |
| `published_x_in_key_position` | x | provenance flag value 32 set | 1,693,875,718 |
| `published_x_only_as_p2tr_output_key` | x | flag value 8 set; flag values 4, 16 and 32 clear | 83,039,682 |
| `published_x_only_in_unrecognized_output_push` | x | flag value 16 set; flag values 4, 8 and 32 clear, so seen only in pushes of output scripts that are neither P2PK nor bare multisig | 15,527 |
| `keys_funded_p2pk` | x | funded as P2PK | 217,086 |
| `keys_funded_p2pkh` | x | funded as P2PKH | 591,795,195 |
| `keys_funded_p2wpkh` | x | funded as P2WPKH | 417,786,147 |
| `keys_funded_p2sh_p2wpkh` | x | funded as P2SH-P2WPKH | 270,314,282 |
| `keys_funded_p2pk_and_p2pkh` | x | funded under both types, possibly also others | 40,385 |
| `keys_funded_p2pk_and_p2wpkh` | x | funded under both types, possibly also others | 17 |
| `keys_funded_p2pk_and_p2sh_p2wpkh` | x | funded under both types, possibly also others | 16 |
| `keys_funded_p2pkh_and_p2wpkh` | x | funded under both types, possibly also others | 189,857 |
| `keys_funded_p2pkh_and_p2sh_p2wpkh` | x | funded under both types, possibly also others | 29,167 |
| `keys_funded_p2wpkh_and_p2sh_p2wpkh` | x | funded under both types, possibly also others | 12,806 |
| `keys_funded_in_2plus_script_types` | x | funded under at least two of the four types | 264,361 |
| `keys_funded_in_3plus_script_types` | x | funded under at least three of the four types | 3,942 |
| `keys_funded_in_any_form` | x | funded under at least one of the four types | 1,279,844,406 |
| `keys_comp_and_uncomp_any_type` | x | a compressed encoding (i = 0 or 1) and an uncompressed encoding (i = 2 or 3) both funded, each as P2PKH or P2WPKH; despite its name, this counter looks at P2PKH and P2WPKH funding only | 5,011 |
| `keys_comp_and_uncomp_p2pkh_only` | x | the same, counting P2PKH only | 4,570 |
| `keys_hybrid_encoding_funded` | x | a hybrid encoding (i = 4 or 5) funded as P2PKH or P2WPKH | 1 |
| `funded_hash20_total` | p | distinct values in at least one of F_PKH, F_WPKH and F_SH | 1,436,010,128 |
| `funded_hash20_p2pkh` | p | distinct values in F_PKH | 608,915,048 |
| `funded_hash20_p2wpkh` | p | distinct values in F_WPKH | 437,595,697 |
| `funded_hash20_p2sh` | p | distinct values in F_SH | 389,693,448 |
| `funded_hash32_p2wsh` | p | distinct values in F_WSH | 40,521,584 |
| `funded_hash32_p2wsh_note` | - | null here because the 2026-11-08 build did not resume: the scanner of that build set it only when a resumed run skipped the 32-byte reduction and left the count above null. This scanner does not resume and always writes null | null |

- The values are those of `results/975019/btc-indexer-stats.json`, the `stats.json` of the 2026-11-08 build. The chain-list scan's `stats.json`, `results/975019/chain-list-scan-stats.json`, has the same values, the census object included, and adds `scan_height` and `scan_block_hash`.
- Values of x that fail the curve check are counted too (Sections 2.2 and 8). They can inflate `published_x_total`, the three provenance counters, `keys_funded_p2pk` and `keys_funded_in_any_form`, and no other counter.
- The three provenance counters are disjoint. The x values counted by none of them, 1,710 by subtraction, were seen as a P2TR output key and in an unrecognized output push, and never in a key position.
- The six pairwise counts sum to 272,248 = 264,361 + 2 x 3,942 + 3 x 1, since a key funded under exactly t types counts in t(t - 1)/2 of them. So exactly one key is funded under all four types and 3,941 under exactly three.
- The per-type counts exceed `funded_hash20_total` by 194,065: a program in exactly two of the three sets adds 1 to this excess, and a program in all three adds 2. The excess is therefore not the number of cross-type programs.
- `keys_funded_in_any_form` counts keys, while the size of `pubkey_hash_index.bin` counts hashes. The two are not comparable.
- The top-level fields of `stats.json` repeat other numbers. `unique_published_x_coords` equals `published_x_total`, the five `*_entries` fields (`exposed_h160_entries`, `revealed_p2sh_20_entries`, `revealed_p2wsh_32_entries`, `cross_format_diff_20_entries`, `cross_format_diff_32_entries`) are the entry counts of Section 5.5 in that order, and `cross_type_reuse` repeats `keys_funded_p2pk_and_p2pkh`, `keys_funded_p2pkh_and_p2wpkh` and `keys_comp_and_uncomp_any_type` as `keys_in_both_p2pk_and_p2pkh`, `keys_in_both_p2pkh_and_p2wpkh` and `keys_in_both_compressed_and_uncompressed`; the last one, like its source, counts P2PKH and P2WPKH funding only. `scan_height` and `scan_block_hash` (Section 5.4) are new with this scanner; the `stats.json` of the 2026-11-08 build and the archive's `stats.json` do not have them.

## 8. Known limitations and non-goals

- Ever funded, not currently funded. An entry means the program was funded at least once and its key or script was published at least once at or before the snapshot height, in either order. No UTXO filter is applied.
- Block set. Only the blocks on the chain list are used (Sections 1 and 2.1), and the list is trusted as exported: the scan checks each listed block against it, not against proof of work or a node of its own. Bytes outside block records are skipped without being counted, and a record that is shorter than 80 bytes or runs past the end of its file ends that file; a listed block lost that way stops the scan as missing. The completeness checks are that every listed block is found exactly once and passes its checks. The transaction total of Section 9 is printed but not compared with anything.
- Spend types inferred from shape. Key-shaped pushes inside non-script data taken as a script are counted as published keys; random key-shaped bytes reach a table only through a hash collision with a funded program. A native segwit spend whose last elements happen to look like a tapscript and a control block is treated as a Taproot spend: the second-to-last element is processed as a tapscript, and the last element is not recorded as a witness script. The control-block test ignores the first byte, so three or more elements ending in a 33-byte or 65-byte public key also match.
- Counting before curve validation. P2TR output keys and 33-byte candidates outside tapscripts are counted before the curve check. Invalid x values therefore inflate `published_x_total` and the three provenance counters, and a P2PK output with an invalid 33-byte key counts in `keys_funded_p2pk` and `keys_funded_in_any_form`. They produce no table entries. Their number has not been measured.
- Mixed evidence. A 20-byte entry does not record its output type or encoding. Spent P2SH-P2WPKH programs are in both 20-byte tables. A point and its negation are one key by design.
- Data added after the snapshot. The daily path (`--apply-block-hex` per block, `--compact` once a day) follows different rules:
  - No funded filter: all 12 derived hashes of every valid key in a new block enter `pubkey_hash_index.bin`, and all script hashes enter the script tables.
  - The spent output is never looked up and there are no shape exclusions. The last scriptSig push of every non-coinbase input is a script; when that push is a P2WSH program (`00 20` and 32 bytes), the last witness element is a script as well, as in a P2SH-P2WSH spend. For an empty scriptSig, the last witness element is a script. Taproot inputs are not exempt, so a control block or annex can be taken as a script. Key and signature hashes therefore enter the script tables: for example the key that ends a P2PKH or P2WPKH spend, and the signature of a Taproot key-path spend.
  - TapLeaf and TapBranch hashes enter `script_hash_index_32.bin`; the hashes of the tapscripts themselves do not.
  - The diff tables are never updated.
  - Each block is checked before anything is recorded: its header must hash to the block hash given on the command line, every transaction must parse with no bytes left over, the Merkle root must match, and the witness commitment must match where one is required. A block that fails is rejected whole. Proof of work and the link to the previous block are not checked.
  - Reorganizations are not detected. Nothing checks that an applied block is still on the best chain, and the daily updater, which is not in this repository, only moves forward from the last height it applied. Applying a height again drops the records of that height and above in `delta_blocks.jsonl` that are not yet merged; entries merged into the tables by `--compact` are never removed. The entries of a block that a reorganization replaces therefore stay.
  - Funding after the snapshot is not tracked. Hashes are added only for keys and scripts that appear in new blocks, and new outputs are not checked against keys and scripts published earlier. An output created after the snapshot that pays a key or script published by the snapshot height, and not published again, is therefore not found, unless its program had already been funded as the matching type (Section 5) by that height, which puts it in the snapshot tables. The census of Section 10 is not affected, since every output unspent at height 975019 had been funded by then.

  After the first `--compact` the three main tables are supersets of the snapshot sets with mixed meaning, and their checksums no longer apply. This document defines only the snapshot.
- Tests. The 128 `--self-test` vectors exercise the prevout-based `extract_evidence` and `classify`, not the block scanner. Section 11.5 lists where their expected results differ from the draft text as it stands now. `cargo test` runs the unit tests: the 12 `census_tests`, and the `integrity_tests`, which include tests of the scanner in `integrity_tests::chain_scan` (hand-specified extraction rows, the block checks, the chain list, the state files, `checkpoint.json` and failure cases). The scripts in `btc-indexer/tests/old-vs-new/` compare the scanner with the scanner of the first commit of this repository (tag `original-scanner`) on a generated fixture chain and on a regtest chain. The top-level `README.md` says what each script does and where the old source and the fixture come from; each script prints a usage line with its arguments when run without them. The snapshot itself is checked by reproducing the checksums.

## 9. Reproduction

1. Block files and chain list. Use a non-pruned Bitcoin Core mainnet node whose blocks directory was created with `-blocksxor=0`; recent versions obfuscate block files by default, and the scanner stops if the blocks directory holds an `xor.dat` with a non-zero byte. The node must be out of initial block download, with as many headers as blocks, and at least 100 blocks past 975,019. With the scanner built in step 2, export the best-chain list through the node's RPC cookie:

   ```
   ./target/release/btc-indexer --export-chain-list http://127.0.0.1:8332/ <datadir>/.cookie 975019 chain-975019.txt
   ```

   The URL must have the form `http://<host>:<port>/`. The command reads the hashes with batched `getblockhash` calls, checks at the end that the hash at 975,019 is unchanged and still at least 100 blocks deep, does not overwrite an existing file, and prints `Exported chain list: tip=<tip>, H=975019, hash=<hash>`. The file has one line `<height> <hash>` for each height from 0 to 975,019, the hash in display order, and ends with a line feed; its last line must read `975019 0000000000000000000158c9898f947463d71d98c97f1dad1639e25114a1dae6`. The block files may also hold stale blocks or blocks above 975,019, which the scan skips. Each block must lie within one file.

2. Build and test:

   ```
   cd btc-indexer
   cargo build --release
   cargo test
   ./target/release/btc-indexer --self-test test_vectors_070.json
   ```

   `cargo test` runs the unit tests, the 12 `census_tests` and the scanner's tests among them, and all must pass. Expected self-test output: `PASS: All 128 test vectors (14 script, 12 history, 71 classification, 31 extraction) verified 100%!`

3. Scan into a directory that is absent or empty. There is no resume: a run that stops starts again from the beginning in a new directory.

   ```
   ./target/release/btc-indexer --scan-blocks <blocks_dir> <out_dir> chain-975019.txt
   ```

   The scanner writes the five tables, `last_indexed_height`, `stats.json`, the five state files and, last, `checkpoint.json` (Section 5.4), and exits with status 0 only when the scan is complete. The line that closes phase 1 must report `975020 blocks, 1476123483 txs`. The scanner prints six phases: 1 block scan, with a line for the records skipped as not on the list; 2a reduction of the 16 H32 shards (32-byte hashes); 2b deduplication of the 64 H20 shards (20-byte hashes) and the Bloom filter; 2c derivation over the 64 X shards (x values); 3 intersection; 4 writing of `cross_format_diff_20.bin`, `stats.json`, `last_indexed_height` and `checkpoint.json`. GB here means 10^9 bytes. The chain-list scan took 13,932.7 seconds in all, 6,956.3 of them in phase 1, on an n2d-standard-8 machine (8 vCPUs, 32 GiB of memory) with its container limited to 6 CPUs and 12 GiB. Phase 2c holds one byte per distinct x, one X shard and a Bloom filter of 2^31 bytes, about 2.1 GB, which is only a pre-filter: every hit is confirmed by binary search. Phases 3 and 4 hold three bytes per distinct x, about 5.3 GB here, plus one shard of hashes. In the chain-list scan, the scanner's `VmHWM` (peak resident memory so far), read every ten minutes, was 7,102,240 KiB, about 7.3 GB, at the last reading, 7 minutes 48 seconds before the scan ended; a later peak was not recorded. Code comments put the temporary shards, deleted at the end, at about 56 GB for 20-byte hashes, 33 GB for 32-byte hashes and 20 GB for candidates, with no estimate for x values. The tables take 34,578,118,864 bytes and the state files 146,234,643,004 bytes.

4. Verify. Save the six lines of Section 5.5 as `SHA256SUMS-975019` in `<out_dir>`, then run the command below. All six files should report OK. Then compare `stats.json` with Sections 5.5 and 7; step 4 of the top-level `README.md` also checks it against the archive's hash, after removing `census`, `scan_height` and `scan_block_hash`.

   ```
   cd <out_dir> && sha256sum -c SHA256SUMS-975019
   ```

The 975019 tables were first built by an earlier scanner whose revision was not recorded. The 2026-11-08 rebuild, run with no shard files to resume from by an internal revision whose scan path differs from that of the first commit of this repository (tag `original-scanner`) only as `results/975019/README.md` lists, matched all six files byte for byte. The chain-list scanner in this repository matched them too, on 2026-11-16 (`results/975019/README.md`).

## 10. UTXO-basis exposure definition (height 975019)

The UTXO-basis census (`tools/utxo-census`; results in `results/975019/`, provenance also on
https://snapshots.ark0.si/method.html) takes the set of outputs that
are still unspent at height 975019 (Bitcoin Core `dumptxoutset`, base hash
`0000000000000000000158c9898f947463d71d98c97f1dad1639e25114a1dae6`, 163,658,747 coins,
20,109,207.36373994 BTC) and classifies each output by its scriptPubKey. An output is
counted as **exposed** when:

- P2PKH or P2WPKH: its 20-byte program is in `pubkey_hash_index.bin`, i.e. it is the HASH160
  of a public key published anywhere on chain up to the snapshot height, or the HASH160 of
  such a key's P2WPKH script that was funded as P2SH (Section 5.1; the table does not record
  which);
- P2SH: the redeem script has been revealed on chain, or the script hash is the
  nested-P2WPKH wrapper of a public key already published anywhere on chain (either
  suffices), i.e. its 20-byte program is in `script_hash_index_20.bin` or in
  `pubkey_hash_index.bin`;
- P2WSH: its 32-byte program is in `script_hash_index_32.bin`, i.e. the witness script was
  revealed;
- P2TR, P2PK and bare multisig: always, because the public key is part of the output
  script itself (structural exposure). At height 975019 these classes hold 222,545.28 BTC
  (P2TR), 1,714,618.81 BTC (P2PK) and 68.36 BTC (bare multisig). The census counts as bare
  multisig only OP_m, n direct pushes of 33 or 65 bytes, OP_n and OP_CHECKMULTISIG with
  1 <= m <= n <= 3, a narrower form than the key sources of Section 4. Multisig scripts with such
  keys but m or n outside 1 to 3 or a non-minimal key push, and P2PK scripts with a non-minimal
  key push, are counted in the `other` buckets `bare_multisig_outside_policy` and
  `p2pk_nonminimal_push`; both are empty at height 975019.

Outputs of any other form are counted but never exposed. Not exposed is an outcome of this
census only, not the draft's EXPOSED_ON_SPEND (Section 11.4): outputs of other forms are among
them, and the lookup API reports those as UNDETERMINED, or UNCLASSIFIED for OP_RETURN outputs
and version 0 programs of other lengths. A spend reveals a key or script to the tables only
through the positions and roles of Section 2. Amounts are summed per class and
"distinct keys" counts distinct programs per class. The headline figure (7,164,754.12 BTC
exposed out of 20,109,207.36 BTC unspent, 35.6 %) uses only output amounts and table
membership, so the "Counting before curve validation" caveat of Section 8 does not apply to
it; the caveat does apply to any denominator taken from the `published_x_*` counters. The
structural classes are counted in full. Outputs that fail the census curve check are 19,915
UTXOs holding 0.16674821 BTC at height 975019: 73 P2TR and 463 P2PK UTXOs whose key fails it,
and 19,379 bare-multisig UTXOs with fewer than m keys that pass, m being the number of
signatures required (`curve_validation` in `results/975019/utxo-census-stats.json`, described
in `results/975019/README.md`). The census check accepts only `02`, `03` and `04` keys, so one
P2PK output with a valid hybrid key is among the 463; `results/975019/README.md` gives its
outpoint. The lookup API reports outputs that fail its own check as UNDETERMINED; its check
also accepts a hybrid key whose prefix matches the parity of y.

## 11. Relation to the BIP 362 draft

The index was built for the BIP 362 draft, "Output Public Key Exposure Classification". The draft was assigned BIP number 362 in [bitcoin/bips#2294](https://github.com/bitcoin/bips/pull/2294), but it is not a ratified standard. This section compares Sections 1 to 10 with draft version 0.7.0, commit 9a9def264c80be2591b64d27149d8ce9bf0d66e8 on the branch of that pull request; line numbers refer to [`bip-0362.md` at that commit](https://github.com/duncan0k/bips/blob/9a9def264c80be2591b64d27149d8ce9bf0d66e8/bip-0362.md). It lists correspondences and differences and does not state that the index meets the draft's requirements. The self-test vectors come from an earlier text of the draft, also numbered 0.7.0 (Section 11.5).

### 11.1 Correspondences

| Draft | Lines | Rules |
| --- | --- | --- |
| Four key encodings; "An x-only key covers both points with its x-coordinate." | 54-56 | Same encodings, with hybrid prefixes matching the parity of y (Section 11.2, item 12); one key per x, hashes of both points (Sections 2.2, 3) |
| Published: in a confirmed transaction, "in a `scriptPubKey`, a `scriptSig` or a witness" | 57-58, 65 | Only the blocks of a best-chain list, each checked against the list, so no unconfirmed transactions and no stale blocks (Section 11.2, item 10); keys from outputs, scriptSigs and witnesses, none from signatures (Sections 1, 2.1, 2.2) |
| Derived, revealed script `S`: its P2SH, P2SH-P2WSH and P2WSH hashes | 82-84 | Three forms of each revealed script (Sections 2.3, 3, 5.2, 5.3) |
| Derived, published key: "the six encodings `e` of the two points", for P2PKH, P2WPKH and P2SH-P2WPKH | 88-90 | K_i(x) and W_i(x) (Sections 3, 5.1) |
| Structural: "its `scriptPubKey` contains a public key"; the P2PK, bare multisig and P2TR rows | 80, 163-164, 169, 174 | Exposed by form (Section 10); keys from positions 2 and 3 (Section 2.2) |
| "Nothing is rebuilt from published keys"; unrevealed scripts are not assumed | 92-94, 185-186 | No script built from keys except the P2WPKH script in W_i(x), as at line 90 (Sections 3, 5.2, 5.3) |
| Address indexes miss P2PK and bare multisig keys | 235-241 | Raw blocks, P2PK and bare multisig keys included (Sections 2.1, 2.2) |

Sections 6 and 7 have no counterpart in the draft: the diff tables are a heuristic, and some counters of Section 7 include x values that are not x-coordinates of curve points.

### 11.2 Differences at height 975,019

"Fewer" and "more" compare the exposed counts of the census of Section 10 with the draft's `EXPOSED_AT_REST`. Where the draft at this commit does not settle a point, the effect is given under each reading. Upper bounds come from `results/975019/utxo-census-stats.json`, the output of that census. The exact sizes of items 5 and 9 come from `utxo-census-audit-other-keys.json` and `utxo-census-audit-structural-keys.json` in the same directory, written by an audit extension of the census tool; the extension is not in this repository. The size of item 4 comes from `witness-program-histogram.json` in that directory, written from the same UTXO snapshot by the script published as `tools/validation/witness-histogram.py`, which shares no code with the census tool.

1. Keys inside longer pushes. Keys are whole data pushes or witness elements, except pushes inside strings read as scripts and Taproot internal keys (Section 2.2). The draft does not say whether a key inside a longer push or element is published (lines 57-58).
2. x-only key positions. The index takes x-only keys in positions 3, 6 and 7 of Section 2.2. The draft gives no rule for where an x-only key is published (lines 54-56).
3. Scripts not taken as revealed. Section 2.3 does not take an empty redeem script or native witness script, a script in a spend of the P2PKH or P2WPKH shape, or a native witness script that passes the control-block test (Section 8), whose pushed keys are then taken only from their other occurrences. The draft matches any revealed redeem or witness script (line 82), even one that needs no signature (lines 183-185).
4. Witness version 2, 32-byte outputs. The census never counts them as exposed (Sections 2.4, 10), and the index does not "flag the case separately" (lines 205-206). BIP 360 is not active on mainnet. Under lines 203-206 such an output has the level of P2MR: `EXPOSED_AT_REST` when its program equals a leaf or branch hash revealed by a P2TR or P2MR script-path spend (lines 85-87), or when an output paying the same `scriptPubKey` has a confirmed spend (lines 218-221). Under lines 170-171 it is "Other witness versions / programs", `UNDETERMINED`, as the P2MR row applies "where BIP 360 is active".
5. Other output forms with a key push. The index takes keys pushed in any output script (Section 2.2), but the census counts these outputs as not exposed (Section 10). The draft does not define the lookup API label `UNCLASSIFIED`, nor say whether the structural condition (line 80) or the type rows for other and non-standard outputs (lines 171-172) apply to them. The size covers outputs with a whole 33-byte or 65-byte push that the scanner's key test accepts as a curve point (Section 2.2); keys inside longer pushes and x-only keys stay with items 1 and 2.
6. Tapscripts matched with P2SH and P2WSH. The index derives the three forms of every tapscript and matches TapLeaf and TapBranch hashes with P2WSH programs (Sections 2.3, 5.3). The draft maps a "redeem script or witness script" to P2SH and P2WSH (line 82) and a "leaf script revealed with its Merkle path" to P2MR roots (lines 85-87), without saying whether a leaf script is also a witness script. The P2WSH bound includes programs revealed as redeem or nested witness scripts, which the draft matches too.
7. Strings taken as scripts. Without the spent output, the shape rules also take signatures, the annex of a Taproot key-path spend, and keys that end a scriptSig without the P2PKH spend shape, as scripts (Sections 2.3, 8). The draft matches redeem and witness scripts (line 82).
8. 20-byte lookups. `pubkey_hash_index.bin` does not record whether an entry is a K_i(x) or a W_i(x) (Section 5.1), and the census looks up P2PKH, P2WPKH and P2SH programs in it (Section 10). The draft matches key hashes with P2PKH and P2WPKH, and wrapper hashes with P2SH (lines 88-90). The P2SH bound includes nested P2WPKH outputs, which the draft matches.
9. Structural classes without a curve check. Section 10 counts these classes in full. The draft defines a public key as "a point on secp256k1" (line 54), but its rows for these classes (lines 163, 164, 169) do not mention keys that are not points. Under line 80 only outputs with no valid key differ: 73 P2TR, 462 P2PK and 19,379 bare multisig outputs by the scanner's key test, that is, those failing the census curve check (19,915 UTXOs, 0.16674821 BTC; Section 10) except the P2PK output with a valid hybrid key.
10. Chain membership. The draft excludes stale blocks (line 65). The scan uses only the blocks of a best-chain list exported from a node, checks each listed block against the list and skips every other record (Sections 1 and 2.1); which blocks are on the best chain is taken from that node, and the scan does not check proof of work (Section 8). The published tables predate this scan: the revision of the scanner that first built them was not recorded (Section 9), and the 2026-11-08 build checked no block hash (Section 1), so extra block records (stale, duplicate or above the snapshot height) may have been scanned. The chain-list scan reproduced the tables byte for byte (Section 9), so no table entry depends on a record that is not on the list.
11. Parse failures. The draft's derived condition can be met by any confirmed transaction (line 81). The scan stops when a transaction of a listed block does not parse, when bytes are left after the last transaction, when the Merkle root does not match or when a listed block is not found (Section 2.1), so a scan that completes has parsed every transaction of the listed blocks. The scanner of the first commit of this repository, which Section 9 relates to the 2026-11-08 build, stops on none of these: it skips a file it cannot read and drops the rest of a block at a transaction that does not parse, without counting or logging either, and it checks neither the bytes after the last transaction nor the Merkle root. The chain-list scan reproduced the published tables byte for byte (Section 9).
12. Hybrid key prefixes. The index takes a hybrid key only when its `06` or `07` prefix matches the parity of y (Section 2.2). The draft lists hybrid keys without this condition (lines 54-56).

| # | Difference | Effect | Known size at 975,019 |
| --- | --- | --- | --- |
| 1 | Keys inside longer pushes | Fewer, if a key inside a longer push or element counts | Not measured |
| 2 | x-only key positions | Fewer, if an x-only key in another position counts | Not measured |
| 3 | Scripts not taken as revealed | Fewer | Not measured |
| 4 | Witness version 2, 32-byte outputs | Fewer under lines 203-206; no difference under lines 170-171 | None: the UTXO set holds no such output |
| 5 | Other output forms with a key push | Fewer under line 80; no difference under lines 171-172 | 20 UTXOs, 0.02690339 BTC |
| 6 | Tapscripts matched with P2SH and P2WSH | More: tapscript forms under one reading, TapLeaf and TapBranch hashes under both | P2WSH: at most 388 UTXOs, 3,090.78805826 BTC, 204 programs. P2SH: not measured |
| 7 | Strings taken as scripts | More | Not measured |
| 8 | 20-byte lookups | More | P2SH: at most 8,042 UTXOs, 570.66630416 BTC, 5,334 programs. P2PKH and P2WPKH: not measured |
| 9 | Structural classes without a curve check | More under lines 54 and 80; no difference under lines 163, 164 and 169 | 19,914 UTXOs, 0.16672004 BTC |
| 10 | Chain membership | More, by method, for a scan without the chain list | None: the chain-list scan reproduced the tables (Section 9) |
| 11 | Parse failures | Fewer, by method, for a scan that does not stop on them | None: the chain-list scan reproduced the tables (Section 9) |
| 12 | Hybrid key prefixes | Fewer, if a hybrid key with a mismatched prefix counts | Not measured |

### 11.3 After the snapshot

The daily path of Section 8 affects lookups after height 975,019, not the census.

- Funding after the snapshot is not tracked, while the draft counts a later output paying a published key or script (lines 93-94); lookups can report fewer.
- Entries merged by `--compact` are never removed, so those of a block that a reorganization later replaces stay; applying a height again drops the unmerged records from that height up. Key and signature hashes enter the script tables. The draft excludes stale blocks (line 65) and matches redeem and witness scripts (line 82), so lookups can report more.
- The daily path adds TapLeaf and TapBranch hashes but not tapscript forms, so only the hash part of item 6 applies to it, and under the reading that a leaf script is a witness script, lookups can report fewer.
- Keys come from the scan's seven positions (Section 2.2); without shape exclusions, position 5 also reads pushes inside the extra strings taken as scripts.

### 11.4 Section 10, the lookup API and the draft's levels

The outputs that Section 10 does not count as exposed are not the draft's `EXPOSED_ON_SPEND` set: some are `UNDETERMINED` in the draft (lines 171-172), and the draft requires the derived condition to have "been checked against every confirmed transaction" (lines 229-230), which the index does only within the limits of Section 11.2. A result of not exposed means that no table entry matched, or that the output is of a form the census does not look up; it is not evidence that the key or script was never disclosed, on chain in a position the rules do not read or off chain (lines 256-258).

The totals of Section 10 are therefore not the draft's `EXPOSED_AT_REST` totals. Both directions in Section 11.2 have items not measured, so no total bound can be given.

The lookup API answers `EXPOSED_ON_SPEND` when it looks a program up in the tables and the loaded delta and finds no entry. Since the index checks the derived condition only within the limits of Sections 11.2 and 11.3, that answer establishes neither `EXPOSED_AT_REST` nor `EXPOSED_ON_SPEND`, and the draft requires `UNDETERMINED` in that case (lines 142-144 and 230-231). The answer means only that no entry matched, and it carries the action key `SWEEP_WHEN_SPENDING` where `UNDETERMINED` would carry `MIGRATE` (lines 401 and 403).

### 11.5 Self-test vectors

`btc-indexer/test_vectors_070.json` is identical to the `test_vectors.json` of commit 897a451c7b5ee4f5f1c8ed88a25331d322aae250 in the draft's reference implementation repository, https://github.com/duncan0k/pubkey-exposure-classification (line 418). That commit carries an earlier text of the draft, also numbered 0.7.0. The repository's `main` branch reverted it on 2026-11-07 (UTC), and the branch `v0.7.0-withdrawn` keeps it. The vectors exercise `classify` and `extract_evidence` (Section 8), which only `--self-test` calls. Against the text at commit 9a9def2:

1. C45, C46 and the second target of E-e expect no level, for OP_RETURN outputs and a version 0 program of another length. The draft gives every output a level: "Each output has exactly one level." (line 71).
2. S11 and C64 (Section 11.2, item 4), C34, S09, C33, C25, C27 and C31 (item 9) and C67 to C69 (item 6) follow rules of the earlier text where the current text reads differently or can be read in two ways.
3. C29, C30, C37 to C43 and 14 extraction targets depend on rules that only the earlier text states: key positions (Section 11.2, items 1 and 2), output templates and valid key counts, hybrid key parity (item 12), and activation heights.

A review of the other assertions against the text at commit 9a9def2 found no difference; no implementation of that text was run. The earlier text states the rules behind items 1, 2 and 12 of Section 11.2, the `UNDETERMINED` of item 4 before activation, the leaf scripts of item 6 as revealed scripts, and the "not classified" outputs that the lookup API labels `UNCLASSIFIED` (item 5). The lookup API applies the vectors' rules to OP_RETURN outputs, witness version 2 outputs and bare multisig (Section 10). No part of the index gates reveals on the earlier text's activation heights; `extract_evidence` takes BIP 16, BIP 341 and BIP 360 activation as flags read from each vector (BIP 16 defaults to active) and has none for BIP 141.

## Appendix A. Claims list

For fact checking. Line numbers are approximate and refer to `btc-indexer/src/main.rs` in this repository unless another file is named. Some records of the reference build, such as its scan log, are not part of this repository; rows that rest on them say so. The files of `results/975019/` are.

| ID | Sec. | Claim | Support |
| --- | --- | --- | --- |
| A1 | 1, 5.4 | Snapshot height 975,019; `last_indexed_height` contains `975019` plus a line feed, written by the scanner | Its line in the archive's `SHA256SUMS` equals sha256 of "975019\n"; written by `scan_blocks_dir` ~2457 as the last listed height and a line feed; `http_response` ~3363 reads it; the daily updater, which is not in this repository, writes it for later heights |
| A2 | 1 | Node synced on 2026-11-07/08 and ran with `-blocksxor=0` | Record of the reference build; not verifiable from this repository |
| A3 | 1, 2.1 | Scanner searches for `f9 be b4 d9`, has no de-obfuscation and stops on an `xor.dat` with a non-zero byte | `scan_blocks_dir` ~2027; `xor.dat` check ~1980-1986 |
| A4 | 1 | 975,020 blocks and 1,476,123,483 transactions in the 2026-11-08 build; the chain-list scan's counts | Phase 1 line of the 2026-11-08 rebuild log (not in this repository); the method page gives the same transaction count as `nchaintx` of the UTXO snapshot; the chain-list scan: its phase 1 line, `[1.5/4] Block scan finished in 6956.3s (975020 blocks, 1476123483 txs).`, and the line after it, `-> Skipped 1164 records not in chain list.` (its output is not in this repository) |
| A5 | 1, 2.1, 8 | Each listed block is checked: header hash, previous-block hash, full parse with nothing left over, Merkle root with no equal pair, witness commitment; no proof-of-work, script, signature or amount check | `extract_block` ~1666-1707; `unmutated_merkle_root` ~1650-1664 |
| A6 | 1, 4, 8 | Funded means ever funded; values ignored; nothing removed | `parse_transaction_from_reader` ~497 (value skipped); output loop ~1716-1748; inputs never set funded flag values |
| A7 | 2.1 | Files named `blk*.dat` | `scan_blocks_dir` ~1987-1994 |
| A8 | 2.1 | Six reader threads, one whole file each | `scan_blocks_dir` ~2013-2020 |
| A9 | 2.1 | Record under 80 bytes or past end of file ends the file; the header is hashed and looked up in the list | `scan_blocks_dir` ~2027-2035 |
| A10 | 2.1, 8 | A transaction that does not parse, bytes left after the last one, and a file that cannot be opened or read each stop the scan | `extract_block` ~1676-1692; `scan_blocks_dir` ~2018-2020 |
| A11 | 2.1 | No prevout lookup | `extract_block` ~1750-1898 uses scriptSig and witness only |
| A12 | 2.2 | 33-byte `02`/`03` accepted without curve check; 65-byte `04`/`06`/`07` with parity and curve check | `fast_candidate_x` ~202-220; `key_x` ~61-114 |
| A13 | 2.2 | 32-byte keys only at positions 3, 6, 7 | x-only calls ~1744, ~1827, ~1871 |
| A14 | 2.2 | Position 1: every push of every output, OP_RETURN included | ~1716-1721 (before `recognize`) |
| A15 | 2.2 | Position 2: P2PK key, bare multisig keys | ~1722-1730; `recognize` ~395-415 |
| A16 | 2.2 | Position 3: P2TR program, no curve check | ~1743-1745; `fast_candidate_x` ~203-208 |
| A17 | 2.2 | Position 4: scriptSig pushes including coinbase, witness elements | ~1751-1766 (recorded before the coinbase `continue`) |
| A18 | 2.2 | Position 5: pushes in revealed scripts; tapscript pushes must be valid points | ~1783-1787, ~1799-1803, ~1856-1864, ~1891-1895 |
| A19 | 2.2 | Position 6: Taproot internal key, validated | ~1827-1830 |
| A20 | 2.2 | Position 7: leaf version `c0`, 32-byte push before opcode 172, 173 or 186 | ~1865-1878 |
| A21 | 2.2 | Dedup by x, provenance flag values combined with OR | per-block maps in `extract_block` ~1708-1713 and per-file maps in `scan_blocks_dir` ~2042-2044, combined with OR; `flush_scan_map` ~1904-1918; phase 2c ~2214-2225 |
| A22 | 2.2 | Provenance flag values per position | ~1719, ~1724, ~1728, ~1744, ~1758, ~1762, ~1785, ~1801, ~1829, ~1860, ~1872, ~1893 |
| A23 | 2.3 | Redeem-script role and P2PKH-shape exclusion | ~1768-1772 |
| A24 | 2.3 | Nested-witness-script role | ~1788-1789 |
| A25 | 2.3 | P2WPKH-shape exclusion, annex drop, control-block shape, leaf version | ~1809-1827, ~1846 |
| A26 | 2.3 | Native-witness-script role | ~1881-1896 |
| A27 | 2.3 | TapLeaf and TapBranch hashes | `leaf_hashes` ~229-250; ~1839-1854 |
| A28 | 2.4 | P2MR disabled in the scan | `recognize(out, false)` ~1722; `recognize` ~361 |
| A29 | 2.4, 4 | Witness program rules and other versions | `witness_program` ~315-324; `recognize` ~344-367 |
| A30 | 3 | Six encodings, 12 hashes, invalid x skipped | `key_hashes_from_x` ~148-195; `negate_field_y` ~118; ~2237-2239 |
| A31 | 4 | Exact P2PKH and P2SH patterns | `recognize` ~368-377 |
| A32 | 4 | Funded flag values 1, 2, 4 for 20-byte and 1 for 32-byte values | ~1731-1741 |
| A33 | 4 | Values without flag value 1, 2 or 4 dropped | ~2171 |
| A34 | 4, 6 | Revealed and cross flag values per role (20-byte 8 and 16, 32-byte 2 and 4) | ~1774-1782, ~1792-1798, ~1831-1838, ~1853, ~1883-1890 |
| A35 | 5 | Sorted, unique, written in shard order | sharding `flush_scan_map` ~1904-1918; sorts ~2100, ~2155, ~2359; dedup ~2102-2111, ~2157-2166, ~2362-2369, ~2410-2411 |
| A36 | 5 | Lookups are binary searches over the file | `binary_search_file` ~2942-2962 |
| A37 | 5.1 | Direct hashes need P2PKH or P2WPKH funding, wrapped hashes need P2SH funding | ~2324-2348; written ~2362-2369 |
| A38 | 5.2 | `script_hash_index_20` = flag values 4 and 8 | ~2178-2180 |
| A39 | 5.3 | `script_hash_index_32` = flag values 1 and 2 | ~2118-2121 |
| A40 | 5.5, 7 | Entry counts and census values | `results/975019/btc-indexer-stats.json`, the `stats.json` of the 2026-11-08 rebuild, and its log (not in this repository); the archive's `stats.json` has the same entry counts and no census (A83) |
| A41 | 5.5 | Sizes = entries times width | Arithmetic on A40 |
| A42 | 5.5, 9 | Six SHA256 values; rebuild matched | `SHA256SUMS` inside the published archive; `results/975019/verify-against-original.log`, the check of the 2026-11-08 rebuild against the six checksums of Section 5.5 |
| A43 | 5.5 | `stats.json` bytes differ between builds | The archive's `SHA256SUMS` versus the hash of `results/975019/btc-indexer-stats.json`, the `stats.json` of the 2026-11-08 rebuild, in `results/975019/SHA256SUMS`; see A83 |
| A44 | 6 | D32 = flag values 1 and 4 | ~2122-2125 |
| A45 | 6 | D20 formula | ~2309-2311, ~2400-2408 |
| A46 | 6 | B(x) bit indices | ~2333-2348 |
| A47 | 6 | Cross flag only set with the revealed flag | every site in A34 sets 16 with 8 and 4 with 2 |
| A48 | 7 | Census definitions | `census_row` ~1111-1131; `record_row` ~1164-1185; `record_hash20` ~1187-1192 |
| A49 | 7, 8 | Census rows cover every recorded x, valid or not | x flags pushed for all x ~2227-2231; invalid x skipped only for hashes ~2237; census loop ~2424-2427 |
| A50 | 7 | The note field: null in the 2026-11-08 build, which did not resume, and always null in this scanner, which does not resume; the earlier scanner set it only when a resumed run skipped the 32-byte reduction | No scan path sets `funded_hash32_p2wsh_note` (`Census` ~1160); only a unit test does, ~1347; in the first commit of this repository (tag `original-scanner`), `scan_blocks_dir` sets it only when the H32 reduction was done before a resume, ~1862 there; the 2026-11-08 build ran with no shard files to resume from (Section 9); `results/975019/btc-indexer-stats.json` (null) |
| A51 | 7 | Top-level fields and `cross_type_reuse` | ~2424-2454 |
| A52 | 7 | 1,710 and 194,065 | Arithmetic on A40 |
| A53 | 8 | Daily path: no funded filter, all 12 hashes merged | `apply_block` ~2790-2797; `compact_delta` ~3164-3165, ~3177 |
| A54 | 8 | Daily path: last push, nested witness script and last witness element treated as scripts without exclusions | `apply_block` ~2656-2664, ~2692-2701; the nested witness script is taken when the last push is a P2WSH program |
| A55 | 8 | Daily path: leaf and branch hashes merged into the 32-byte table, tapscript forms not added | `apply_block` ~2709-2737; `compact_delta` ~3167-3179 |
| A56 | 8 | Diff tables untouched by the merge | `compact_delta` ~3177-3179, ~3193-3196 |
| A57 | 8 | Daily path: header hash, full parse, Merkle root and witness commitment checked; no proof-of-work or previous-block check; a failing block is rejected whole | `apply_block` ~2586-2623, ~2768-2788, ~2813-2836 |
| A58 | 8 | Merged entries never removed | `merge_sorted_bin_file` ~3043-3123 |
| A59 | 8, 9 | 128 self-test vectors over `classify` and `extract_evidence`; expected message | `run_self_test` ~966-1040; `test_vectors_070.json` has 14, 12, 71 and 31 vectors |
| A60 | 9 | No resume: the output directory must be absent or empty, and an empty path is refused | `scan_blocks_dir` ~1962, ~1971-1979 |
| A61 | 9 | Shards deleted at the end | ~2418 |
| A62 | 9 | Memory: one flag byte per x from phase 2c, two hit bytes per x from phase 3; Bloom filter of 2^31 bytes | ~2199, ~2288-2290; `FundedBloom` ~1045-1092 |
| A63 | 9 | Bloom filter confirmed by exact search | ~2243, ~2251, ~2324 |
| A64 | 9 | Scratch estimates from code comments | ~2076, ~2134, ~2192 |
| A65 | 9 | Run time, machine and peak resident memory of the chain-list scan | The last line of its output, `[4/4] Index build completed in 1163.1s (total 13932.7s)!`, and its phase 1 line (A4); the machine type and container limits of the run; `VmHWM` in `/proc/<pid>/status` of the scanner, read every ten minutes, last at 22:39:58 UTC, the scan ending at 22:47:46 UTC (records of the run, not in this repository) |
| A66 | 9 | Size of the state files of the chain-list scan | The `bytes` of the five `state/` files in `results/975019/chain-list-scan-checkpoint.json`: 58,638,777,021, 30,156,212,688, 1,296,690,688, 29,750,653,422 and 26,392,309,185 |
| A67 | 9 | Output independent of file split and order | per-file maps merged with OR ~2042-2044 and `flush_scan_map` ~1904-1918; sort, dedup and OR ~2100-2111, ~2155-2171, ~2214-2225 |
| A68 | 9 | Shard files are not kept between runs: they are created in the new output directory and a complete run deletes them; a failed run can leave them behind | `make_scan_shards` ~1920-1923; `scan_blocks_dir` ~2004-2006, ~2418; errors return before ~2418 |
| A69 | 1 | Indexed programs are those of P2PKH, P2WPKH, P2SH and P2WSH outputs; P2TR outputs are only a key source | output loop ~1722-1745: funded flags only for these four types, P2TR goes to `record_x` |
| A70 | 1, 2.1 | Records not on the list are skipped and counted; a listed block found twice, or not at all, stops the scan | `scan_blocks_dir` ~2034-2038, ~2065-2069; count printed ~2075 |
| A71 | 2.1 | The search resumes at the end of the record; a listed block is checked and parsed only within its record | `scan_blocks_dir` ~2031-2033 (`pos += size` before the lookup), ~2040-2041; `extract_block` ~1676-1692 |
| A72 | 2.1, 2.3 | Data pushes are opcodes 0 to 78 with their data, OP_0 empty; other opcodes carry no data; a truncated push ends parsing and earlier pushes are kept | `Instructions` ~264-302 |
| A73 | 2.2 | 65-byte layout: x is bytes 1-32, y is bytes 33-64; curve check for `04`, `06` and `07`; parity of byte 64 for `06` and `07` | `key_x` ~90-111 |
| A74 | 2.2, 7, 8 | Curve checked at extraction for 65-byte candidates, tapscript pushes and positions 6 and 7; not for P2TR output keys or other 33-byte candidates | `fast_candidate_x` ~202-220; `key_x` calls ~1827, ~1859, ~1871; P2TR ~1744 |
| A75 | 2.2 | Candidates are whole pushes or elements, except the internal key | `record_x` ~1711-1713 receives whole pushes and elements (~1719-1762, ~1785, ~1801, ~1893); tapscript pushes ~1856-1878; internal key `control[1..33]` ~1827 |
| A76 | 2.2 | Tapscript pushes are taken for any leaf version | push loop ~1856-1864 runs before the `version == 192` test ~1865 |
| A77 | 2.3 | r is the last data push, not necessarily the last opcode; the P2PKH shape counts data pushes | ~1752-1760, ~1769-1772 |
| A78 | 2.3 | P2WPKH shape tested on the full witness; annex dropped only for the tapscript test; the native witness script is the last element of the full witness and is never taken for a P2WPKH-shaped witness | ~1809-1818; ~1881 inside the `!is_p2wpkh_spend` branch, using `last_w` |
| A79 | 2.3 | TapLeaf and TapBranch hashes as in BIP 341; leaf hash and every branch hash recorded | `tagged_hash` ~32-39; `leaf_hashes` ~229-250; ~1839-1854 |
| A80 | 4 | P2PK and bare multisig matched by structure (any push opcode, 33-byte or 65-byte length, no curve check, m may be OP_0); P2TR is `51 20` and 32 bytes; keys recorded only as key candidates | `recognize` ~379-417; `small_int` ~305-313; `witness_program` ~315-324, ~358-360; `record_x` ~1711-1713, ~1724, ~1728 |
| A81 | 5.2 | Spent P2SH-P2WPKH programs reach `pubkey_hash_index.bin` through the witness key and W_i(x) funded as P2SH | witness elements ~1761-1763; wrapped match ~2345-2347 |
| A82 | 5.3 | Tapscript forms are cross forms; TapLeaf and TapBranch hashes are tagged SHA256 values; their matches are not counted | ~1830-1838; `tagged_hash` ~32-39; no such counter in `Census` ~1134-1161 |
| A83 | 5.5 | `stats.json` has no timestamp and differs between builds only by the census object | `stats_json` ~2439-2454; removing `census` from the rebuilt `stats.json` and re-serializing it with sorted keys, two-space indent and no final newline gives the `stats.json` hash in the archive's `SHA256SUMS` |
| A84 | 6 | At most one own form per role; none for tapscripts | own forms ~1774, ~1797, ~1883; tapscript forms all cross ~1831-1838 |
| A85 | 6 | Internal keys set provenance flag value 2; D32 includes TapLeaf and TapBranch hashes | ~1829; ~1853; ~2122-2125 |
| A86 | 6 | The size of B(x) is its number of set bit indices; keys with one set bit index and without flag value 2 are left out of D20 | `hits.count_ones() > 1` or flag value 2, ~2405 |
| A87 | 7 | Pairwise counters ignore other types; 272,248 decomposition | `record_row` ~1173-1180; arithmetic on A40 |
| A88 | 7 | 194,065 counts programs in two sets once and in three sets twice | `record_hash20` ~1187-1192; arithmetic on A40 |
| A89 | 7 | `keys_comp_and_uncomp_any_type` uses P2PKH and P2WPKH hits only | `census_row` ~1123-1124: masks `00C3` and `030C` exclude bit index 12 and P2PK |
| A90 | 7 | Names of the five `*_entries` fields | ~2444-2448 |
| A91 | 8 | Completeness: every listed block found exactly once and checked; the transaction total is printed, not compared | `scan_blocks_dir` ~2036-2038, ~2065-2069; print ~2073-2075 |
| A92 | 8 | Look-alike witness: second-to-last element processed as a tapscript; the control-block test ignores the first byte; 33-byte or 65-byte keys ending three or more elements match | ~1820-1828; 65 = 33 + 32 |
| A93 | 8 | Daily path: no shape exclusions; Taproot inputs not exempt | `apply_block` ~2656-2664, ~2692-2701, run for every input with an empty scriptSig before the control-block test ~2709 |
| A94 | 8 | `--compact` changes only the three main tables | `compact_delta` ~3177-3179, ~3193-3196 |
| A95 | 8, 9 | 12 unit tests in `census_tests`, run by `cargo test` | `#[cfg(test)] mod census_tests` ~1195-1354 |
| A96 | 9 | `getblock <hash> 0` returns the block as hex | Bitcoin Core RPC help for `getblock` (verbosity 0) |
| A97 | 9 | A block must lie within one file | ~2028-2030 |
| A98 | 9 | Phase labels; 16 H32, 64 H20 and 64 X shards | prints ~2003, ~2073, ~2084, ~2135, ~2193, ~2280, ~2484; shards `make_scan_shards` ~1920-1923, ~2004-2006, `flush_scan_map` ~1904-1918 |
| A99 | 8 | Daily path: hashes come only from the keys, scripts and leaf hashes of each new block; new outputs are not matched against earlier keys or scripts; a miss is reported as EXPOSED_ON_SPEND | `apply_block` ~2585-2836; `evaluate_script_level` ~2964-2989 |
| A100 | 10 | Outputs of other forms: the lookup API reports UNDETERMINED, or UNCLASSIFIED for OP_RETURN outputs and version 0 programs of other lengths | `recognize` ~340-367; `evaluate_script_level` ~2967-2968 |
| A101 | 10 | Census curve check accepts `02`, `03` and `04` keys only and fails bare multisig with fewer than m valid keys; the API key check also accepts hybrid keys with matching parity | `tools/utxo-census/src/curve.rs` ~81-92, `tools/utxo-census/src/details.rs` ~102-111; `key_x` ~90-104; `evaluate_script_level` ~2969-2974 |
| A102 | 11 | Section 11 refers to draft version 0.7.0, commit 9a9def264c80be2591b64d27149d8ce9bf0d66e8, on the branch of bitcoin/bips#2294; the draft has BIP number 362 and status Draft; line numbers refer to `bip-0362.md` at that commit | Draft lines 2, 6, 8 and 12 at that commit; commit list of bitcoin/bips#2294 |
| A103 | 11.1 | Four key encodings, with hybrid prefixes matching the parity of y (item 12); one key per x, with the hashes of both points | Draft lines 54-56; Sections 2.2 and 3; `key_x` ~61-114 (parity ~95-100); `key_hashes_from_x` ~148-195; A134 |
| A104 | 11.1 | Keys from output scripts, scriptSigs and witnesses of the listed best-chain blocks only, so no unconfirmed transactions and no stale blocks (item 10 of Section 11.2); no key recovered from a signature | Draft lines 57-58 and 65 (unconfirmed transactions and stale blocks); Sections 1, 2.1 and 2.2; `scan_blocks_dir` ~2018-2020 (reads the block files) and ~2034-2038 (skips records that are not on the list); `extract_block` ~1717-1763; A70, A123 |
| A105 | 11.1 | Three forms of a revealed script; six encodings with the P2SH-P2WPKH wrapper | Draft lines 82-84 and 88-90; Sections 3, 5.1, 5.2 and 5.3; `extract_block` ~1772-1782, ~1788-1798, ~1881-1890; `key_hashes_from_x` ~148-195 |
| A106 | 11.1 | P2PK, bare multisig and P2TR counted as exposed by form; their keys come from positions 2 and 3 | Draft lines 80, 163-164, 169 and 174; Sections 2.2 and 10; census `parse` (`tools/utxo-census/src/lib.rs` ~210-213); `extract_block` ~1722-1730, ~1743-1744 |
| A107 | 11.1 | No script built from keys except the P2WPKH script inside W_i(x); P2PK and bare multisig keys taken from raw blocks | Draft lines 90, 92-94, 185-186 and 235-241; Sections 2.1, 2.2, 3, 5.2 and 5.3 |
| A108 | 11.1 | Sections 6 and 7 have no counterpart in the draft | Section 6 (the diff tables are a heuristic); Section 7 (counters that can include x values that are not x-coordinates of curve points) |
| A109 | 11.2 | Item 1: keys are whole pushes or elements, except pushes inside strings read as scripts and Taproot internal keys; the draft states no granularity | Draft lines 57-58; Section 2.2; A75 |
| A110 | 11.2 | Item 2: x-only keys at positions 3, 6 and 7 only; the draft gives no position rule | Draft lines 54-56; Section 2.2; A13; method page, Limitations |
| A111 | 11.2 | Item 3: empty redeem scripts and empty native witness scripts are not taken (an empty nested witness script is); P2PKH and P2WPKH spend shapes; a native witness script that passes the control-block test is read as a control block, so the keys pushed inside it are taken only from their other occurrences | Draft lines 82 and 183-185; Sections 2.3 and 8; `extract_block` ~1769-1772, ~1788-1789, ~1809-1828, ~1881; the pushes of the last element are read only in the native branch ~1891-1895; A23, A25, A92 |
| A112 | 11.2 | Item 4: witness version 2, 32-byte outputs are never exposed and not flagged; under lines 203-206 such an output is `EXPOSED_AT_REST` through a leaf or branch hash revealed by a P2TR or P2MR script-path spend, or through a confirmed spend of an output paying the same `scriptPubKey`; under lines 170-171 it is `UNDETERMINED` | Draft lines 85-87, 112-115, 170-171, 203-206 and 218-221; Sections 2.4 and 10; `recognize` ~361-366 (P2MR only when BIP 360 is active); A28; `test_vectors_070.json` C64 (`own_spend_count` 1, expected `UNDETERMINED`) tests the second route |
| A113 | 11.2 | Item 4 size: none; the UTXO set at 975,019 holds no witness version 2 output with a 32-byte program | `results/975019/witness-program-histogram.json` (amounts in satoshis): `aggregates.v2_32` is 0 outputs and 0 satoshis; `witness_programs.v2` has three program lengths, 2 bytes (1 output, 500 satoshis), 16 bytes (2; 1,047) and 20 bytes (1; 0); `aggregates.v2_v16` (96,673; 52,748,497) equals `other_histogram.witness_v2_v16` of `utxo-census-stats.json`, the census bucket of all witness version 2 to 16 outputs (census `bucket`, `tools/utxo-census/src/details.rs` ~73-78); A137 |
| A114 | 11.2 | Item 5: keys taken from pushes of any output script; other forms counted as not exposed; `UNCLASSIFIED` is not a level of the draft; the readings of line 80 and lines 171-172; the size covers outputs with a whole 33-byte or 65-byte push that the scanner's key test accepts as a curve point, while keys inside longer pushes and x-only keys stay with items 1 and 2 | Draft lines 18-21 (the four levels), 80 and 171-172; Sections 2.2 and 10; the key test is the scanner's `key_x` ~61-114 on pushes split by `Instructions` ~252-303, applied by the audit extension (A136); A14, A100, A115 |
| A115 | 11.2 | Item 5 size: 20 UTXOs and 0.02690339 BTC | `results/975019/utxo-census-audit-other-keys.json` (amounts in satoshis): `total.utxo_count` 20 and `total.amount_sats` 2,690,339 satoshis, that is 0.02690339 BTC; `buckets` splits the total by bucket; its `all_other_buckets` and `all_other_total` equal `other_histogram` and `classes.other` of `utxo-census-stats.json`; the file does not name its key test; A136 |
| A116 | 11.2 | Item 6: three forms of every tapscript; TapLeaf and TapBranch hashes matched with P2WSH programs; the draft maps leaf scripts to P2MR roots | Draft lines 82 and 85-87; Sections 2.3, 5.3 and 6; `extract_block` ~1829-1854; `leaf_hashes` ~229-250; A82, A85 |
| A117 | 11.2 | Item 6 bound: 388 P2WSH UTXOs, 3,090.78805826 BTC and 204 programs, the exposed P2WSH outputs whose program is in `cross_format_diff_32.bin`, which also holds programs revealed as redeem or nested witness scripts | `results/975019/utxo-census-stats.json`, key `classes.p2wsh.exposed_in_cross_format_diff` (amounts in satoshis); census `join` (`tools/utxo-census/src/lib.rs` ~379-412); Section 6 (D32) |
| A118 | 11.2 | Item 7: signatures, the annex of a Taproot key-path spend, and keys that end a scriptSig without the P2PKH spend shape are taken as scripts | Draft line 82; Section 2.3 (the native witness script is the last element of the full witness, annex included) and Section 8; `extract_block` ~1768-1772, ~1809-1818, ~1881; A11, A23, A78 |
| A119 | 11.2 | Item 8: one 20-byte table for key and wrapper hashes, looked up for P2PKH, P2WPKH and P2SH programs | Draft lines 88-90; Sections 5.1 and 10; census `join` (`tools/utxo-census/src/lib.rs` ~381-396); A37 |
| A120 | 11.2 | Item 8 bound: 8,042 P2SH UTXOs, 570.66630416 BTC and 5,334 programs in `pubkey_hash_index.bin` but not in `script_hash_index_20.bin`, nested P2WPKH outputs included | `results/975019/utxo-census-stats.json`, key `classes.p2sh.exposed_pk20_only` (amounts in satoshis); census `join` (`tools/utxo-census/src/lib.rs` ~400-402); method page, Limitations (the P2SH row mixes nested P2WPKH outputs) |
| A121 | 11.2 | Item 9: the structural classes are counted in full; the draft's definition of a public key and its type rows; under line 80 only outputs with no valid key differ, 73 P2TR, 462 P2PK and 19,379 bare multisig outputs by the scanner's key test, that is, those failing the census curve check except the P2PK output with a valid hybrid key | Draft lines 54, 80, 163, 164 and 169; Section 10; A101, A122 |
| A122 | 11.2 | Item 9 size: 19,914 UTXOs and 0.16672004 BTC; the census curve check of Section 10 gives 19,915 UTXOs and 0.16674821 BTC | `results/975019/utxo-census-audit-structural-keys.json` (`rule`: `scanner key_x(data, false)`; amounts in satoshis): the size is the sum of `utxo_count` and of `amount_sats` over `p2tr.invalid` (73; 8,437,548), `p2pk.invalid` (462; 162,280) and `bare_multisig.no_valid_key` (19,379; 8,072,176), that is 19,914 UTXOs and 16,672,004 satoshis, 0.16672004 BTC; `bare_multisig.some_valid` and `bare_multisig.with_hybrid_valid_key` are 0; `p2pk.hybrid_valid` is 1 UTXO of 2,817 satoshis. The census figure is the sum over `classes.p2tr.curve_validation.invalid`, `classes.p2pk.curve_validation.invalid` and `classes.bare_multisig.curve_validation.invalid` of `utxo-census-stats.json` (19,915; 16,674,821 satoshis), the audit total plus `p2pk.hybrid_valid`; `key_x` ~61-114; census `valid_multisig` (`tools/utxo-census/src/details.rs` ~102-111), `lift_x` and `pubkey` (`tools/utxo-census/src/curve.rs` ~69-92); A136 |
| A123 | 11.2 | Items 10 and 11: the scan uses only the listed best-chain blocks, checks each against the list and skips other records; it stops on a transaction that does not parse, on bytes left after the last transaction, on a Merkle root mismatch and on a listed block that is not found; the scanner of the first commit computes no block hash, skips a file it cannot read and drops the rest of a block at a transaction that does not parse, counting and logging neither, and checks neither the bytes after the last transaction nor the Merkle root; the chain-list scan reproduced the tables byte for byte | Draft lines 65 and 81; Sections 1, 2.1, 8 and 9; `scan_blocks_dir` ~2034-2038 (lookup, skip, repeated block) and ~2065-2069 (missing block); `extract_block` ~1666-1707; A5, A10, A70, A91; the chain-list scan: A146; in the first commit of this repository (tag `original-scanner`), `scan_blocks_dir` computes no block hash, returns from a file it cannot read at ~1540-1544 and leaves a block at ~1588-1592, with no counter or log line for either; its transaction loop ends at ~1826 with no check of the bytes that remain, and `merkle_root` is called only in `apply_block` (~2539, ~2551); `results/975019/README.md` relates that scanner to the revision that ran the 2026-11-08 build |
| A124 | 11.3 | Daily path: funding after the snapshot not tracked; entries merged by `--compact` never removed, while applying a height again drops the unmerged records from that height up; no shape exclusions; TapLeaf and TapBranch hashes added, tapscript forms not; keys from the same seven positions, position 5 also reading the extra strings taken as scripts | Draft lines 65, 82 and 93-94; Sections 2.2 and 8; `apply_block` ~2624-2757, journal rewrite ~2799-2835 keeps only records below the applied height; `compact_delta` ~3144-3203; A53, A54, A55, A58, A93, A99 |
| A125 | 11.4 | Not exposed is not the draft's EXPOSED_ON_SPEND; a result of not exposed means that no table entry matched or that the census does not look the output up; it is not evidence that no disclosure occurred; no total bound in either direction; the lookup API answers EXPOSED_ON_SPEND for a program it looks up and does not find, where the draft requires UNDETERMINED, and reports the action key SWEEP_WHEN_SPENDING with it | Draft lines 142-144, 171-172, 228-231, 245-258 and 398-403; Sections 10, 11.2 and 11.3; `evaluate_script_level` ~2964-2989: `recognize(spk, false)` (~2966) sends only P2PKH, P2WPKH, P2SH and P2WSH programs to a lookup, and `EXPOSED_ON_SPEND` is returned at ~2986 when the lookup finds no entry, the delta is loaded (~2983) and `pubkey_hash_index.bin` exists; the `/classify` handler maps `EXPOSED_ON_SPEND` to `SWEEP_WHEN_SPENDING` and `UNDETERMINED` to `MIGRATE` (~3686-3690); A99; census `run` (`tools/utxo-census/src/lib.rs` ~515-521) joins only the P2PKH, P2WPKH, P2SH and P2WSH classes with the tables |
| A126 | 11, 11.5 | `btc-indexer/test_vectors_070.json` is identical to `test_vectors.json` of commit 897a451c7b5ee4f5f1c8ed88a25331d322aae250 in the reference implementation repository; that commit carries an earlier text, also numbered 0.7.0; `main` reverted it on 2026-11-07 and the branch `v0.7.0-withdrawn` keeps it; the self-test vectors come from that text | Draft line 418 (the repository); both files are git blob 3b83687b5fe2dfe45c2b685a38fdf02d07433c02 (sha256 c1d5051cc52db76bd4cb1d51d8acc4d5880557bc7d02632a171830b82482f058); reference implementation repository, commit 897a451, `bip-0362.md` line 12 ("Version: 0.7.0"); revert commit aa07edb14c83ad9856053202bc3c13c41bf015d6 on `main`, dated 2026-11-07 03:36:55 UTC; branch `v0.7.0-withdrawn` at 26270b0 |
| A127 | 11.5 | The vectors exercise `classify` and `extract_evidence`, which only `--self-test` calls | `run_self_test` ~966-1041 calls `classify` (~636) at ~979, ~983 and ~1027 and `extract_evidence` (~709) at ~997; `main` calls `run_self_test` for `--self-test` at ~3710-3711; no other caller; Section 8; A59 |
| A128 | 11.5 | Group 1: C45, C46 and the second target of E-e expect no level | `test_vectors_070.json`: `classification_vectors` C45 (`6a21...`) and C46 (`00021122`), `extraction_vectors` E-e target 2 (`6a`), each with `expected` null; `classify` ~638 returns no level for `Unclassified`; draft lines 71, 135 and 171; reference implementation repository, commit 897a451, `bip-0362.md` lines 89-92 and 194 |
| A129 | 11.5 | Group 2: S11 and C64 (item 4); C34, S09, C33, C25, C27 and C31 (item 9); C67 to C69 (item 6) | `test_vectors_070.json`: `script_vectors` S11 and S09, `classification_vectors` C64, C34, C33, C25, C27, C31, C67, C68 and C69; S09 and C33 are P2TR outputs whose program is not below the field prime, C25 (`02` with x not below the field prime), C27 (`04` with a point off the curve) and C31 (prefix `05`) are P2PK-shaped outputs, and all five expect `UNDETERMINED`; draft lines 54, 80, 82-87, 163, 164, 169, 170-171, 203-206 and 218-221; reference implementation repository, commit 897a451, `bip-0362.md` lines 61-63, 113-119, 133-135, 155-156 and 210-211 |
| A130 | 11.5 | Group 3: C29, C30, C37 to C43 and 14 extraction targets | `test_vectors_070.json`: `classification_vectors` C29, C30 and C37 to C43; `extraction_vectors` targets E-c 1, E-l 1, E-m 1, E-o 2, E-r 1, E-u 2, E-v 1, E-w 1, E-w-wsh 1 and 2, E-x-wpkh 1, E-x-wsh 1, E-x-sig 1, E-x-output 1; draft lines 54-58, 80 and 164; reference implementation repository, commit 897a451, `bip-0362.md` lines 55-58 (hybrid parity, item 12), 67-70, 89 and 168-170 (activation), 71-80 (published keys), 113-116 and 198-201 (templates and valid keys) |
| A131 | 11.5 | A review of the other assertions against the text at commit 9a9def2 found no difference, E-u target 1 included; no implementation of that text was run | Review of the 146 level assertions (97 vectors, one extra target, 48 extraction targets) against the draft at commit 9a9def2, with the extraction transactions decoded and the target hashes recomputed; no implementation was run; records not in this repository. E-u target 1: the spend's control byte is `c0`, and BIP 360, which the draft follows for P2MR paths (line 87), requires the last bit of a P2MR control byte to be 1 (`bip-0360.mediawiki` at the same commit, line 243), so no leaf is revealed |
| A132 | 11.5 | The earlier text states the rules of items 1, 2 and 12, the `UNDETERMINED` of item 4 before activation, leaf scripts as revealed scripts (item 6) and the "not classified" outputs that the lookup API labels `UNCLASSIFIED` (item 5) | Reference implementation repository, commit 897a451, `bip-0362.md` lines 71-80 (items 1 and 2), 56-58 (item 12), 210-211 (item 4), 61-63 and 117-119 (item 6), 89-92 and 194 (item 5); Sections 2.2, 2.3 and 10; A100 |
| A133 | 11.5 | The lookup API applies the vectors' rules to OP_RETURN outputs, witness version 2 outputs and bare multisig | `evaluate_script_level` ~2964-2975; `recognize` ~341-342, ~355, ~361-366, ~402-414; Section 10; A100, A101 |
| A134 | 11.2 | Item 12: a hybrid key is taken only when its `06` or `07` prefix matches the parity of y; the draft lists hybrid keys without this condition | Draft lines 54-56; Section 2.2; `key_x` ~95-100, which `fast_candidate_x` ~217 uses for 65-byte candidates; A12, A73 |
| A135 | 11.5 | No part of the index gates reveals on the earlier text's activation heights; `extract_evidence` takes BIP 16, BIP 341 and BIP 360 activation as flags read from each vector (BIP 16 defaults to active) and has none for BIP 141 | `extract_block` ~1768-1898 and `apply_block` ~2656-2762 take revealed scripts without an activation test; `SEGWIT_ACTIVATION_HEIGHT` (~2516) serves only the witness commitment checks in `extract_block` ~1699 and `apply_block` ~2777; the census `parse` and `join` have no activation test; `extract_evidence` ~709-799 gates P2SH reveals on `bip16_active`, P2TR reveals on `taproot_active` and P2MR on `bip360_active`, read from each vector by `ExtractionVectorItem` ~898-912; reference implementation repository, commit 897a451, `bip-0362.md` lines 67-70, 89 and 168-170 |
| A136 | 11.2 | The exact sizes of items 5 and 9 come from `utxo-census-audit-other-keys.json` and `utxo-census-audit-structural-keys.json`, written by an audit extension of the census tool; the extension is not in this repository | `results/975019/utxo-census-audit-manifest.json`: `snapshot.base_hash` and `snapshot.coins_count` equal those of `utxo-census-stats.json`, and `files` gives the sha256 of both audit files, under the names `other-keys.json` and `structural-keys.json`; the extension's source is not in this repository |
| A137 | 11.2 | The size of item 4 comes from `witness-program-histogram.json`, written from the same UTXO snapshot by the script published as `tools/validation/witness-histogram.py`, which shares no code with the census tool | `results/975019/witness-program-histogram.json`: `snapshot.base_hash` and `snapshot.coins_count` equal those of `utxo-census-stats.json`; ten of its `aggregates` equal the census figures, `total` the `parsed_coin_count` and `total_amount_sats`, `p2pkh`, `p2sh`, `p2pk`, `v0_20`, `v0_32` and `v1_32` the classes P2PKH, P2SH, P2PK, P2WPKH, P2WSH and P2TR, and `v0_other`, `v1_other` and `v2_v16` the `other_histogram` buckets `witness_v0_wrong_length`, `witness_v1_non32` and `witness_v2_v16`; `aggregates.p2pk_hybrid_valid` (1; 2,817) equals `p2pk.hybrid_valid` of `utxo-census-audit-structural-keys.json`; `checks` records these comparisons and `all_checks_ok` is true |
| A138 | 1, 9 | Chain list: one line `<height> <hash>` for each height from 0 in order, the hash in display order, a final line feed, no hash twice | `parse_chain_list` ~1379-1399; `parse_display_hash` ~1369-1377 |
| A139 | 1, 9 | Export: URL `http://<host>:<port>/` and the node's cookie; node out of initial block download with as many headers as blocks; at least 100 blocks above the height; batched `getblockhash`; final check of the last hash and the depth; no overwrite; printed line | `ChainRpc::new` ~1510-1527; `ChainRpc::info` ~1583-1589; `export_chain_list` ~1592-1640 |
| A140 | 2.1 | Witness commitment checked where the block has witness data, or a commitment output from height 481,824 on; the last coinbase output of at least 38 bytes with the commitment prefix; the coinbase's single 32-byte witness item | `extract_block` ~1696-1707; `SEGWIT_ACTIVATION_HEIGHT` ~2516 |
| A141 | 5.4, 7 | `stats.json` keys `scan_height` and `scan_block_hash` | `stats_json` ~2439-2441 |
| A142 | 5.4 | State files: names, record widths and flag values; sorted, no value twice | records ~2113-2114, ~2168-2169, ~2229; `finish_scan_output` calls ~2129-2132, ~2187-2190, ~2278; `ScanWriter::record` ~1436-1446 refuses keys that do not increase |
| A143 | 5.4 | `checkpoint.json`: the twelve files it lists with size, record count and SHA256, its other fields, and `state_digest` | `RULES_VERSION` and `DIGEST_FILES` ~1357-1361; `state_digest` ~1473-1485; `ScanFileInfo` ~1400-1406; checkpoint ~2458-2480 |
| A144 | 5.4, 9 | Exit status 0 only on success, `ERROR:` and status 1 otherwise; every output written to a temporary file, synced and renamed, its directory synced on Unix; `checkpoint.json` last; its removal after a failed publication is best effort; nothing after the publication can fail the run | `main` ~3712-3716; `ScanWriter::finish` ~1447-1457; `withdraw_failed_checkpoint` ~1945-1959; `scan_blocks_dir` ~2474-2501 |
| A145 | 8 | Scanner unit tests in `integrity_tests::chain_scan`; comparison scripts in `btc-indexer/tests/old-vs-new/` | `mod chain_scan` ~4254; the usage lines of the four scripts |
| A146 | 1, 9 | Date, counts, skipped records and checksums of the chain-list scan | Run from 18:55:33 to 22:47:46 UTC on 2026-11-16 (records of the run, not in this repository); counts and skipped records: A4; `verify-chain-list-scan.log`, `chain-list-scan-stats.json` and `chain-list-scan-checkpoint.json` in `results/975019/`, the checkpoint's six hashes equal to those of Section 5.5; the chain list: `results/975019/chain-975019.txt.sha256` |
