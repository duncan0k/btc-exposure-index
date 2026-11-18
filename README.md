# btc-exposure-index

Chain-wide index of **exposed public-key hashes** and **revealed script hashes** on Bitcoin mainnet, built for the
BIP 362 draft (public key exposure classification). The draft was assigned BIP number 362 in bitcoin/bips#2294,
but it is not a ratified standard. The index answers one question for a 20-byte or 32-byte output commitment:
*has the public key or script behind this hash already been published on chain anywhere?* A hit means that
the tables hold the hash, which apart from the cases listed in section 11 of `docs/extraction-rules.md` means it
has; a miss only means that they hold no match (see also [Known limitations](#known-limitations)).

This repository has the indexer that builds the tables, the rules it follows, and the tools we used to check
the result. The tables are far too big for git, so they are published separately (see [Data](#data)).

## Contents

| Path | What it is |
| --- | --- |
| `btc-indexer/` | The indexer, a single Rust binary: full-chain scan, per-block updates, the daily merge into the tables, and an HTTP lookup API. |
| `btc-indexer/test_vectors_070.json` | 128 vectors for `--self-test`: 97 level vectors and 31 extraction vectors. |
| `docs/extraction-rules.md` | What counts as a published key or a revealed script, what each table and counter means, and how to rebuild the snapshot. Start here. |
| `results/975019/` | The `stats.json` files of the scan and of the UTXO census at block 975,019, the checksum comparison of the 2026-11-08 rebuild, and three cross-checks: the output of an audit extension of the census tool, a histogram of the witness programs in the same UTXO set, and a sample of unexposed outputs checked against a public Esplora API. `results/975019/README.md` says what wrote each file. |
| `tools/utxo-census/` | Joins a Bitcoin Core UTXO snapshot (`dumptxoutset`) with the tables and counts the unspent outputs whose key or script is already public. Rust standard library only. |
| `tools/validation/` | Read-only Python checks. `table-check.py` and `validate-index.py` check the tables: their integrity, and spot checks against chain data from a public Esplora API. `witness-histogram.py` reads a UTXO snapshot instead (next row). |
| `tools/validation/witness-histogram.py` | A check of a UTXO snapshot that you export yourself with `dumptxoutset` at block 975,019: witness programs by version and length, and class totals to compare with the census. It shares no code with `tools/utxo-census`; `results/975019/README.md` says how it relates to `witness-program-histogram.json`. |

## Data

The snapshot at block 975,019 is a single archive:

```
https://snapshots.ark0.si/btc-exposure-index-975019.tar.zst
33,654,024,835 bytes
SHA-256 b1712d436b9811ed2261399166bafd055e11f3a48f79e351e9c14e49076d13ba
```

There's a `.sha256` file next to it. The archive holds the five tables, `last_indexed_height` and `stats.json`,
plus a `SHA256SUMS` covering all seven:

```
sha256sum -c btc-exposure-index-975019.tar.zst.sha256
mkdir tables
tar -I zstd -xf btc-exposure-index-975019.tar.zst -C tables
(cd tables && sha256sum -c SHA256SUMS)
```

The index keeps growing after that block. https://snapshots.ark0.si/manifest.json lists the latest full archive
with its date and height, the cross-format diff archive and the daily delta files. Each delta file holds the
blocks applied since the previous day's merge. The manifest lists every delta file that is kept; one is
removed only when 30 newer ones exist and it is dated before the latest full archive. Everything after 975,019
comes from the per-block path, which follows different rules (section 8 of `docs/extraction-rules.md` and
[Known limitations](#known-limitations) below), so read those before you build on it.

For single lookups, https://data.ark0.si runs the [HTTP API](#http-api) below, limited to 10 requests per
10 seconds per IP address, after which that address gets HTTP 429 for 10 seconds. It answers at
`last_indexed_height`, which is past 975,019, so a program first exposed after the snapshot shows up as
present too.

## Reproducing the 975019 tables

The 975019 tables were first built by an earlier version of this scanner, without the census counters; its
exact revision was not recorded. A second build on 2026-11-08, run with no shard files to resume from and with
the census counters added, gave the same five tables and `last_indexed_height` byte for byte
(`results/975019/verify-against-original.log`); its `stats.json` differs only by the `census` object. On the
scan path, `btc-indexer/src/main.rs` here differs from the revision that ran that build only at lines 471-473,
486, 495 and 508, where three preallocations are capped at the remaining input, and at line 2262, a printed
heading; neither changes what is parsed or written (details in `results/975019/README.md`). The code in this
repository has not itself been run over the chain end to end.

What you need:

- **A full node.** Bitcoin Core on mainnet, not pruned, with a blocks directory created with `-blocksxor=0`.
  Recent versions obfuscate block files by default, and the scanner can't read them. At this height the
  block data was about 730 GB.
- **Scratch disk.** Code comments put the temporary shards at about 56 GB for 20-byte hashes, 33 GB for 32-byte
  hashes and 20 GB for candidates; the x-value shards come on top and weren't measured. The finished tables
  take 34,578,118,864 bytes.
- **Memory.** The last phases hold three bytes per distinct x-coordinate, about 5.3 GB here, plus one shard of
  hashes. An earlier phase holds a 2 GiB Bloom filter next to one byte per x.
- **Time.** About 3.3 hours on the reference machine (8 vCPU, 32 GB), close to two of them spent reading block
  files at roughly 106 MB/s.

Steps:

1. Get block files that hold exactly the best chain from block 0 to 975,019. The scanner reads every block
   record in every `blk*.dat` file and doesn't check chain membership, so a stale block or anything above
   975,019 changes the result. A node stopped at that height may already have later blocks on disk. If in
   doubt, export the blocks over RPC into fresh files; section 9 of `docs/extraction-rules.md` has the format.

2. Build and test:

   ```
   cd btc-indexer
   cargo build --release
   cargo test
   ./target/release/btc-indexer --self-test test_vectors_070.json
   ```

   Every unit test has to pass, and the self-test should end with
   `PASS: All 128 test vectors (14 script, 12 history, 71 classification, 31 extraction) verified 100%!`

   `btc-indexer/test_vectors_070.json` is `test_vectors.json` from the draft's reference implementation,
   https://github.com/duncan0k/pubkey-exposure-classification, at commit `897a451c7b5ee4f5f1c8ed88a25331d322aae250`,
   byte for byte. That commit is the 0.7.0 implementation of 2026-11-05 (UTC). The reference repository reverted
   it on `main` on 2026-11-07 (UTC) while the draft text was redone, and keeps it on the branch
   `v0.7.0-withdrawn`; the commit is in the history of both. The vectors test `classify` and `extract_evidence`
   against that earlier text. Section 11.5 of `docs/extraction-rules.md` lists where their expected results differ
   from the draft text as it stands now.

3. Scan, then write the height file (this scanner doesn't):

   ```
   ./target/release/btc-indexer --scan-blocks <blocks_dir> <out_dir>
   printf '975019\n' > <out_dir>/last_indexed_height
   ```

   Use an empty directory: the scanner resumes from shard files under `<out_dir>/shards` if it finds any.
   Phase 1 has to end with `975020 blocks, 1476123483 txs`. Any other count means the block files are wrong.

4. Check. Save the six checksum lines of section 5.5 of `docs/extraction-rules.md` as `SHA256SUMS-975019` in
   `<out_dir>`, then:

   ```
   cd <out_dir>
   sha256sum -c SHA256SUMS-975019
   python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d.pop("census"); sys.stdout.buffer.write(json.dumps(d, indent=2, sort_keys=True).encode())' stats.json | sha256sum
   ```

   All six files should report OK, as they did for the 2026-11-08 build. The second command should print
   `2757785e8c344efc49e6ea4e632063eda0c0498031e6d8896e5cf21cf792cd3c`, the `stats.json` line of the archive's
   `SHA256SUMS`; it does for `results/975019/btc-indexer-stats.json`, the `stats.json` of that build. The numbers
   of the `census` object of `stats.json` are in section 7 of the rules.

## UTXO census

```
cd tools/utxo-census
cargo build --release
cargo test
./target/release/utxo-census --utxo <file> --tables <dir> --out <dir> --tmp <dir> [--tool-version <str>] [--limit-coins N] [--check-curve]
```

`--utxo` takes the `dumptxoutset` file of the mainnet UTXO set at block 975,019, in snapshot format
version 2 as written by Bitcoin Core v28.1.0. The tool refuses any other snapshot: the base hash must be
`0000000000000000000158c9898f947463d71d98c97f1dad1639e25114a1dae6`. `--tables` is a directory with the five
tables; the unpacked archive works. What counts as exposed, and the
results at block 975,019, are in section 10 of `docs/extraction-rules.md` and on
https://snapshots.ark0.si/method.html. A full run over that snapshot with `--check-curve` took about
26 minutes and stayed under 1 GB of memory.

## Validation scripts

```
python3 tools/validation/table-check.py <index_dir>
python3 tools/validation/validate-index.py <index_dir> <api_base> <recall_height> <recall_pages> <equiv_height> <equiv_max_addrs>
python3 -I tools/validation/witness-histogram.py <snapshot> <out_json> [--expect NAME=COUNT:SATS ...] [--progress N]
```

The first one works offline: record order, duplicates, sizes, first-byte spread, the subset relations of the
diff tables, and the structure of `delta_blocks.jsonl` when there is one. The second compares the tables with
chain data from the mempool.space Esplora API, and a few answers of a running API (`<api_base>`) with the
tables. It sends its requests to mempool.space, so keep the sample small. The third reads a UTXO snapshot, not
the tables: one that you export yourself with `dumptxoutset` at block 975,019. It writes the witness programs
by version and length and the class totals to `<out_json>`, and each `--expect` compares a total with a value
you give, for example one from `results/975019/utxo-census-stats.json`. Its documentation says what it checks
and what it does not.

## Commands

| Command | What it does |
| --- | --- |
| `--self-test <json>` | Runs the self-test vectors. |
| `--scan-blocks <blocks_dir> <out_dir>` | Full rebuild from raw block files. |
| `--apply-block-hex <index_dir> <height> <block_hash>` | Reads one raw block as hex on stdin, checks it, and writes what it publishes to `delta_blocks.jsonl`, replacing any record at that height or above. |
| `--compact <index_dir>` | Merges `delta_blocks.jsonl` into the three main tables, then removes it. |
| `--query <index_dir> <script_pubkey_hex>` | Prints the exposure level of one output script. |
| `--serve <index_dir> <bind_addr>` | Runs the HTTP API. |

## HTTP API

Run `btc-indexer --serve <index_dir> <bind>`. All endpoints support GET and HEAD; HEAD returns the same status,
headers and Content-Length without a body, except when the request line is too long (414) or cannot be read,
where the method is not yet known. Connections close after one response. Other methods return 405 with
`Allow: GET, HEAD`. Request lines are limited to 8 KiB (414) and headers to 64 KiB (400). Socket read and write
timeouts are 5 and 30 seconds, and the request line plus headers must arrive within 10 seconds (408 otherwise).
Malformed requests return 400.

| Endpoint | JSON fields |
| --- | --- |
| `/readyz` | `ready` and `delta_ready`, with 200, only when the base pubkey table exists and the initial delta load has completed; otherwise 503 with `ready` false and `reason` |
| `/healthz` | `status`, `base_index_ready`, `delta_ready`, `last_indexed_height`, `stats`, `delta_blocks`, `delta_max_height` (null when empty), `delta_loaded_at` (Unix seconds; 0 before the initial load), `delta_entries_20` (sum of the two 20-byte families), `delta_entries_32` |
| `/lookup/hash/<hex>` | `hash`, `byte_len`, `in_pubkey_hash_index`, `in_script_hash_20_index`, `in_script_hash_32_index`, `in_cross_format_diff`, `delta_hit`, `base_index_ready`, `last_indexed_height` |
| `/lookup/diff/<hex>` | `hash`, `byte_len`, `in_cross_format_diff`, `delta_hit`, `base_index_ready`, `last_indexed_height` |
| `/lookup/script/<scriptPubKey-hex>` | `script_pubkey`, `script_type`, `target_hash`, `structural_key_valid`, the three index membership fields, `delta_hit`, `base_index_ready`, `last_indexed_height` |
| `/lookup/batch?hashes=<hex>,<hex>` | `base_index_ready`, `last_indexed_height`, `results` keyed by normalized hash; each result has `byte_len`, the three index membership fields and `delta_hit`. The first 200 items are read and invalid ones are omitted, but the 8 KiB request-line limit allows at most 198 20-byte or 125 32-byte hashes in one GET. |
| `/lookup/pubkey/<hex>` | `input_pubkey`, `valid_curve_point`, `published_on_chain`, `base_index_ready`, `last_indexed_height`; valid keys also include `x_coord`, `derived_key_hashes_20`, `derived_wrapped_p2sh_p2wpkh_hashes_20` |
| `/classify/<scriptPubKey-hex>` | `script_pubkey`, `level`, `action`; a script that needs a table lookup gets `UNDETERMINED` and `MIGRATE` when that table is unavailable; section 11.4 of `docs/extraction-rules.md` says how the answer for a program that is not found relates to the draft's levels |
| `/snapshots/manifest.json` | The file `snapshots/manifest.json` next to the index directory; 404 JSON when missing |
| `/snapshots/download/<file>` | 410 with `{"error":"downloads moved","manifest":"/snapshots/manifest.json"}`; serve archives from a static host |

Hash endpoints accept 20-byte or 32-byte hexadecimal hashes. `delta_hit` means the hash occurs in the
post-snapshot delta: it was published after the snapshot, but its funded status is unknown. For scripts it
checks the recognized hash commitment; structural public-key and multisig scripts return false. Pubkey-index
delta entries are `kh20 UNION wrapped20`; script-index entries are `sh20` and `wsh32 UNION mr32`. These are the
fields of a `delta_blocks.jsonl` record: `kh20` holds key hashes K_i(x) and `wrapped20` the P2SH-P2WPKH hashes
W_i(x) (section 3 of `docs/extraction-rules.md`), `sh20` the HASH160 of each revealed script and of its P2WSH
program, `wsh32` the SHA256 of each revealed script, and `mr32` TapLeaf and TapBranch hashes, not P2MR roots.
`in_cross_format_diff` and `/lookup/diff` use only the frozen cross-format diff tables. Delta hits establish
neither funded status nor cross-format exposure.

Lookup endpoints return 503 `{"error":"index unavailable"}` if a required table can't be opened or read, has a
length that is not a whole number of records, or the initial delta load isn't ready. A table cut short by whole
records is not detected. `/healthz` stays available and reports
`base_index_ready: false` when the base pubkey table is missing. A failed background reload keeps the last good
delta, and `delta_loaded_at` shows its age. Changes are checked every 2 seconds; rebuilding a large delta adds
some latency before the new version is visible.

`BTC_INDEXER_THREADS` sets the size of the worker pool (default 8). The delta is held in memory as sorted
arrays, and a reload briefly holds the old and the new version, so plan memory for twice the largest delta
you expect. Lookups only binary-search the loaded arrays and the base tables.

## Known limitations

Data added after block 975,019 (the per-block updates, the daily deltas, the latest full archive and the answers
of https://data.ark0.si) has four known problems:

- **Key and signature hashes in the script tables.** For example the public key that ends a P2PKH or P2WPKH spend
  and the signature of a Taproot key-path spend.
- **No prevout lookup and no funded filter.** Like the full scan, the per-block path never sees the output an
  input spends: it takes the last scriptSig push of every non-coinbase input, or the last witness element when
  the scriptSig is empty, as a script (both when the push is a P2WSH program), here without the full scan's
  shape checks. Unlike the full scan, which enters a hash only if it was funded as the matching type by block
  975,019, it enters every hash it derives. That is how the hashes above get in.
- **Reorganizations are not detected.** Nothing checks that an applied block is still on the best chain, and the
  daily updater, which is not in this repository, only moves forward from the last height it applied. Applying a
  height again drops the per-block records from that height on that are not yet merged, but entries merged into
  the tables are never removed. The entries of a block that a reorganization replaces therefore stay.
- **Late funding is missed.** An output created after block 975,019 that pays a key or script published by then,
  and not again, is not found (`/classify` answers `EXPOSED_ON_SPEND`) unless its program had already been funded
  as the matching type by that block (section 5 of `docs/extraction-rules.md`). The 975019 census is not affected.

The fixed 975019 archive has no per-block data, so the last two problems do not arise. Its tables come from
the full scan, which also never sees the spent output, but applies shape checks and keeps only hashes funded
as the matching type: a string that is not a script gets in only when one of its hashes was itself funded as
a P2SH or P2WSH program (sections 2.3 and 11.2, item 7, of `docs/extraction-rules.md`). Its other limits,
among them that chain membership is not checked, are in sections 1 and 8. A redesign that makes the
per-block updates exact is under way.

`/lookup/pubkey` sets `published_on_chain` only when one of the key's 12 derived hashes is in the pubkey table,
which for the snapshot holds only hashes funded as the matching type. A key published by block 975,019 none of
whose hashes had been funded that way by then, for example one seen only in P2PK outputs, gets `false` unless it
appears on chain again.

## License

The code is under the MIT License, see `LICENSE`. `btc-indexer/test_vectors_070.json` carries its own
CC0-1.0 notice.

The published tables and archives and the data files in `results/975019/` are dedicated to the public domain
under Creative Commons Zero v1.0 Universal (SPDX identifier `CC0-1.0`,
https://creativecommons.org/publicdomain/zero/1.0/legalcode). The MIT License does not cover these data, and
CC0-1.0 does not cover the code that produces them.
