# Results at block 975,019

Output of the 975019 scan, the UTXO census and three cross-checks, kept byte for byte as written. `SHA256SUMS`
covers the other files in this directory. Amounts are in satoshis.

| File | Written by |
| --- | --- |
| `btc-indexer-stats.json` | `btc-indexer --scan-blocks`: the `stats.json` of the full scan to block 975,019, rebuilt on 2026-11-08 |
| `verify-against-original.log` | The check of that scan's five tables and `last_indexed_height` against the six checksums in section 5.5 of `docs/extraction-rules.md`, which come from the first build; `rc=0` is its exit status |
| `utxo-census-stats.json` | `tools/utxo-census`: the `stats.json` of a run over the UTXO set at block 975,019 (`dumptxoutset`) and the five tables of that scan |
| `utxo-census-audit-manifest.json` | An audit extension of `tools/utxo-census`, which is not included in this repository, run once over the same `dumptxoutset` file and the same five tables: the manifest of that run, published unchanged |
| `utxo-census-audit-other-keys.json` | The same run: outputs of the `other` class whose script holds a whole 33- or 65-byte data push that is a valid public key, by histogram bucket (`other-keys.json` in the manifest) |
| `utxo-census-audit-structural-keys.json` | The same run: P2PK, P2TR and bare-multisig outputs by key validity, including keys in hybrid encoding (`structural-keys.json` in the manifest) |
| `witness-program-histogram.json` | `tools/validation/witness-histogram.py`: witness programs in the same UTXO set by version and program length, the class totals it was checked against, and the P2PK outputs whose key has the hybrid prefix 06 or 07 |
| `esplora-sample-summary.json` | The audit extension drew the sample; a script that is not in this repository checked it against the public Esplora API at `mempool.space` and wrote this file. Aggregates only: no addresses, scripts or transaction ids |

Removing the `census` object from `btc-indexer-stats.json` and serializing the rest as in step 4 of the
top-level README gives the `stats.json` of the fixed 975019 archive, sha256
`2757785e8c344efc49e6ea4e632063eda0c0498031e6d8896e5cf21cf792cd3c`.

## Notes on the files

- `utxo-census-stats.json`: `amount_near_19_9_million_btc` is a sanity flag, true when the run is complete and
  the total lies between 19,000,000 and 21,000,000 BTC; the total here is 20,109,207.36373994 BTC.
  `other_histogram.mt_gox_malformed` counts outputs whose script is exactly `76 a9 00 88 ac`, the P2PKH script
  with an empty push where the 20-byte hash belongs, which no key can satisfy (23 outputs, 2,609.36304319 BTC).
  Under `curve_validation` (`--check-curve`), `invalid` holds the P2TR and P2PK outputs whose key fails the
  census curve check, which accepts only `02`, `03` and `04` keys, and the bare multisig outputs with fewer
  than m keys that pass it, m being the number of signatures required. `exposed_in_cross_format_diff` counts
  the exposed outputs of a class whose program is also in a cross-format diff table (section 6 of
  `docs/extraction-rules.md`), and `cross_program` the 20-byte programs that hold unspent outputs both as P2PKH
  and as P2WPKH, with those of them in `pubkey_hash_index.bin` under `exposed_*`.
- `utxo-census-audit-other-keys.json` has no `rule` field. It counts the outputs of the census class `other`
  whose script holds at least one whole push of 33 or 65 bytes that the scanner's key test (`key_x` with
  `xonly` false, section 2.2 of `docs/extraction-rules.md`) accepts as a curve point: `02` or `03` with x on
  the curve, `04` with (x, y) on the curve, `06` or `07` with (x, y) on the curve and y of the prefix's parity.
  `buckets` and `total` split those outputs by census bucket, `key_push_occurrences` counts the accepted
  pushes, and `all_other_buckets` and `all_other_total` repeat the whole class.
- `witness-program-histogram.json`: its eleven `expect_*` checks compare its totals with the census, ten with
  `utxo-census-stats.json` and `p2pk_hybrid_valid` with `utxo-census-audit-structural-keys.json`; all pass
  (`all_checks_ok`). `hybrid_prefix_p2pk` lists the five P2PK outputs whose key has a `06` or `07` prefix. One
  of them is valid, with y of the prefix's parity, and it is the P2PK output with a valid hybrid key that
  section 10 of `docs/extraction-rules.md` mentions: txid
  `519c79dc444009744e5dec35817d0a7530ba3601aed58ac34837397134177db8`, vout 2, height 707,034, 2,817 satoshis.
  The census curve check rejects it; the scanner's key test accepts it.
- `esplora-sample-summary.json` reports a sample, not a census: 250 unexposed outputs of each of P2PKH, P2WPKH,
  P2SH and P2WSH, drawn with seed 975019 by the audit extension, which is not in this repository, so the sample
  cannot be redrawn from the files here. Each sampled output was checked against the public Esplora API at
  `mempool.space`, a third-party service, not against the tables in this repository; the script that queried the
  API and wrote this summary is not in this repository either. The only question it answers is whether an output
  carrying the same scriptPubKey as a sampled unexposed output had been spent at or before block height 975019.
  None of the 1,000 had; 8 were spent only later, which is not counted. The one-sided 95% upper bound on the
  share of such outputs is 1.19% for each type and 0.53% for the four types together, weighting each type by its
  number of unexposed outputs as given in `utxo-census-stats.json`.

## Code versions

None of these files was regenerated with the code in this repository, and the code in this repository has not
itself been run over the chain end to end.

- `btc-indexer-stats.json` names no tool version. It comes from the 2026-11-08 build, run with no shard files to
  resume from and with the scanner of internal revision `fbc9a9d`, the first revision with the census counters;
  the commit that recorded the file has the same scanner source. `verify-against-original.log` checks that
  build's tables against the first build, whose revision was not recorded. On the scan path,
  `btc-indexer/src/main.rs` here differs from `fbc9a9d` only at lines 471-473, 486, 495 and 508, where
  `capped_capacity` caps three preallocations at the remaining input, and at line 2262, the heading `Cross-type
  reuse stats:`; neither changes what is parsed or written. Its other differences are in the per-block path, the
  lookup API and HTTP server, the error handling of `--apply-block-hex` and `--compact` in `main`, and tests.
- `utxo-census-stats.json` has `tool_version` `ba2bf8c+iter3-20261109T123057Z`: `ba2bf8c` is an internal
  commit, `+iter3` marks changes on top of it that were not yet committed, and the rest is the start of the
  run, 2026-11-09 12:30:57 UTC. Against `ba2bf8c`, these files differ here: `btc-indexer/src/main.rs`, and
  `codec.rs`, `curve.rs`, `details.rs`, `lib.rs`, `main.rs` and `tests.rs` in `tools/utxo-census/src/`. The
  changes were committed together with the results; against that commit, only `btc-indexer/src/main.rs` and
  `tools/utxo-census/src/tests.rs` differ, and the census tool does not use `btc-indexer`.
- The three `utxo-census-audit-*` files come from an audit extension of `utxo-census` that is not included in
  this repository. The same run also wrote the census `stats.json`, which is not in this repository; it was
  identical to `utxo-census-stats.json` except for `tool_version`. The manifest is published unchanged: its
  `tool_version` `q11-b1+2ab29c2` labels that run, `2ab29c2` being an internal commit; the files it lists other
  than `other-keys.json` and `structural-keys.json` are not published, and the hashes it gives for those two
  match the files published here.
- `witness-program-histogram.json` was written by `tools/validation/witness-histogram.py`, a cross-check that
  reads the `dumptxoutset` file using only the Bitcoin Core serialization and shares no code with
  `utxo-census`. It was produced by the script before its documentation text was edited for publication; the
  code is the same, and on synthetic test snapshots both versions write byte-identical output.
