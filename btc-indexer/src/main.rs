use rayon::prelude::*;
use ripemd::Ripemd160;
use rustc_hash::{FxHashMap, FxHashSet};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut rmd = Ripemd160::new();
    rmd.update(sha);
    rmd.finalize().into()
}

pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compact_size(n: usize) -> Vec<u8> {
    if n < 253 {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![253];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xFFFF_FFFF {
        let mut v = vec![254];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![255];
        v.extend_from_slice(&(n as u64).to_le_bytes());
        v
    }
}

/// Validate SEC (33/65-byte, including 06/07 hybrid) or BIP340 x-only (32-byte) public key
/// and return its 32-byte x-coordinate.
pub fn key_x(key: &[u8], xonly: bool) -> Option<[u8; 32]> {
    if xonly {
        if key.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 33];
        buf[0] = 0x02;
        buf[1..33].copy_from_slice(key);
        if PublicKey::from_slice(&buf).is_ok() {
            let mut x = [0u8; 32];
            x.copy_from_slice(key);
            return Some(x);
        }
        return None;
    }

    match key.len() {
        33 => {
            if key[0] != 0x02 && key[0] != 0x03 {
                return None;
            }
            if PublicKey::from_slice(key).is_ok() {
                let mut x = [0u8; 32];
                x.copy_from_slice(&key[1..33]);
                Some(x)
            } else {
                None
            }
        }
        65 => {
            let prefix = key[0];
            if prefix != 0x04 && prefix != 0x06 && prefix != 0x07 {
                return None;
            }
            if prefix == 0x06 || prefix == 0x07 {
                let y_parity = key[64] & 1;
                if prefix != 0x06 + y_parity {
                    return None;
                }
            }
            let mut uncompressed = [0u8; 65];
            uncompressed.copy_from_slice(key);
            uncompressed[0] = 0x04;
            if PublicKey::from_slice(&uncompressed).is_ok() {
                let mut x = [0u8; 32];
                x.copy_from_slice(&key[1..33]);
                Some(x)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Subtract a 32-byte big-endian integer `y` from the secp256k1 field prime `P`.
#[inline]
fn negate_field_y(even_y: &[u8; 32]) -> [u8; 32] {
    const P: [u64; 4] = [
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];
    let y0 = u64::from_be_bytes(even_y[24..32].try_into().unwrap());
    let y1 = u64::from_be_bytes(even_y[16..24].try_into().unwrap());
    let y2 = u64::from_be_bytes(even_y[8..16].try_into().unwrap());
    let y3 = u64::from_be_bytes(even_y[0..8].try_into().unwrap());

    let (d0, b0) = P[0].overflowing_sub(y0);
    let (d1, b1) = P[1].overflowing_sub(y1);
    let (d1, b1b) = d1.overflowing_sub(b0 as u64);
    let (d2, b2) = P[2].overflowing_sub(y2);
    let (d2, b2b) = d2.overflowing_sub((b1 || b1b) as u64);
    let (d3, _) = P[3].overflowing_sub(y3);
    let (d3, _) = d3.overflowing_sub((b2 || b2b) as u64);

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&d3.to_be_bytes());
    out[8..16].copy_from_slice(&d2.to_be_bytes());
    out[16..24].copy_from_slice(&d1.to_be_bytes());
    out[24..32].copy_from_slice(&d0.to_be_bytes());
    out
}

/// Compute all 6 SEC encodings (2 compressed + 2 uncompressed + 2 hybrid) for a valid 32-byte x-coordinate.
/// Returns ([20B; 6] key_hashes, [20B; 6] wrapped_key_hashes).
pub fn key_hashes_from_x(x: &[u8; 32]) -> Option<([[u8; 20]; 6], [[u8; 20]; 6])> {
    let mut comp_even = [0u8; 33];
    comp_even[0] = 0x02;
    comp_even[1..33].copy_from_slice(x);
    let pk_even = PublicKey::from_slice(&comp_even).ok()?;
    let uncomp_even = pk_even.serialize_uncompressed(); // [0x04, x.., even_y..]

    let mut comp_odd = [0u8; 33];
    comp_odd[0] = 0x03;
    comp_odd[1..33].copy_from_slice(x);

    let even_y: &[u8; 32] = uncomp_even[33..65].try_into().unwrap();
    let odd_y = negate_field_y(even_y);

    let mut uncomp_odd = [0u8; 65];
    uncomp_odd[0] = 0x04;
    uncomp_odd[1..33].copy_from_slice(x);
    uncomp_odd[33..65].copy_from_slice(&odd_y);

    let mut hyb_even = uncomp_even;
    hyb_even[0] = 0x06;
    let mut hyb_odd = uncomp_odd;
    hyb_odd[0] = 0x07;

    let mut kh = [[0u8; 20]; 6];
    let mut wrapped = [[0u8; 20]; 6];

    let encodings: [&[u8]; 6] = [
        &comp_even,
        &comp_odd,
        &uncomp_even,
        &uncomp_odd,
        &hyb_even,
        &hyb_odd,
    ];

    for (i, enc) in encodings.iter().enumerate() {
        let h = hash160(enc);
        kh[i] = h;
        let mut redeem = [0u8; 22];
        redeem[0] = 0x00;
        redeem[1] = 0x14;
        redeem[2..22].copy_from_slice(&h);
        wrapped[i] = hash160(&redeem);
    }

    Some((kh, wrapped))
}

/// Fast candidate key extraction for bulk block scanning:
/// For 32-byte (when xonly=true) or 33-byte (0x02/0x03) keys, returns the 32-byte x-coordinate
/// without running the modular square root yet (Step 3 validates x on secp256k1 after deduplication!).
/// For 65-byte keys (0x04/0x06/0x07), validates that (x, y) is on the curve immediately.
#[inline]
fn fast_candidate_x(key: &[u8], xonly: bool) -> Option<[u8; 32]> {
    if xonly {
        if key.len() == 32 {
            let mut x = [0u8; 32];
            x.copy_from_slice(key);
            return Some(x);
        }
        return None;
    }
    match key.len() {
        33 if key[0] == 0x02 || key[0] == 0x03 => {
            let mut x = [0u8; 32];
            x.copy_from_slice(&key[1..33]);
            Some(x)
        }
        65 => key_x(key, false),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevealedLeaf {
    pub version: u8,
    pub script: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

pub fn leaf_hashes(leaf: &RevealedLeaf) -> Vec<[u8; 32]> {
    let mut leaf_data = Vec::with_capacity(1 + 5 + leaf.script.len());
    leaf_data.push(leaf.version);
    leaf_data.extend_from_slice(&compact_size(leaf.script.len()));
    leaf_data.extend_from_slice(&leaf.script);
    let mut h = tagged_hash(b"TapLeaf", &leaf_data);
    let mut res = Vec::with_capacity(1 + leaf.path.len());
    res.push(h);
    for sibling in &leaf.path {
        let mut branch_data = [0u8; 64];
        if h <= *sibling {
            branch_data[0..32].copy_from_slice(&h);
            branch_data[32..64].copy_from_slice(sibling);
        } else {
            branch_data[0..32].copy_from_slice(sibling);
            branch_data[32..64].copy_from_slice(&h);
        }
        h = tagged_hash(b"TapBranch", &branch_data);
        res.push(h);
    }
    res
}

/// Iterate script instructions `(opcode, Option<&[u8]>)`, stopping at any incomplete push.
pub struct Instructions<'a> {
    script: &'a [u8],
    pos: usize,
}

impl<'a> Instructions<'a> {
    pub fn new(script: &'a [u8]) -> Self {
        Self { script, pos: 0 }
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = (u8, Option<&'a [u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.script.len() {
            return None;
        }
        let op = self.script[self.pos];
        self.pos += 1;
        if op <= 78 {
            let size = if op < 76 {
                op as usize
            } else {
                let width = match op {
                    76 => 1,
                    77 => 2,
                    78 => 4,
                    _ => unreachable!(),
                };
                if self.pos + width > self.script.len() {
                    self.pos = self.script.len();
                    return None;
                }
                let mut buf = [0u8; 4];
                buf[..width].copy_from_slice(&self.script[self.pos..self.pos + width]);
                self.pos += width;
                u32::from_le_bytes(buf) as usize
            };
            if self.pos + size > self.script.len() {
                self.pos = self.script.len();
                return None;
            }
            let data = &self.script[self.pos..self.pos + size];
            self.pos += size;
            Some((op, Some(data)))
        } else {
            Some((op, None))
        }
    }
}

fn small_int(op: u8) -> Option<usize> {
    if op == 0 {
        Some(0)
    } else if (81..=96).contains(&op) {
        Some((op - 80) as usize)
    } else {
        None
    }
}

fn witness_program(script: &[u8]) -> Option<(usize, &[u8])> {
    if (4..=42).contains(&script.len()) {
        if let Some(version) = small_int(script[0]) {
            if script[1] as usize == script.len() - 2 {
                return Some((version, &script[2..]));
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognized<'a> {
    Unclassified,
    Unknown,
    P2PK(&'a [u8]),
    Multisig { required: usize, keys: Vec<&'a [u8]> },
    P2PKH([u8; 20]),
    P2WPKH([u8; 20]),
    P2SH([u8; 20]),
    P2WSH([u8; 32]),
    P2TR(&'a [u8]),
    P2MR([u8; 32]),
}

pub fn recognize(script: &[u8], bip360_active: bool) -> Recognized<'_> {
    if script.starts_with(&[0x6a]) {
        return Recognized::Unclassified;
    }
    if let Some((version, program)) = witness_program(script) {
        if version == 0 {
            if program.len() == 20 {
                let mut h = [0u8; 20];
                h.copy_from_slice(program);
                return Recognized::P2WPKH(h);
            } else if program.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(program);
                return Recognized::P2WSH(h);
            } else {
                return Recognized::Unclassified;
            }
        }
        if version == 1 && program.len() == 32 {
            return Recognized::P2TR(program);
        }
        if version == 2 && program.len() == 32 && bip360_active {
            let mut h = [0u8; 32];
            h.copy_from_slice(program);
            return Recognized::P2MR(h);
        }
        return Recognized::Unknown;
    }
    if script.len() == 25 && &script[0..3] == b"\x76\xa9\x14" && &script[23..25] == b"\x88\xac" {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        return Recognized::P2PKH(h);
    }
    if script.len() == 23 && &script[0..2] == b"\xa9\x14" && script[22] == 0x87 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[2..22]);
        return Recognized::P2SH(h);
    }

    let ops: Vec<(u8, Option<&[u8]>)> = Instructions::new(script).collect();
    let decoded_size: usize = ops
        .iter()
        .map(|(op, data)| {
            1 + data.map_or(0, |d| d.len())
                + match op {
                    76 => 1,
                    77 => 2,
                    78 => 4,
                    _ => 0,
                }
        })
        .sum();
    if decoded_size != script.len() {
        return Recognized::Unknown;
    }
    if script.ends_with(&[0xac]) && ops.len() == 2 && ops[1] == (172, None) {
        if let Some(key) = ops[0].1 {
            if key.len() == 33 || key.len() == 65 {
                return Recognized::P2PK(key);
            }
        }
    }
    if script.ends_with(&[0xae]) && ops.len() >= 3 && ops[ops.len() - 1] == (174, None) {
        if let (Some(m), Some(n)) = (small_int(ops[0].0), small_int(ops[ops.len() - 2].0)) {
            let key_ops = &ops[1..ops.len() - 2];
            if m <= n
                && n == key_ops.len()
                && key_ops
                    .iter()
                    .all(|(_, d)| d.map_or(false, |k| k.len() == 33 || k.len() == 65))
            {
                let keys = key_ops.iter().map(|(_, d)| d.unwrap()).collect();
                return Recognized::Multisig { required: m, keys };
            }
        }
    }
    Recognized::Unknown
}

pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        if size > self.data.len() - self.pos {
            return None;
        }
        let s = &self.data[self.pos..self.pos + size];
        self.pos += size;
        Some(s)
    }

    pub fn count(&mut self) -> Option<usize> {
        let first = self.take(1)?[0];
        if first < 253 {
            return Some(first as usize);
        }
        let (width, low): (usize, u64) = match first {
            253 => (2, 253),
            254 => (4, 0x10000),
            255 => (8, 0x1_0000_0000),
            _ => unreachable!(),
        };
        let bytes = self.take(width)?;
        let mut buf = [0u8; 8];
        buf[..width].copy_from_slice(bytes);
        let value = u64::from_le_bytes(buf);
        if value < low {
            return None;
        }
        Some(value as usize)
    }

    pub fn vector(&mut self) -> Option<&'a [u8]> {
        let n = self.count()?;
        self.take(n)
    }
}

pub struct ParsedTx<'a> {
    pub inputs: Vec<(bool, &'a [u8])>, // (is_coinbase, script_sig)
    pub outputs: Vec<&'a [u8]>,
    pub witnesses: Vec<Vec<&'a [u8]>>,
}

fn capped_capacity(count: usize, remaining: usize) -> usize {
    count.min(remaining)
}

pub fn parse_transaction_from_reader<'a>(r: &mut Reader<'a>) -> Option<ParsedTx<'a>> {
    r.take(4)?; // version
    let mut segwit = false;
    if r.data.len() - r.pos >= 2 && r.data[r.pos..r.pos + 2] == [0x00, 0x01] {
        r.take(2)?;
        segwit = true;
    }
    let in_count = r.count()?;
    if in_count == 0 {
        return None;
    }
    let mut inputs = Vec::with_capacity(capped_capacity(in_count, r.data.len() - r.pos));
    for _ in 0..in_count {
        let prev = r.take(36)?;
        let is_cb = prev[0..32] == [0u8; 32] && prev[32..36] == [0xff; 4];
        let script = r.vector()?;
        r.take(4)?; // sequence
        inputs.push((is_cb, script));
    }
    let out_count = r.count()?;
    let mut outputs = Vec::with_capacity(capped_capacity(out_count, r.data.len() - r.pos));
    for _ in 0..out_count {
        r.take(8)?; // value
        outputs.push(r.vector()?);
    }
    let mut witnesses = vec![Vec::new(); inputs.len()];
    if segwit {
        let mut any_nonempty = false;
        for w in &mut witnesses {
            let wc = r.count()?;
            if wc > 0 {
                any_nonempty = true;
            }
            let mut items = Vec::with_capacity(capped_capacity(wc, r.data.len() - r.pos));
            for _ in 0..wc {
                items.push(r.vector()?);
            }
            *w = items;
        }
        if !any_nonempty {
            return None;
        }
    }
    r.take(4)?; // locktime
    Some(ParsedTx {
        inputs,
        outputs,
        witnesses,
    })
}

pub fn parse_single_transaction(tx: &[u8]) -> Option<ParsedTx<'_>> {
    let mut r = Reader::new(tx);
    let parsed = parse_transaction_from_reader(&mut r)?;
    if r.pos != tx.len() {
        return None;
    }
    Some(parsed)
}

#[derive(Clone, Debug, Default)]
pub struct ChainEvidence {
    pub published_keys: FxHashSet<[u8; 32]>,
    pub revealed_scripts: FxHashSet<Vec<u8>>,
    pub revealed_leaves: Vec<RevealedLeaf>,
    pub own_spend_count: Option<i64>,
    pub complete: bool,
    pub bip360_active: bool,
    pub p2sh_matches: FxHashSet<[u8; 20]>,
    pub p2wsh_matches: FxHashSet<[u8; 32]>,
    pub p2mr_matches: FxHashSet<[u8; 32]>,
    pub key_hashes: FxHashSet<[u8; 20]>,
    pub wrapped_key_hashes: FxHashSet<[u8; 20]>,
}

impl ChainEvidence {
    pub fn build(
        raw_keys: &[Vec<u8>],
        revealed_scripts: &[Vec<u8>],
        revealed_leaves: &[RevealedLeaf],
        own_spend_count: Option<i64>,
        complete: bool,
        bip360_active: bool,
    ) -> Self {
        let mut xs = FxHashSet::default();
        for k in raw_keys {
            let xonly = k.len() == 32;
            if let Some(x) = key_x(k, xonly) {
                xs.insert(x);
            }
        }
        Self::from_extracted(
            xs,
            revealed_scripts.iter().cloned().collect(),
            revealed_leaves.to_vec(),
            own_spend_count,
            complete,
            bip360_active,
        )
    }

    pub fn from_extracted(
        xs: FxHashSet<[u8; 32]>,
        scripts: FxHashSet<Vec<u8>>,
        leaves: Vec<RevealedLeaf>,
        own_spend_count: Option<i64>,
        complete: bool,
        bip360_active: bool,
    ) -> Self {
        let mut all_scripts: FxHashSet<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
        for l in &leaves {
            all_scripts.insert(l.script.as_slice());
        }
        let mut p2sh_matches = FxHashSet::default();
        let mut p2wsh_matches = FxHashSet::default();
        let mut p2mr_matches = FxHashSet::default();
        let mut key_hashes = FxHashSet::default();
        let mut wrapped_key_hashes = FxHashSet::default();

        for s in all_scripts {
            let digest = sha256(s);
            p2sh_matches.insert(hash160(s));
            let mut w = [0u8; 34];
            w[0] = 0x00;
            w[1] = 0x20;
            w[2..34].copy_from_slice(&digest);
            p2sh_matches.insert(hash160(&w));
            p2wsh_matches.insert(digest);
        }
        for leaf in &leaves {
            for h in leaf_hashes(leaf) {
                p2mr_matches.insert(h);
            }
        }
        for x in &xs {
            if let Some((kh, wrapped)) = key_hashes_from_x(x) {
                for h in kh {
                    key_hashes.insert(h);
                }
                for w in wrapped {
                    wrapped_key_hashes.insert(w);
                }
            }
        }

        Self {
            published_keys: xs,
            revealed_scripts: scripts,
            revealed_leaves: leaves,
            own_spend_count,
            complete,
            bip360_active,
            p2sh_matches,
            p2wsh_matches,
            p2mr_matches,
            key_hashes,
            wrapped_key_hashes,
        }
    }
}

pub fn classify(script: &[u8], ev: &ChainEvidence) -> Option<&'static str> {
    match recognize(script, ev.bip360_active) {
        Recognized::Unclassified => None,
        Recognized::Unknown => Some("UNDETERMINED"),
        Recognized::P2PK(k) => {
            if key_x(k, false).is_some() {
                Some("EXPOSED_AT_REST")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::P2TR(k) => {
            if key_x(k, true).is_some() {
                Some("EXPOSED_AT_REST")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::Multisig { required, keys } => {
            let valid = keys.iter().filter(|k| key_x(k, false).is_some()).count();
            if valid >= required {
                Some("EXPOSED_AT_REST")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::P2SH(h) => {
            if ev.p2sh_matches.contains(&h) || ev.wrapped_key_hashes.contains(&h) {
                Some("EXPOSED_AT_REST")
            } else if ev.own_spend_count.unwrap_or(0) > 0 {
                Some("EXPOSED_AT_REST")
            } else if ev.complete {
                Some("EXPOSED_ON_SPEND")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::P2WSH(h) => {
            if ev.p2wsh_matches.contains(&h) {
                Some("EXPOSED_AT_REST")
            } else if ev.own_spend_count.unwrap_or(0) > 0 {
                Some("EXPOSED_AT_REST")
            } else if ev.complete {
                Some("EXPOSED_ON_SPEND")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::P2MR(h) => {
            if ev.p2mr_matches.contains(&h) {
                Some("EXPOSED_AT_REST")
            } else if ev.own_spend_count.unwrap_or(0) > 0 {
                Some("EXPOSED_AT_REST")
            } else if ev.complete {
                Some("EXPOSED_ON_SPEND")
            } else {
                Some("UNDETERMINED")
            }
        }
        Recognized::P2PKH(h) | Recognized::P2WPKH(h) => {
            if ev.key_hashes.contains(&h) {
                Some("EXPOSED_AT_REST")
            } else if ev.own_spend_count.unwrap_or(0) > 0 {
                Some("EXPOSED_AT_REST")
            } else if ev.complete {
                Some("EXPOSED_ON_SPEND")
            } else {
                Some("UNDETERMINED")
            }
        }
    }
}

pub fn extract_evidence(
    tx: &[u8],
    prevout_scripts: &[Option<Vec<u8>>],
    bip360_active: bool,
    taproot_active: bool,
    bip16_active: bool,
) -> Option<ChainEvidence> {
    let parsed = parse_single_transaction(tx)?;
    if prevout_scripts.len() != parsed.inputs.len() {
        return None;
    }
    let mut keys = FxHashSet::default();
    let mut scripts = FxHashSet::default();
    let mut leaves = Vec::new();

    let mut publish = |data: &[u8], xonly: bool| {
        if let Some(x) = key_x(data, xonly) {
            keys.insert(x);
        }
    };

    let scan = |script: &[u8], publish: &mut dyn FnMut(&[u8], bool)| {
        for (_, data) in Instructions::new(script) {
            if let Some(d) = data {
                publish(d, false);
            }
        }
    };

    for output in &parsed.outputs {
        scan(output, &mut publish);
        if let Recognized::P2TR(prog) = recognize(output, false) {
            publish(prog, true);
        }
    }

    for (((coinbase, script_sig), witness), prevout) in parsed
        .inputs
        .iter()
        .zip(parsed.witnesses.iter())
        .zip(prevout_scripts.iter())
    {
        scan(script_sig, &mut publish);
        for elem in witness {
            publish(elem, false);
        }
        if *coinbase {
            continue;
        }
        let prev = prevout.as_deref().unwrap_or(&[]);
        match recognize(prev, bip360_active) {
            Recognized::P2SH(_) if bip16_active => {
                let pushes: Vec<&[u8]> = Instructions::new(script_sig)
                    .filter_map(|(_, d)| d)
                    .collect();
                if let Some(&redeem) = pushes.last() {
                    scripts.insert(redeem.to_vec());
                    scan(redeem, &mut publish);
                    if let Recognized::P2WSH(_) = recognize(redeem, false) {
                        if let Some(&wscript) = witness.last() {
                            scripts.insert(wscript.to_vec());
                            scan(wscript, &mut publish);
                        }
                    }
                }
            }
            Recognized::P2WSH(_) => {
                if let Some(&wscript) = witness.last() {
                    scripts.insert(wscript.to_vec());
                    scan(wscript, &mut publish);
                }
            }
            Recognized::P2MR(_) => {
                extract_tap_or_mr_leaf(witness, false, &mut publish, &scan, &mut leaves);
            }
            Recognized::P2TR(_) if taproot_active => {
                extract_tap_or_mr_leaf(witness, true, &mut publish, &scan, &mut leaves);
            }
            _ => {}
        }
    }

    Some(ChainEvidence::from_extracted(
        keys,
        scripts,
        leaves,
        None,
        false,
        bip360_active,
    ))
}

fn extract_tap_or_mr_leaf(
    witness: &[&[u8]],
    is_p2tr: bool,
    publish: &mut dyn FnMut(&[u8], bool),
    scan: &dyn Fn(&[u8], &mut dyn FnMut(&[u8], bool)),
    leaves: &mut Vec<RevealedLeaf>,
) {
    let mut stack = witness;
    if stack.len() >= 2 && stack.last().unwrap().starts_with(&[0x50]) {
        stack = &stack[..stack.len() - 1];
    }
    if stack.len() < 2 {
        return;
    }
    let script = stack[stack.len() - 2];
    let control = stack[stack.len() - 1];
    let base = if is_p2tr { 33 } else { 1 };
    if control.len() < base || (control.len() - base) % 32 != 0 {
        return;
    }
    if (control.len() - base) / 32 > 128 {
        return;
    }
    if !is_p2tr && (control[0] & 1) == 0 {
        return;
    }
    if is_p2tr {
        publish(&control[1..33], true);
    }
    let mut path = Vec::with_capacity((control.len() - base) / 32);
    for i in (base..control.len()).step_by(32) {
        let mut h = [0u8; 32];
        h.copy_from_slice(&control[i..i + 32]);
        path.push(h);
    }
    let version = control[0] & 254;
    let leaf = RevealedLeaf {
        version,
        script: script.to_vec(),
        path,
    };
    leaves.push(leaf);
    scan(script, publish);
    if version == 192 {
        let ops: Vec<(u8, Option<&[u8]>)> = Instructions::new(script).collect();
        for w in ops.windows(2) {
            if let Some(data) = w[0].1 {
                if matches!(w[1].0, 172 | 173 | 186) {
                    publish(data, true);
                }
            }
        }
    }
}

// --- JSON Test Vector Runner ---

#[derive(Deserialize)]
struct RawLeaf {
    version: u8,
    script: String,
    #[serde(default)]
    path: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RawEvidence {
    #[serde(default)]
    published_keys: Vec<String>,
    #[serde(default)]
    revealed_scripts: Vec<String>,
    #[serde(default)]
    revealed_leaves: Vec<RawLeaf>,
    own_spend_count: Option<i64>,
    #[serde(default)]
    complete: bool,
    #[serde(default)]
    bip360_active: bool,
}

#[derive(Deserialize)]
struct TargetClassification {
    script_pubkey: String,
    expected: Option<String>,
}

#[derive(Deserialize)]
struct VectorItem {
    id: String,
    script_pubkey: String,
    evidence: RawEvidence,
    expected: Option<String>,
    #[serde(default)]
    classifications: Vec<TargetClassification>,
}

#[derive(Deserialize)]
struct ExtractionVectorItem {
    id: String,
    tx: String,
    prevout_scripts: Vec<Option<String>>,
    #[serde(default)]
    bip360_active: bool,
    #[serde(default = "default_true")]
    taproot_active: bool,
    #[serde(default = "default_true")]
    bip16_active: bool,
    expected_evidence: RawEvidence,
    #[serde(default)]
    classification_complete: bool,
    #[serde(default)]
    classifications: Vec<TargetClassification>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct TestVectorsFile {
    script_vectors: Vec<VectorItem>,
    history_vectors: Vec<VectorItem>,
    classification_vectors: Vec<VectorItem>,
    extraction_vectors: Vec<ExtractionVectorItem>,
}

fn build_evidence_from_raw(raw: &RawEvidence) -> ChainEvidence {
    let keys: Vec<Vec<u8>> = raw
        .published_keys
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect();
    let scripts: Vec<Vec<u8>> = raw
        .revealed_scripts
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect();
    let leaves: Vec<RevealedLeaf> = raw
        .revealed_leaves
        .iter()
        .map(|l| RevealedLeaf {
            version: l.version,
            script: hex::decode(&l.script).unwrap(),
            path: l
                .path
                .iter()
                .map(|p| {
                    let b = hex::decode(p).unwrap();
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                })
                .collect(),
        })
        .collect();
    ChainEvidence::build(
        &keys,
        &scripts,
        &leaves,
        raw.own_spend_count,
        raw.complete,
        raw.bip360_active,
    )
}

fn run_self_test(json_path: &str) {
    let content = fs::read_to_string(json_path).expect("Failed to read test_vectors_070.json");
    let tv: TestVectorsFile = serde_json::from_str(&content).expect("Failed to parse JSON");

    let mut total = 0;
    for group in [
        &tv.script_vectors,
        &tv.history_vectors,
        &tv.classification_vectors,
    ] {
        for v in group {
            let ev = build_evidence_from_raw(&v.evidence);
            let spk = hex::decode(&v.script_pubkey).unwrap();
            let actual = classify(&spk, &ev).map(|s| s.to_string());
            assert_eq!(actual, v.expected, "Vector {} failed", v.id);
            for t in &v.classifications {
                let tspk = hex::decode(&t.script_pubkey).unwrap();
                let tactual = classify(&tspk, &ev).map(|s| s.to_string());
                assert_eq!(tactual, t.expected, "Target in {} failed", v.id);
            }
            total += 1;
        }
    }

    for v in &tv.extraction_vectors {
        let tx = hex::decode(&v.tx).unwrap();
        let prevs: Vec<Option<Vec<u8>>> = v
            .prevout_scripts
            .iter()
            .map(|opt| opt.as_ref().map(|s| hex::decode(s).unwrap()))
            .collect();
        let mut extracted = extract_evidence(
            &tx,
            &prevs,
            v.bip360_active,
            v.taproot_active,
            v.bip16_active,
        )
        .expect(&format!("Extraction failed on {}", v.id));
        let expected = build_evidence_from_raw(&v.expected_evidence);
        assert_eq!(
            extracted.published_keys, expected.published_keys,
            "{}: published_keys mismatch",
            v.id
        );
        assert_eq!(
            extracted.revealed_scripts, expected.revealed_scripts,
            "{}: revealed_scripts mismatch",
            v.id
        );
        assert_eq!(
            extracted.revealed_leaves, expected.revealed_leaves,
            "{}: revealed_leaves mismatch",
            v.id
        );

        if v.classification_complete {
            extracted.complete = true;
        }
        for t in &v.classifications {
            let tspk = hex::decode(&t.script_pubkey).unwrap();
            let tactual = classify(&tspk, &extracted).map(|s| s.to_string());
            assert_eq!(tactual, t.expected, "Extraction target in {} failed", v.id);
        }
        total += 1;
    }

    println!(
        "PASS: All {} test vectors ({} script, {} history, {} classification, {} extraction) verified 100%!",
        total,
        tv.script_vectors.len(),
        tv.history_vectors.len(),
        tv.classification_vectors.len(),
        tv.extraction_vectors.len()
    );
}

// --- Full-Chain Block Scanner & Index Builder ---

struct FundedBloom {
    words: Vec<std::sync::atomic::AtomicU64>,
}

impl FundedBloom {
    // 2^28 u64 words = 2^34 bits = 17,179,869,184 bits = 2.0 GiB RAM
    fn new() -> Self {
        let n = 1usize << 28;
        let mut words = Vec::with_capacity(n);
        words.resize_with(n, || std::sync::atomic::AtomicU64::new(0));
        Self { words }
    }

    #[inline]
    fn indices(h: &[u8; 20]) -> [usize; 4] {
        let w0 = u64::from_le_bytes(h[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(h[4..12].try_into().unwrap());
        let w2 = u64::from_le_bytes(h[8..16].try_into().unwrap());
        let w3 = u64::from_le_bytes(h[12..20].try_into().unwrap());
        [
            (w0 & 0x3_FFFF_FFFF) as usize,
            (w1 & 0x3_FFFF_FFFF) as usize,
            (w2 & 0x3_FFFF_FFFF) as usize,
            (w3 & 0x3_FFFF_FFFF) as usize,
        ]
    }

    #[inline]
    fn insert(&self, h: &[u8; 20]) {
        for bit_idx in Self::indices(h) {
            let word = bit_idx >> 6;
            let mask = 1u64 << (bit_idx & 63);
            self.words[word].fetch_or(mask, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[inline]
    fn may_contain(&self, h: &[u8; 20]) -> bool {
        for bit_idx in Self::indices(h) {
            let word = bit_idx >> 6;
            let mask = 1u64 << (bit_idx & 63);
            if (self.words[word].load(std::sync::atomic::Ordering::Relaxed) & mask) == 0 {
                return false;
            }
        }
        true
    }
}

#[derive(Debug)]
struct CensusRow {
    p2pk: bool,
    p2pkh: bool,
    p2wpkh: bool,
    p2sh_p2wpkh: bool,
    script_types: u8,
    any_form: bool,
    comp: bool,
    uncomp: bool,
    comp_and_uncomp_p2pkh: bool,
    hybrid: bool,
    key_position: bool,
    only_p2tr: bool,
    only_output_push: bool,
}

fn census_row(hits: u16, fl: u8) -> CensusRow {
    let p2pk = (fl & 4) != 0;
    let p2pkh = (hits & 0x003F) != 0;
    let p2wpkh = (hits & 0x0FC0) != 0;
    let p2sh_p2wpkh = (hits & 0x1000) != 0;
    CensusRow {
        p2pk,
        p2pkh,
        p2wpkh,
        p2sh_p2wpkh,
        script_types: p2pk as u8 + p2pkh as u8 + p2wpkh as u8 + p2sh_p2wpkh as u8,
        any_form: hits != 0 || p2pk,
        comp: (hits & 0x00C3) != 0,
        uncomp: (hits & 0x030C) != 0,
        comp_and_uncomp_p2pkh: (hits & 0x0003) != 0 && (hits & 0x000C) != 0,
        hybrid: (hits & 0x0C30) != 0,
        key_position: (fl & 32) != 0,
        only_p2tr: (fl & 8) != 0 && (fl & (4 | 16 | 32)) == 0,
        only_output_push: (fl & 16) != 0 && (fl & (4 | 8 | 32)) == 0,
    }
}

#[derive(Default, Serialize)]
struct Census {
    published_x_total: usize,
    published_x_in_key_position: usize,
    published_x_only_as_p2tr_output_key: usize,
    published_x_only_in_unrecognized_output_push: usize,
    keys_funded_p2pk: usize,
    keys_funded_p2pkh: usize,
    keys_funded_p2wpkh: usize,
    keys_funded_p2sh_p2wpkh: usize,
    keys_funded_p2pk_and_p2pkh: usize,
    keys_funded_p2pk_and_p2wpkh: usize,
    keys_funded_p2pk_and_p2sh_p2wpkh: usize,
    keys_funded_p2pkh_and_p2wpkh: usize,
    keys_funded_p2pkh_and_p2sh_p2wpkh: usize,
    keys_funded_p2wpkh_and_p2sh_p2wpkh: usize,
    keys_funded_in_2plus_script_types: usize,
    keys_funded_in_3plus_script_types: usize,
    keys_funded_in_any_form: usize,
    keys_comp_and_uncomp_any_type: usize,
    keys_comp_and_uncomp_p2pkh_only: usize,
    keys_hybrid_encoding_funded: usize,
    funded_hash20_total: usize,
    funded_hash20_p2pkh: usize,
    funded_hash20_p2wpkh: usize,
    funded_hash20_p2sh: usize,
    funded_hash32_p2wsh: Option<usize>,
    funded_hash32_p2wsh_note: Option<&'static str>,
}

impl Census {
    fn record_row(&mut self, row: &CensusRow) {
        self.published_x_total += 1;
        self.published_x_in_key_position += row.key_position as usize;
        self.published_x_only_as_p2tr_output_key += row.only_p2tr as usize;
        self.published_x_only_in_unrecognized_output_push += row.only_output_push as usize;
        self.keys_funded_p2pk += row.p2pk as usize;
        self.keys_funded_p2pkh += row.p2pkh as usize;
        self.keys_funded_p2wpkh += row.p2wpkh as usize;
        self.keys_funded_p2sh_p2wpkh += row.p2sh_p2wpkh as usize;
        self.keys_funded_p2pk_and_p2pkh += (row.p2pk && row.p2pkh) as usize;
        self.keys_funded_p2pk_and_p2wpkh += (row.p2pk && row.p2wpkh) as usize;
        self.keys_funded_p2pk_and_p2sh_p2wpkh += (row.p2pk && row.p2sh_p2wpkh) as usize;
        self.keys_funded_p2pkh_and_p2wpkh += (row.p2pkh && row.p2wpkh) as usize;
        self.keys_funded_p2pkh_and_p2sh_p2wpkh += (row.p2pkh && row.p2sh_p2wpkh) as usize;
        self.keys_funded_p2wpkh_and_p2sh_p2wpkh += (row.p2wpkh && row.p2sh_p2wpkh) as usize;
        self.keys_funded_in_2plus_script_types += (row.script_types >= 2) as usize;
        self.keys_funded_in_3plus_script_types += (row.script_types >= 3) as usize;
        self.keys_funded_in_any_form += row.any_form as usize;
        self.keys_comp_and_uncomp_any_type += (row.comp && row.uncomp) as usize;
        self.keys_comp_and_uncomp_p2pkh_only += row.comp_and_uncomp_p2pkh as usize;
        self.keys_hybrid_encoding_funded += row.hybrid as usize;
    }

    fn record_hash20(&mut self, mask: u8) {
        self.funded_hash20_total += ((mask & 7) != 0) as usize;
        self.funded_hash20_p2pkh += ((mask & 1) != 0) as usize;
        self.funded_hash20_p2wpkh += ((mask & 2) != 0) as usize;
        self.funded_hash20_p2sh += ((mask & 4) != 0) as usize;
    }
}

#[cfg(test)]
mod census_tests {
    use super::{census_row, Census};

    fn count(hits: u16, flags: u8) -> Census {
        let mut census = Census::default();
        census.record_row(&census_row(hits, flags));
        census
    }

    #[test]
    fn p2pk_only_is_funded_without_hash_hits() {
        let c = count(0, 1 | 2 | 4 | 16 | 32);
        assert_eq!(c.published_x_total, 1);
        assert_eq!(c.published_x_in_key_position, 1);
        assert_eq!(c.keys_funded_p2pk, 1);
        assert_eq!(c.keys_funded_in_any_form, 1);
        assert_eq!(c.keys_funded_in_2plus_script_types, 0);
        assert_eq!(c.keys_funded_p2pk_and_p2pkh, 0);
    }

    #[test]
    fn compressed_p2pkh_and_p2wpkh_are_two_types() {
        let c = count((1 << 0) | (1 << 6), 32);
        assert_eq!(c.keys_funded_p2pkh, 1);
        assert_eq!(c.keys_funded_p2wpkh, 1);
        assert_eq!(c.keys_funded_p2pkh_and_p2wpkh, 1);
        assert_eq!(c.keys_funded_in_2plus_script_types, 1);
        assert_eq!(c.keys_funded_in_3plus_script_types, 0);
        assert_eq!(c.keys_comp_and_uncomp_any_type, 0);
    }

    #[test]
    fn two_p2pkh_encodings_are_one_type() {
        let c = count((1 << 0) | (1 << 2), 32);
        assert_eq!(c.keys_comp_and_uncomp_p2pkh_only, 1);
        assert_eq!(c.keys_comp_and_uncomp_any_type, 1);
        assert_eq!(c.keys_funded_in_2plus_script_types, 0);
        assert_eq!(c.keys_hybrid_encoding_funded, 0);
    }

    #[test]
    fn wrapped_only_is_funded_without_encoding_evidence() {
        let c = count(1 << 12, 32);
        assert_eq!(c.keys_funded_p2sh_p2wpkh, 1);
        assert_eq!(c.keys_funded_p2pkh, 0);
        assert_eq!(c.keys_funded_p2wpkh, 0);
        assert_eq!(c.keys_funded_in_any_form, 1);
        assert_eq!(c.keys_funded_in_2plus_script_types, 0);
        let row = census_row(1 << 12, 32);
        assert!(!row.comp && !row.uncomp && !row.hybrid);
    }

    #[test]
    fn p2tr_only_provenance() {
        let c = count(0, 8);
        assert_eq!(c.published_x_only_as_p2tr_output_key, 1);
        assert_eq!(c.published_x_in_key_position, 0);
        assert_eq!(c.keys_funded_in_any_form, 0);
        for other in [4, 16, 32] {
            assert!(!census_row(0, 8 | other).only_p2tr);
        }
    }

    #[test]
    fn unrecognized_output_push_only_provenance() {
        let c = count(0, 16);
        assert_eq!(c.published_x_only_in_unrecognized_output_push, 1);
        assert_eq!(c.published_x_in_key_position, 0);
        assert_eq!(c.keys_funded_in_any_form, 0);
        for other in [4, 8, 32] {
            assert!(!census_row(0, 16 | other).only_output_push);
        }
    }

    #[test]
    fn bare_multisig_is_a_key_position_not_p2pk() {
        for flags in [32, 1 | 2 | 16 | 32] {
            let c = count(0, flags);
            assert_eq!(c.published_x_in_key_position, 1);
            assert_eq!(c.keys_funded_p2pk, 0);
            assert_eq!(c.keys_funded_in_any_form, 0);
            assert_eq!(c.published_x_only_in_unrecognized_output_push, 0);
        }
    }

    #[test]
    fn all_script_type_combinations_and_pairs() {
        for mask in 0u8..16 {
            let p = (mask & 1) != 0;
            let h = (mask & 2) != 0;
            let w = (mask & 4) != 0;
            let s = (mask & 8) != 0;
            let hits = (h as u16) | ((w as u16) << 6) | ((s as u16) << 12);
            let c = count(hits, if p { 4 } else { 0 });
            assert_eq!(c.keys_funded_p2pk_and_p2pkh, (p && h) as usize);
            assert_eq!(c.keys_funded_p2pk_and_p2wpkh, (p && w) as usize);
            assert_eq!(c.keys_funded_p2pk_and_p2sh_p2wpkh, (p && s) as usize);
            assert_eq!(c.keys_funded_p2pkh_and_p2wpkh, (h && w) as usize);
            assert_eq!(c.keys_funded_p2pkh_and_p2sh_p2wpkh, (h && s) as usize);
            assert_eq!(c.keys_funded_p2wpkh_and_p2sh_p2wpkh, (w && s) as usize);
            assert_eq!(c.keys_funded_in_2plus_script_types, (mask.count_ones() >= 2) as usize);
            assert_eq!(c.keys_funded_in_3plus_script_types, (mask.count_ones() >= 3) as usize);
            assert_eq!(c.keys_funded_in_any_form, (mask != 0) as usize);
        }
    }

    #[test]
    fn every_encoding_bit_has_the_expected_classification() {
        for bit in 0..13 {
            let row = census_row(1 << bit, 0);
            assert_eq!(row.comp, matches!(bit, 0 | 1 | 6 | 7));
            assert_eq!(row.uncomp, matches!(bit, 2 | 3 | 8 | 9));
            assert_eq!(row.hybrid, matches!(bit, 4 | 5 | 10 | 11));
            assert_eq!(row.p2pkh, bit < 6);
            assert_eq!(row.p2wpkh, (6..12).contains(&bit));
            assert_eq!(row.p2sh_p2wpkh, bit == 12);
        }
        assert!(!census_row((1 << 0) | (1 << 8), 0).comp_and_uncomp_p2pkh);
    }

    #[test]
    fn legacy_reuse_predicates_are_unchanged_for_every_bitmap() {
        for hits in 0u16..=0x1FFF {
            for fl in 0u8..64 {
                let row = census_row(hits, fl);
                let pkh = (hits & 0b0000_0000_0011_1111) != 0;
                let wpkh = (hits & 0b0000_1111_1100_0000) != 0;
                let comp = (hits & 0b0000_0000_1100_0011) != 0;
                let uncomp = (hits & 0b0000_0011_0000_1100) != 0;
                assert_eq!(row.p2pk && row.p2pkh, hits != 0 && pkh && (fl & 4) != 0);
                assert_eq!(row.p2pkh && row.p2wpkh, hits != 0 && pkh && wpkh);
                assert_eq!(row.comp && row.uncomp, hits != 0 && comp && uncomp);
            }
        }
    }

    #[test]
    fn funded_hash20_counts_overlapping_types_and_ignores_reveal_bits() {
        let mut c = Census::default();
        for mask in [1, 2, 4, 7, 8 | 16, 1 | 8 | 16] {
            c.record_hash20(mask);
        }
        assert_eq!(c.funded_hash20_total, 5);
        assert_eq!(c.funded_hash20_p2pkh, 3);
        assert_eq!(c.funded_hash20_p2wpkh, 2);
        assert_eq!(c.funded_hash20_p2sh, 2);
    }

    #[test]
    fn unavailable_hash32_count_serializes_as_null() {
        let c = Census {
            funded_hash32_p2wsh_note: Some("Unavailable: H32 reduction skipped on resume."),
            ..Census::default()
        };
        let json = serde_json::to_value(&c).unwrap();
        assert!(json["funded_hash32_p2wsh"].is_null());
        assert!(json["funded_hash32_p2wsh_note"].as_str().unwrap().contains("resume"));
    }
}

/// Bitflags for output types that funded a given 20-byte HASH160 on chain:
/// bit 0 (1): P2PKH
/// bit 1 (2): P2WPKH
/// bit 2 (4): P2SH
fn scan_blocks_dir(blocks_dir: &str, out_dir: &str) {
    let t0 = Instant::now();
    let mut blk_files: Vec<PathBuf> = fs::read_dir(blocks_dir)
        .expect("Cannot read blocks dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |s| s.starts_with("blk") && s.ends_with(".dat"))
        })
        .collect();
    blk_files.sort();

    let out_path = Path::new(out_dir);
    let shard_dir = out_path.join("shards");
    fs::create_dir_all(&shard_dir).unwrap();
    fs::create_dir_all(out_dir).unwrap();

    // Clean up any partial candidate or matched files from a previous interrupted run
    for i in 0..64 {
        let _ = fs::remove_file(shard_dir.join(format!("cand_{:02}.bin", i)));
        let _ = fs::remove_file(shard_dir.join(format!("matched_{:02}.bin", i)));
    }

    let have_h20 = (0..64).all(|i| {
        shard_dir
            .join(format!("h20_{:02}.bin", i))
            .metadata()
            .map(|m| m.len() > 0 && m.len() % 21 == 0)
            .unwrap_or(false)
    });
    let have_funded = (0..64).all(|i| {
        shard_dir
            .join(format!("funded_{:02}.bin", i))
            .metadata()
            .map(|m| m.len() > 0 && m.len() % 21 == 0)
            .unwrap_or(false)
    });
    let have_h32 = (0..16).all(|i| {
        shard_dir
            .join(format!("h32_{:02}.bin", i))
            .metadata()
            .map(|m| m.len() > 0 && m.len() % 33 == 0)
            .unwrap_or(false)
    });
    let have_done_h32 = out_path
        .join("script_hash_index_32.bin")
        .metadata()
        .map(|m| m.len() > 0 && m.len() % 32 == 0)
        .unwrap_or(false)
        && out_path
            .join("cross_format_diff_32.bin")
            .metadata()
            .map(|m| m.len() % 32 == 0)
            .unwrap_or(false);
    let have_x: [bool; 64] = std::array::from_fn(|i| {
        shard_dir
            .join(format!("x_{:02}.bin", i))
            .metadata()
            .map(|m| m.len() > 0 && m.len() % 33 == 0)
            .unwrap_or(false)
    });

    let need_h20 = !have_h20 && !have_funded;
    let need_h32 = !have_h32 && !have_done_h32;
    let need_any_x = have_x.iter().any(|&b| !b);

    println!(
        "[1/4] Found {} blk*.dat files in {}. Checkpoint state: have_h20={}, have_funded={}, have_h32={}, existing_x_shards={}/64",
        blk_files.len(),
        blocks_dir,
        have_h20,
        have_funded,
        have_h32 || have_done_h32,
        have_x.iter().filter(|&&b| b).count()
    );
    let _ = io::stdout().flush();

    if need_h20 || need_h32 || need_any_x {
        let x_shards: Vec<Option<Mutex<BufWriter<File>>>> = (0..64)
            .map(|i| {
                if have_x[i] {
                    None
                } else {
                    Some(Mutex::new(BufWriter::with_capacity(
                        256 * 1024,
                        File::create(shard_dir.join(format!("x_{:02}.bin", i))).unwrap(),
                    )))
                }
            })
            .collect();
        let h20_shards: Vec<Option<Mutex<BufWriter<File>>>> = (0..64)
            .map(|i| {
                if !need_h20 {
                    None
                } else {
                    Some(Mutex::new(BufWriter::with_capacity(
                        256 * 1024,
                        File::create(shard_dir.join(format!("h20_{:02}.bin", i))).unwrap(),
                    )))
                }
            })
            .collect();
        let h32_shards: Vec<Option<Mutex<BufWriter<File>>>> = (0..16)
            .map(|i| {
                if !need_h32 {
                    None
                } else {
                    Some(Mutex::new(BufWriter::with_capacity(
                        256 * 1024,
                        File::create(shard_dir.join(format!("h32_{:02}.bin", i))).unwrap(),
                    )))
                }
            })
            .collect();

        let flush_local = |lx: &mut FxHashMap<[u8; 32], u8>,
                           lh20: &mut FxHashMap<[u8; 20], u8>,
                           lh32: &mut FxHashMap<[u8; 32], u8>| {
            if !lx.is_empty() {
                let mut buckets: Vec<Vec<u8>> = (0..64).map(|_| Vec::new()).collect();
                for (k, v) in lx.drain() {
                    let b = (k[0] >> 2) as usize;
                    if !have_x[b] {
                        buckets[b].extend_from_slice(&k);
                        buckets[b].push(v);
                    }
                }
                for (i, buf) in buckets.into_iter().enumerate() {
                    if !buf.is_empty() {
                        if let Some(ref writer) = x_shards[i] {
                            writer.lock().unwrap().write_all(&buf).unwrap();
                        }
                    }
                }
            }
            if !lh20.is_empty() {
                let mut buckets: Vec<Vec<u8>> = (0..64).map(|_| Vec::new()).collect();
                for (k, v) in lh20.drain() {
                    let b = (k[0] >> 2) as usize;
                    buckets[b].extend_from_slice(&k);
                    buckets[b].push(v);
                }
                for (i, buf) in buckets.into_iter().enumerate() {
                    if !buf.is_empty() {
                        if let Some(ref writer) = h20_shards[i] {
                            writer.lock().unwrap().write_all(&buf).unwrap();
                        }
                    }
                }
            }
            if !lh32.is_empty() {
                let mut buckets: Vec<Vec<u8>> = (0..16).map(|_| Vec::new()).collect();
                for (k, v) in lh32.drain() {
                    let b = (k[0] >> 4) as usize;
                    buckets[b].extend_from_slice(&k);
                    buckets[b].push(v);
                }
                for (i, buf) in buckets.into_iter().enumerate() {
                    if !buf.is_empty() {
                        if let Some(ref writer) = h32_shards[i] {
                            writer.lock().unwrap().write_all(&buf).unwrap();
                        }
                    }
                }
            }
        };

        let total_blocks = std::sync::atomic::AtomicUsize::new(0);
        let total_txs = std::sync::atomic::AtomicUsize::new(0);
        let files_done = std::sync::atomic::AtomicUsize::new(0);
        let total_files = blk_files.len();

        let io_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(6)
            .build()
            .unwrap();

        io_pool.install(|| {
            blk_files.par_iter().for_each(|path| {
                let Ok(mut file) = File::open(path) else { return };
                let mut buf = Vec::with_capacity(135 * 1024 * 1024);
                if file.read_to_end(&mut buf).is_err() {
                    return;
                }
                let mut local_x: FxHashMap<[u8; 32], u8> = FxHashMap::default();
                let mut local_h20: FxHashMap<[u8; 20], u8> = FxHashMap::default();
                let mut local_h32: FxHashMap<[u8; 32], u8> = FxHashMap::default();

                let mut b_count = 0usize;
                let mut tx_count = 0usize;
                let mut pos = 0;

                let mut record_x = |lx: &mut FxHashMap<[u8; 32], u8>, data: &[u8], xonly: bool, flags: u8| {
                    let first_byte = if xonly {
                        if data.len() == 32 {
                            data[0]
                        } else {
                            return;
                        }
                    } else if data.len() == 33 || data.len() == 65 {
                        data[1]
                    } else {
                        return;
                    };
                    if have_x[(first_byte >> 2) as usize] {
                        return;
                    }
                    if let Some(x) = fast_candidate_x(data, xonly) {
                        *lx.entry(x).or_insert(0) |= flags;
                    }
                };

                while pos + 8 <= buf.len() {
                    if buf[pos..pos + 4] != [0xf9, 0xbe, 0xb4, 0xd9] {
                        pos += 1;
                        continue;
                    }
                    let size = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
                    pos += 8;
                    if size < 80 || pos + size > buf.len() {
                        break;
                    }
                    let block_slice = &buf[pos..pos + size];
                    pos += size;
                    b_count += 1;

                    let mut r = Reader::new(&block_slice[80..]);
                    let Some(ntx) = r.count() else { continue };
                    for _ in 0..ntx {
                        let Some(tx) = parse_transaction_from_reader(&mut r) else {
                            break;
                        };
                        tx_count += 1;

                        // 1. Scan outputs
                        for out in &tx.outputs {
                            for (_, d) in Instructions::new(out) {
                                if let Some(data) = d {
                                    record_x(&mut local_x, data, false, 1 | 2 | 16);
                                }
                            }
                            match recognize(out, false) {
                                Recognized::P2PK(k) => {
                                    record_x(&mut local_x, k, false, 1 | 2 | 4 | 32);
                                }
                                Recognized::Multisig { keys, .. } => {
                                    for k in keys {
                                        record_x(&mut local_x, k, false, 1 | 2 | 32);
                                    }
                                }
                                Recognized::P2PKH(h) => {
                                    if need_h20 {
                                        *local_h20.entry(h).or_insert(0) |= 1;
                                    }
                                }
                                Recognized::P2WPKH(h) => {
                                    if need_h20 {
                                        *local_h20.entry(h).or_insert(0) |= 2;
                                    }
                                }
                                Recognized::P2SH(h) => {
                                    if need_h20 {
                                        *local_h20.entry(h).or_insert(0) |= 4;
                                    }
                                }
                                Recognized::P2WSH(h) | Recognized::P2MR(h) => {
                                    if need_h32 {
                                        *local_h32.entry(h).or_insert(0) |= 1;
                                    }
                                }
                                Recognized::P2TR(prog) => {
                                    record_x(&mut local_x, prog, true, 1 | 2 | 8);
                                }
                                _ => {}
                            }
                        }

                        // 2. Scan inputs & witnesses
                        for ((is_cb, script_sig), witness) in tx.inputs.iter().zip(tx.witnesses.iter()) {
                            let mut last_push: Option<&[u8]> = None;
                            let mut push_count = 0usize;
                            for (_, d) in Instructions::new(script_sig) {
                                if let Some(data) = d {
                                    push_count += 1;
                                    last_push = Some(data);
                                    record_x(&mut local_x, data, false, 1 | 32);
                                }
                            }
                            for elem in witness {
                                record_x(&mut local_x, elem, false, 1 | 32);
                            }
                            if *is_cb {
                                continue;
                            }

                            if let Some(redeem) = last_push {
                                let is_p2pkh_pubkey = push_count == 2
                                    && (redeem.len() == 33 || redeem.len() == 65)
                                    && fast_candidate_x(redeem, false).is_some();
                                if !is_p2pkh_pubkey && !redeem.is_empty() {
                                    if need_h20 || need_h32 {
                                        let h = hash160(redeem);
                                        if need_h20 {
                                            *local_h20.entry(h).or_insert(0) |= 8;
                                        }
                                        let sha = sha256(redeem);
                                        let mut w = [0u8; 34];
                                        w[0] = 0x00;
                                        w[1] = 0x20;
                                        w[2..34].copy_from_slice(&sha);
                                        if need_h20 {
                                            let w_h160 = hash160(&w);
                                            *local_h20.entry(w_h160).or_insert(0) |= 8 | 16;
                                        }
                                        if need_h32 {
                                            *local_h32.entry(sha).or_insert(0) |= 2 | 4;
                                        }
                                    }
                                    for (_, d) in Instructions::new(redeem) {
                                        if let Some(data) = d {
                                            record_x(&mut local_x, data, false, 1 | 2 | 32);
                                        }
                                    }
                                    if let Recognized::P2WSH(_) = recognize(redeem, false) {
                                        if let Some(&wscript) = witness.last() {
                                            if need_h20 || need_h32 {
                                                let wsha = sha256(wscript);
                                                if need_h20 {
                                                    let ws_h160 = hash160(wscript);
                                                    *local_h20.entry(ws_h160).or_insert(0) |= 8 | 16;
                                                    let mut ww = [0u8; 34];
                                                    ww[0] = 0x00;
                                                    ww[1] = 0x20;
                                                    ww[2..34].copy_from_slice(&wsha);
                                                    *local_h20.entry(hash160(&ww)).or_insert(0) |= 8;
                                                }
                                                if need_h32 {
                                                    *local_h32.entry(wsha).or_insert(0) |= 2 | 4;
                                                }
                                            }
                                            for (_, d) in Instructions::new(wscript) {
                                                if let Some(data) = d {
                                                    record_x(&mut local_x, data, false, 1 | 2 | 32);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if script_sig.is_empty() && !witness.is_empty() {
                                let last_w = witness[witness.len() - 1];
                                let is_p2wpkh_spend = witness.len() == 2
                                    && (last_w.len() == 33 || last_w.len() == 65)
                                    && fast_candidate_x(last_w, false).is_some();
                                if !is_p2wpkh_spend {
                                    let mut stack = witness.as_slice();
                                    if stack.len() >= 2 && stack.last().unwrap().starts_with(&[0x50]) {
                                        stack = &stack[..stack.len() - 1];
                                    }
                                    let mut is_p2tr_script = false;
                                    if stack.len() >= 2 {
                                        let script = stack[stack.len() - 2];
                                        let control = stack[stack.len() - 1];
                                        if control.len() >= 33
                                            && (control.len() - 33) % 32 == 0
                                            && (control.len() - 33) / 32 <= 128
                                        {
                                            if let Some(ix) = key_x(&control[1..33], true) {
                                                is_p2tr_script = true;
                                                if !have_x[(ix[0] >> 2) as usize] {
                                                    *local_x.entry(ix).or_insert(0) |= 1 | 2 | 32;
                                                }
                                                if need_h20 || need_h32 {
                                                    let wsha_s = sha256(script);
                                                    if need_h32 {
                                                        *local_h32.entry(wsha_s).or_insert(0) |= 2 | 4;
                                                    }
                                                    if need_h20 {
                                                        let sh_s = hash160(script);
                                                        *local_h20.entry(sh_s).or_insert(0) |= 8 | 16;
                                                        let mut ww = [0u8; 34];
                                                        ww[0] = 0x00;
                                                        ww[1] = 0x20;
                                                        ww[2..34].copy_from_slice(&wsha_s);
                                                        *local_h20.entry(hash160(&ww)).or_insert(0) |= 8 | 16;
                                                    }
                                                    if need_h32 {
                                                        let mut path =
                                                            Vec::with_capacity((control.len() - 33) / 32);
                                                        for i in (33..control.len()).step_by(32) {
                                                            let mut h = [0u8; 32];
                                                            h.copy_from_slice(&control[i..i + 32]);
                                                            path.push(h);
                                                        }
                                                        let version = control[0] & 254;
                                                        let leaf = RevealedLeaf {
                                                            version,
                                                            script: script.to_vec(),
                                                            path,
                                                        };
                                                        for lh in leaf_hashes(&leaf) {
                                                            *local_h32.entry(lh).or_insert(0) |= 2 | 4;
                                                        }
                                                    }
                                                }
                                                let version = control[0] & 254;
                                                for (_, d) in Instructions::new(script) {
                                                    if let Some(data) = d {
                                                        if data.len() == 33 || data.len() == 65 {
                                                            if !have_x[(data[1] >> 2) as usize] {
                                                                if let Some(x) = key_x(data, false) {
                                                                    *local_x.entry(x).or_insert(0) |= 1 | 2 | 32;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if version == 192 {
                                                    let ops: Vec<(u8, Option<&[u8]>)> =
                                                        Instructions::new(script).collect();
                                                    for w in ops.windows(2) {
                                                        if let Some(data) = w[0].1 {
                                                            if matches!(w[1].0, 172 | 173 | 186) && data.len() == 32 {
                                                                if !have_x[(data[0] >> 2) as usize] {
                                                                    if let Some(x) = key_x(data, true) {
                                                                        *local_x.entry(x).or_insert(0) |= 1 | 2 | 32;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if !is_p2tr_script && !last_w.is_empty() {
                                        if need_h20 || need_h32 {
                                            let wsha = sha256(last_w);
                                            if need_h32 {
                                                *local_h32.entry(wsha).or_insert(0) |= 2;
                                            }
                                            if need_h20 {
                                                let sh_direct = hash160(last_w);
                                                *local_h20.entry(sh_direct).or_insert(0) |= 8 | 16;
                                                let mut ww = [0u8; 34];
                                                ww[0] = 0x00;
                                                ww[1] = 0x20;
                                                ww[2..34].copy_from_slice(&wsha);
                                                *local_h20.entry(hash160(&ww)).or_insert(0) |= 8 | 16;
                                            }
                                        }
                                        for (_, d) in Instructions::new(last_w) {
                                            if let Some(data) = d {
                                                record_x(&mut local_x, data, false, 1 | 2 | 32);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if local_x.len() + local_h20.len() + local_h32.len() >= 1_500_000 {
                            flush_local(&mut local_x, &mut local_h20, &mut local_h32);
                        }
                    }
                }

                flush_local(&mut local_x, &mut local_h20, &mut local_h32);
                total_blocks.fetch_add(b_count, std::sync::atomic::Ordering::Relaxed);
                total_txs.fetch_add(tx_count, std::sync::atomic::Ordering::Relaxed);
                let done = files_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if done % 250 == 0 || done == total_files {
                    println!(
                        "  -> [1/4] Scanned {} / {} blk files ({:.1}%) in {:.1}s",
                        done,
                        total_files,
                        (done as f64 * 100.0) / (total_files as f64),
                        t0.elapsed().as_secs_f64()
                    );
                    let _ = io::stdout().flush();
                }
            });
        });

        drop(x_shards);
        drop(h20_shards);
        drop(h32_shards);

        println!(
            "[1.5/4] Block scan finished in {:.1}s ({} blocks, {} txs).",
            t0.elapsed().as_secs_f64(),
            total_blocks.load(std::sync::atomic::Ordering::Relaxed),
            total_txs.load(std::sync::atomic::Ordering::Relaxed)
        );
        let _ = io::stdout().flush();
    }

    // Step 1B: Reduce h32_00..15.bin immediately to free 33 GB SSD space
    let mut census = Census::default();
    if have_done_h32 {
        census.funded_hash32_p2wsh_note = Some("Unavailable: H32 reduction skipped on resume.");
    } else {
        census.funded_hash32_p2wsh = Some(0);
    }
    let mut total_wsh32 = 0usize;
    let mut total_cross_diff_32 = 0usize;
    if !have_done_h32 {
        println!("[2a/4] Reducing 16 H32 shards into script_hash_index_32.bin & cross_format_diff_32.bin...");
        let _ = io::stdout().flush();
        let mut script32_file =
            BufWriter::with_capacity(256 * 1024, File::create(out_path.join("script_hash_index_32.bin")).unwrap());
        let mut cross32_file =
            BufWriter::with_capacity(256 * 1024, File::create(out_path.join("cross_format_diff_32.bin")).unwrap());
        for s in 0..16 {
            let h32_path = shard_dir.join(format!("h32_{:02}.bin", s));
            let raw_h32 = fs::read(&h32_path).unwrap_or_default();
            let _ = fs::remove_file(&h32_path);
            let mut items: Vec<([u8; 32], u8)> = Vec::with_capacity(raw_h32.len() / 33);
            for chunk in raw_h32.chunks_exact(33) {
                let mut h = [0u8; 32];
                h.copy_from_slice(&chunk[0..32]);
                items.push((h, chunk[32]));
            }
            drop(raw_h32);
            items.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));

            let mut deduped: Vec<([u8; 32], u8)> = Vec::with_capacity(items.len() / 2 + 1);
            for (h, m) in items {
                if let Some(last) = deduped.last_mut() {
                    if last.0 == h {
                        last.1 |= m;
                        continue;
                    }
                }
                deduped.push((h, m));
            }
            for (h, m) in deduped {
                if (m & 1) != 0 {
                    *census.funded_hash32_p2wsh.as_mut().unwrap() += 1;
                }
                if (m & 1) != 0 && (m & 2) != 0 {
                    script32_file.write_all(&h).unwrap();
                    total_wsh32 += 1;
                }
                if (m & 1) != 0 && (m & 4) != 0 {
                    cross32_file.write_all(&h).unwrap();
                    total_cross_diff_32 += 1;
                }
            }
        }
        script32_file.flush().unwrap();
        cross32_file.flush().unwrap();
    } else {
        total_wsh32 = out_path.join("script_hash_index_32.bin").metadata().map(|m| (m.len() / 32) as usize).unwrap_or(0);
        total_cross_diff_32 = out_path.join("cross_format_diff_32.bin").metadata().map(|m| (m.len() / 32) as usize).unwrap_or(0);
    }

    // Step 1C: Deduplicate h20_00..63.bin into funded_00..63.bin (freeing ~56 GB SSD space) and populate 2.0 GiB FundedBloom
    println!("[2b/4] Deduplicating 64 H20 shards and building 2.0 GiB FundedBloom filter...");
    let _ = io::stdout().flush();
    let bloom = FundedBloom::new();
    let mut total_sh20 = 0usize;
    if !have_funded {
        let mut script20_idx_file =
            BufWriter::with_capacity(256 * 1024, File::create(out_path.join("script_hash_index_20.bin")).unwrap());
        for s in 0..64 {
            let h20_path = shard_dir.join(format!("h20_{:02}.bin", s));
            let raw_h20 = fs::read(&h20_path).unwrap_or_default();
            let _ = fs::remove_file(&h20_path);

            let mut h20_items: Vec<([u8; 20], u8)> = Vec::with_capacity(raw_h20.len() / 21);
            for chunk in raw_h20.chunks_exact(21) {
                let mut h = [0u8; 20];
                h.copy_from_slice(&chunk[0..20]);
                h20_items.push((h, chunk[20]));
            }
            drop(raw_h20);
            h20_items.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));

            let mut funded_shard: Vec<([u8; 20], u8)> = Vec::with_capacity(h20_items.len() / 2 + 1);
            for (h, m) in h20_items {
                if let Some(last) = funded_shard.last_mut() {
                    if last.0 == h {
                        last.1 |= m;
                        continue;
                    }
                }
                funded_shard.push((h, m));
            }
            funded_shard.retain(|&(_, m)| (m & 7) != 0);

            let funded_path = shard_dir.join(format!("funded_{:02}.bin", s));
            let mut ff = BufWriter::with_capacity(256 * 1024, File::create(&funded_path).unwrap());
            for &(h, m) in &funded_shard {
                census.record_hash20(m);
                bloom.insert(&h);
                if (m & 4) != 0 && (m & 8) != 0 {
                    script20_idx_file.write_all(&h).unwrap();
                    total_sh20 += 1;
                }
                ff.write_all(&h).unwrap();
                ff.write_all(&[m]).unwrap();
            }
            ff.flush().unwrap();
        }
        script20_idx_file.flush().unwrap();
    } else {
        total_sh20 = out_path.join("script_hash_index_20.bin").metadata().map(|m| (m.len() / 20) as usize).unwrap_or(0);
        for s in 0..64 {
            let funded_path = shard_dir.join(format!("funded_{:02}.bin", s));
            let raw_f = fs::read(&funded_path).unwrap_or_default();
            for chunk in raw_f.chunks_exact(21) {
                let mut h = [0u8; 20];
                h.copy_from_slice(&chunk[0..20]);
                census.record_hash20(chunk[20]);
                bloom.insert(&h);
            }
        }
    }

    // Step 2: Deduplicate x_00..x_63 and emit Bloom-filtered candidate 20-byte hashes into cand_00..cand_63 (~20 GB total)
    println!("[2c/4] Deriving 6 encodings across 64 X shards with FundedBloom filtering...");
    let _ = io::stdout().flush();
    let t1 = Instant::now();
    let cand_shards: Vec<Mutex<BufWriter<File>>> = (0..64)
        .map(|i| {
            Mutex::new(BufWriter::with_capacity(
                256 * 1024,
                File::create(shard_dir.join(format!("cand_{:02}.bin", i))).unwrap(),
            ))
        })
        .collect();

    let mut x_flags_vec: Vec<u8> = Vec::with_capacity(700_000_000);
    for s in 0..64 {
        let x_path = shard_dir.join(format!("x_{:02}.bin", s));
        let raw = fs::read(&x_path).unwrap_or_default();
        let _ = fs::remove_file(&x_path);
        let n = raw.len() / 33;
        if n == 0 {
            continue;
        }
        let mut items: Vec<([u8; 32], u8)> = Vec::with_capacity(n);
        for chunk in raw.chunks_exact(33) {
            let mut x = [0u8; 32];
            x.copy_from_slice(&chunk[0..32]);
            items.push((x, chunk[32]));
        }
        drop(raw);
        items.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut deduped: Vec<([u8; 32], u8)> = Vec::with_capacity(items.len() / 2 + 1);
        for (x, fl) in items {
            if let Some(last) = deduped.last_mut() {
                if last.0 == x {
                    last.1 |= fl;
                    continue;
                }
            }
            deduped.push((x, fl));
        }

        let base_id = x_flags_vec.len() as u32;
        for &(_, fl) in &deduped {
            x_flags_vec.push(fl);
        }

        deduped.par_chunks(32768).enumerate().for_each(|(c_idx, chunk)| {
            let chunk_base = base_id + (c_idx * 32768) as u32;
            let mut buckets: Vec<Vec<u8>> = (0..64).map(|_| Vec::new()).collect();
            for (offset, (x, _)) in chunk.iter().enumerate() {
                let Some((kh, wrapped)) = key_hashes_from_x(x) else {
                    continue;
                };
                let x_id = chunk_base + (offset as u32);
                let x_id_bytes = x_id.to_le_bytes();
                for (enc_idx, h) in kh.iter().enumerate() {
                    if bloom.may_contain(h) {
                        let b = (h[0] >> 2) as usize;
                        buckets[b].extend_from_slice(h);
                        buckets[b].extend_from_slice(&x_id_bytes);
                        buckets[b].push(enc_idx as u8);
                    }
                }
                for (enc_idx, w) in wrapped.iter().enumerate() {
                    if bloom.may_contain(w) {
                        let b = (w[0] >> 2) as usize;
                        buckets[b].extend_from_slice(w);
                        buckets[b].extend_from_slice(&x_id_bytes);
                        buckets[b].push((enc_idx as u8) | 8);
                    }
                }
            }
            for (i, buf) in buckets.into_iter().enumerate() {
                if !buf.is_empty() {
                    cand_shards[i].lock().unwrap().write_all(&buf).unwrap();
                }
            }
        });
        if (s + 1) % 8 == 0 || s == 63 {
            println!("  -> [2c/4] Processed X shard {} / 64 in {:.1}s", s + 1, t1.elapsed().as_secs_f64());
            let _ = io::stdout().flush();
        }
    }
    drop(cand_shards);
    drop(bloom);

    let total_unique_x = x_flags_vec.len();
    println!(
        "[3/4] Derived 6 encodings for {} unique published x-coordinates in {:.1}s. Intersecting 64 H160 shards...",
        total_unique_x,
        t1.elapsed().as_secs_f64()
    );
    let _ = io::stdout().flush();

    // Step 3: Intersect cand_{s}.bin with funded_{s}.bin for each shard s in 0..64
    let t2 = Instant::now();
    let key_hits: Vec<std::sync::atomic::AtomicU16> = (0..total_unique_x)
        .map(|_| std::sync::atomic::AtomicU16::new(0))
        .collect();

    let mut pubkey_idx_file =
        BufWriter::with_capacity(256 * 1024, File::create(out_path.join("pubkey_hash_index.bin")).unwrap());
    let mut matched_files: Vec<PathBuf> = Vec::with_capacity(64);

    let mut total_exposed_h160 = 0usize;

    for s in 0..64 {
        let funded_path = shard_dir.join(format!("funded_{:02}.bin", s));
        let raw_f = fs::read(&funded_path).unwrap_or_default();
        let _ = fs::remove_file(&funded_path);

        let mut funded_shard: Vec<([u8; 20], u8)> = Vec::with_capacity(raw_f.len() / 21);
        let mut shard_cross_sh20: Vec<[u8; 20]> = Vec::new();
        for chunk in raw_f.chunks_exact(21) {
            let mut h = [0u8; 20];
            h.copy_from_slice(&chunk[0..20]);
            let m = chunk[20];
            funded_shard.push((h, m));
            if (m & 4) != 0 && (m & 16) != 0 {
                shard_cross_sh20.push(h);
            }
        }
        drop(raw_f);

        let cand_path = shard_dir.join(format!("cand_{:02}.bin", s));
        let raw_cand = fs::read(&cand_path).unwrap_or_default();
        let _ = fs::remove_file(&cand_path);

        let matched_pairs: Mutex<Vec<([u8; 20], u32)>> = Mutex::new(Vec::new());
        raw_cand.par_chunks(25 * 32768).for_each(|chunk| {
            let mut local_matches: Vec<([u8; 20], u32)> = Vec::new();
            for rec in chunk.chunks_exact(25) {
                let mut h = [0u8; 20];
                h.copy_from_slice(&rec[0..20]);
                let Ok(pos) = funded_shard.binary_search_by(|probe| probe.0.cmp(&h)) else {
                    continue;
                };
                let mask = funded_shard[pos].1;
                let x_id = u32::from_le_bytes(rec[20..24].try_into().unwrap());
                let slot = rec[24];
                let enc_idx = (slot & 7) as u16;
                let is_wrapped = (slot & 8) != 0;

                if !is_wrapped {
                    let mut hit_bits = 0u16;
                    if (mask & 1) != 0 {
                        hit_bits |= 1 << enc_idx;
                    }
                    if (mask & 2) != 0 {
                        hit_bits |= 1 << (6 + enc_idx);
                    }
                    if hit_bits != 0 {
                        key_hits[x_id as usize].fetch_or(hit_bits, std::sync::atomic::Ordering::Relaxed);
                        local_matches.push((h, x_id));
                    }
                } else if (mask & 4) != 0 {
                    key_hits[x_id as usize].fetch_or(1 << 12, std::sync::atomic::Ordering::Relaxed);
                    local_matches.push((h, x_id));
                }
            }
            if !local_matches.is_empty() {
                matched_pairs.lock().unwrap().extend(local_matches);
            }
        });
        drop(raw_cand);
        drop(funded_shard);

        let mut pairs = matched_pairs.into_inner().unwrap();
        pairs.par_sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        pairs.dedup();

        let mut last_written: Option<[u8; 20]> = None;
        for &(h, _) in &pairs {
            if last_written != Some(h) {
                pubkey_idx_file.write_all(&h).unwrap();
                total_exposed_h160 += 1;
                last_written = Some(h);
            }
        }

        let m_path = shard_dir.join(format!("matched_{:02}.bin", s));
        {
            let mut mf = BufWriter::with_capacity(128 * 1024, File::create(&m_path).unwrap());
            for &(h, x_id) in &pairs {
                mf.write_all(&h).unwrap();
                mf.write_all(&x_id.to_le_bytes()).unwrap();
            }
            for h in shard_cross_sh20 {
                mf.write_all(&h).unwrap();
                mf.write_all(&u32::MAX.to_le_bytes()).unwrap();
            }
        }
        matched_files.push(m_path);
    }
    pubkey_idx_file.flush().unwrap();
    drop(pubkey_idx_file);

    // Step 4: Write cross_format_diff_20.bin and stats.json
    let mut cross20_file =
        BufWriter::with_capacity(256 * 1024, File::create(out_path.join("cross_format_diff_20.bin")).unwrap());
    let mut total_cross_diff_20 = 0usize;

    for m_path in matched_files {
        let raw_m = fs::read(&m_path).unwrap_or_default();
        let _ = fs::remove_file(&m_path);
        let mut diff_hashes: Vec<[u8; 20]> = Vec::new();
        for rec in raw_m.chunks_exact(24) {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rec[0..20]);
            let x_id = u32::from_le_bytes(rec[20..24].try_into().unwrap());
            if x_id == u32::MAX {
                diff_hashes.push(h);
            } else {
                let hits = key_hits[x_id as usize].load(std::sync::atomic::Ordering::Relaxed);
                let fl = x_flags_vec[x_id as usize];
                if hits.count_ones() > 1 || (fl & 2) != 0 {
                    diff_hashes.push(h);
                }
            }
        }
        diff_hashes.par_sort_unstable();
        diff_hashes.dedup();
        for h in diff_hashes {
            cross20_file.write_all(&h).unwrap();
            total_cross_diff_20 += 1;
        }
    }
    cross20_file.flush().unwrap();
    drop(cross20_file);
    let _ = fs::remove_dir_all(&shard_dir);

    let mut c_p2pk_p2pkh = 0usize;
    let mut c_pkh_wpkh = 0usize;
    let mut c_comp_uncomp = 0usize;
    for (x_id, hit_atom) in key_hits.iter().enumerate() {
        let hits = hit_atom.load(std::sync::atomic::Ordering::Relaxed);
        let row = census_row(hits, x_flags_vec[x_id]);
        census.record_row(&row);
        if row.p2pk && row.p2pkh {
            c_p2pk_p2pkh += 1;
        }
        if row.p2pkh && row.p2wpkh {
            c_pkh_wpkh += 1;
        }
        if row.comp && row.uncomp {
            c_comp_uncomp += 1;
        }
    }

    let stats_json = serde_json::json!({
        "census": census,
        "unique_published_x_coords": total_unique_x,
        "exposed_h160_entries": total_exposed_h160,
        "revealed_p2sh_20_entries": total_sh20,
        "revealed_p2wsh_32_entries": total_wsh32,
        "cross_format_diff_20_entries": total_cross_diff_20,
        "cross_format_diff_32_entries": total_cross_diff_32,
        "cross_type_reuse": {
            "keys_in_both_p2pk_and_p2pkh": c_p2pk_p2pkh,
            "keys_in_both_p2pkh_and_p2wpkh": c_pkh_wpkh,
            "keys_in_both_compressed_and_uncompressed": c_comp_uncomp
        }
    });
    fs::write(
        out_path.join("stats.json"),
        serde_json::to_string_pretty(&stats_json).unwrap(),
    )
    .unwrap();

    println!(
        "[4/4] Index build completed in {:.1}s (total {:.1}s)!",
        t2.elapsed().as_secs_f64(),
        t0.elapsed().as_secs_f64()
    );
    println!("  - Exposed H160 entries written: {} ({:.2} MB)", total_exposed_h160, (total_exposed_h160 * 20) as f64 / 1e6);
    println!("  - Revealed P2SH entries written: {} ({:.2} MB)", total_sh20, (total_sh20 * 20) as f64 / 1e6);
    println!("  - Revealed P2WSH entries written: {} ({:.2} MB)", total_wsh32, (total_wsh32 * 32) as f64 / 1e6);
    println!("  - Minimal Cross-Format Diff 20B entries: {} ({:.2} MB)", total_cross_diff_20, (total_cross_diff_20 * 20) as f64 / 1e6);
    println!("  - Minimal Cross-Format Diff 32B entries: {} ({:.2} MB)", total_cross_diff_32, (total_cross_diff_32 * 32) as f64 / 1e6);
    println!("  - Cross-type reuse stats:");
    println!("      * Keys in both P2PK and P2PKH: {}", c_p2pk_p2pkh);
    println!("      * Keys in both P2PKH and P2WPKH: {}", c_pkh_wpkh);
    println!("      * Keys funded under both Compressed and Uncompressed encodings: {}", c_comp_uncomp);
    println!("  - Census stats:");
    for (name, value) in stats_json["census"].as_object().unwrap() {
        println!("      * {}: {}", name, value);
    }
}

#[derive(Serialize, Deserialize)]
struct DeltaBlockRecord {
    height: u64,
    block_hash: String,
    kh20: Vec<String>,
    wrapped20: Vec<String>,
    sh20: Vec<String>,
    wsh32: Vec<String>,
    mr32: Vec<String>,
}

// Mainnet BIP141 activation height; commitments are mandatory even in stripped copies.
const SEGWIT_ACTIVATION_HEIGHT: u64 = 481_824;

fn merkle_root(mut hashes: Vec<[u8; 32]>) -> Result<[u8; 32], String> {
    if hashes.is_empty() {
        return Err("block stdin byte offset 80: empty merkle tree".to_string());
    }
    while hashes.len() > 1 {
        let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
        for pair in hashes.chunks(2) {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&pair[0]);
            bytes[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(double_sha256(&bytes));
        }
        hashes = next;
    }
    Ok(hashes[0])
}

fn transaction_hashes(raw: &[u8], tx: &ParsedTx<'_>) -> Result<([u8; 32], [u8; 32]), String> {
    let wtxid = double_sha256(raw);
    if !tx.witnesses.iter().any(|w| !w.is_empty()) {
        return Ok((wtxid, wtxid));
    }
    // The parser enforces canonical compact sizes, so these lengths are exact.
    let mut witness_len = 0usize;
    for witness in &tx.witnesses {
        witness_len = witness_len.checked_add(compact_size(witness.len()).len())
            .ok_or_else(|| "witness length overflow".to_string())?;
        for item in witness {
            witness_len = witness_len.checked_add(compact_size(item.len()).len())
                .and_then(|n| n.checked_add(item.len()))
                .ok_or_else(|| "witness length overflow".to_string())?;
        }
    }
    let end = raw.len().checked_sub(4).and_then(|n| n.checked_sub(witness_len))
        .filter(|&n| n >= 6)
        .ok_or_else(|| "invalid witness boundary".to_string())?;
    let mut stripped = Vec::with_capacity(raw.len() - witness_len - 2);
    stripped.extend_from_slice(&raw[..4]);
    stripped.extend_from_slice(&raw[6..end]);
    stripped.extend_from_slice(&raw[raw.len() - 4..]);
    Ok((double_sha256(&stripped), wtxid))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    #[cfg(unix)]
    File::open(dir).and_then(|f| f.sync_all())
        .map_err(|e| format!("{} byte offset 0: sync parent directory {}: {}", path.display(), dir.display(), e))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn finish_synced_file(mut out: BufWriter<File>, path: &Path) -> Result<File, String> {
    out.flush().map_err(|e| format!("{} byte offset 0: flush: {}", path.display(), e))?;
    let file = out.into_inner().map_err(|e| format!("{} byte offset 0: finish writer: {}", path.display(), e))?;
    file.sync_all().map_err(|e| format!("{} byte offset 0: sync file: {}", path.display(), e))?;
    Ok(file)
}

fn apply_block_hex(index_dir: &str, height: u64, block_hash: &str) -> Result<(), String> {
    let mut hex_str = String::new();
    io::stdin().read_to_string(&mut hex_str)
        .map_err(|e| format!("block stdin byte offset {}: {}", hex_str.len(), e))?;
    apply_block(Path::new(index_dir), height, block_hash, &hex_str)
}

fn apply_block(index_dir: &Path, height: u64, block_hash: &str, block_hex: &str) -> Result<(), String> {
    let block_bytes = hex::decode(block_hex.trim())
        .map_err(|e| format!("block stdin hex at byte offset 0: {}", e))?;
    if block_bytes.len() < 80 {
        return Err(format!("block stdin byte offset {}: block header too short", block_bytes.len()));
    }
    let mut expected_hash = [0u8; 32];
    hex::decode_to_slice(block_hash, &mut expected_hash)
        .map_err(|e| format!("block stdin byte offset 0: invalid block_hash argument: {}", e))?;
    expected_hash.reverse();
    if expected_hash != double_sha256(&block_bytes[..80]) {
        return Err("block stdin byte offset 0: header hash mismatch".to_string());
    }

    let mut r = Reader::new(&block_bytes[80..]);
    let ntx = r.count().ok_or_else(|| "block stdin byte offset 80: invalid transaction count".to_string())?;
    if ntx == 0 {
        return Err("block stdin byte offset 80: zero transactions".to_string());
    }
    let mut txids = Vec::new();
    let mut wtxids = Vec::new();
    let mut coinbase = None;
    let mut has_witness = false;

    let mut keys: FxHashSet<[u8; 32]> = FxHashSet::default();
    let mut sh20: FxHashSet<[u8; 20]> = FxHashSet::default();
    let mut wsh32: FxHashSet<[u8; 32]> = FxHashSet::default();
    let mut mr32: FxHashSet<[u8; 32]> = FxHashSet::default();

    for tx_index in 0..ntx {
        let start = r.pos;
        let tx = parse_transaction_from_reader(&mut r).ok_or_else(||
            format!("block stdin transaction {} at byte offset {}: parse failed (stopped at {})",
                tx_index, start + 80, r.pos + 80))?;
        let (txid, wtxid) = transaction_hashes(&r.data[start..r.pos], &tx)
            .map_err(|e| format!("block stdin transaction {} at byte offset {}: {}", tx_index, start + 80, e))?;
        txids.push(txid);
        wtxids.push(if tx_index == 0 { [0u8; 32] } else { wtxid });
        has_witness |= tx.witnesses.iter().any(|w| !w.is_empty());
        for out in &tx.outputs {
            for (_, d) in Instructions::new(out) {
                if let Some(data) = d {
                    if let Some(x) = key_x(data, false) {
                        keys.insert(x);
                    }
                }
            }
            if let Recognized::P2TR(prog) = recognize(out, false) {
                if let Some(x) = key_x(prog, true) {
                    keys.insert(x);
                }
            }
        }
        for ((is_cb, script_sig), witness) in tx.inputs.iter().zip(tx.witnesses.iter()) {
            let mut last_push: Option<&[u8]> = None;
            for (_, d) in Instructions::new(script_sig) {
                if let Some(data) = d {
                    last_push = Some(data);
                    if let Some(x) = key_x(data, false) {
                        keys.insert(x);
                    }
                }
            }
            for elem in witness {
                if let Some(x) = key_x(elem, false) {
                    keys.insert(x);
                }
            }
            if *is_cb {
                continue;
            }
            if let Some(redeem) = last_push {
                sh20.insert(hash160(redeem));
                let sha = sha256(redeem);
                let mut w = [0u8; 34];
                w[0] = 0x00;
                w[1] = 0x20;
                w[2..34].copy_from_slice(&sha);
                sh20.insert(hash160(&w));
                wsh32.insert(sha);
                for (_, d) in Instructions::new(redeem) {
                    if let Some(data) = d {
                        if let Some(x) = key_x(data, false) {
                            keys.insert(x);
                        }
                    }
                }
                if let Recognized::P2WSH(_) = recognize(redeem, false) {
                    if let Some(&wscript) = witness.last() {
                        let wsha = sha256(wscript);
                        sh20.insert(hash160(wscript));
                        let mut ww = [0u8; 34];
                        ww[0] = 0x00;
                        ww[1] = 0x20;
                        ww[2..34].copy_from_slice(&wsha);
                        sh20.insert(hash160(&ww));
                        wsh32.insert(wsha);
                        for (_, d) in Instructions::new(wscript) {
                            if let Some(data) = d {
                                if let Some(x) = key_x(data, false) {
                                    keys.insert(x);
                                }
                            }
                        }
                    }
                }
            }
            if script_sig.is_empty() && !witness.is_empty() {
                let last_w = witness[witness.len() - 1];
                let wsha = sha256(last_w);
                wsh32.insert(wsha);
                sh20.insert(hash160(last_w));
                let mut ww = [0u8; 34];
                ww[0] = 0x00;
                ww[1] = 0x20;
                ww[2..34].copy_from_slice(&wsha);
                sh20.insert(hash160(&ww));
                for (_, d) in Instructions::new(last_w) {
                    if let Some(data) = d {
                        if let Some(x) = key_x(data, false) {
                            keys.insert(x);
                        }
                    }
                }
                if witness.len() >= 2 {
                    let mut stack = witness.as_slice();
                    if stack.len() >= 2 && stack.last().unwrap().starts_with(&[0x50]) {
                        stack = &stack[..stack.len() - 1];
                    }
                    if stack.len() >= 2 {
                        let script = stack[stack.len() - 2];
                        let control = stack[stack.len() - 1];
                        if control.len() >= 33
                            && (control.len() - 33) % 32 == 0
                            && (control.len() - 33) / 32 <= 128
                        {
                            if let Some(ix) = key_x(&control[1..33], true) {
                                keys.insert(ix);
                                let mut path = Vec::with_capacity((control.len() - 33) / 32);
                                for i in (33..control.len()).step_by(32) {
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&control[i..i + 32]);
                                    path.push(h);
                                }
                                let version = control[0] & 254;
                                let leaf = RevealedLeaf {
                                    version,
                                    script: script.to_vec(),
                                    path,
                                };
                                for lh in leaf_hashes(&leaf) {
                                    mr32.insert(lh);
                                }
                                for (_, d) in Instructions::new(script) {
                                    if let Some(data) = d {
                                        if let Some(x) = key_x(data, false) {
                                            keys.insert(x);
                                        }
                                    }
                                }
                                if version == 192 {
                                    let ops: Vec<(u8, Option<&[u8]>)> =
                                        Instructions::new(script).collect();
                                    for w in ops.windows(2) {
                                        if let Some(data) = w[0].1 {
                                            if matches!(w[1].0, 172 | 173 | 186) {
                                                if let Some(x) = key_x(data, true) {
                                                    keys.insert(x);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if tx_index == 0 {
            coinbase = Some(tx);
        }
    }
    if r.pos != r.data.len() {
        return Err(format!("block stdin byte offset {}: {} trailing bytes", r.pos + 80, r.data.len() - r.pos));
    }
    if merkle_root(txids)? != block_bytes[36..68] {
        return Err("block stdin byte offset 36: transaction merkle root mismatch".to_string());
    }
    let coinbase = coinbase.ok_or_else(|| "block stdin byte offset 81: missing transaction 0".to_string())?;
    let commit_pos = coinbase.outputs.iter().rposition(|out|
        out.len() >= 38 && out.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]));
    if has_witness || (commit_pos.is_some() && height >= SEGWIT_ACTIVATION_HEIGHT) {
        let pos = commit_pos.ok_or_else(||
            "block stdin transaction 0 at byte offset 81: missing witness commitment output".to_string())?;
        let reserved = coinbase.witnesses.first().filter(|w| w.len() == 1 && w[0].len() == 32)
            .ok_or_else(|| "block stdin transaction 0 at byte offset 81: invalid witness reserved value".to_string())?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&merkle_root(wtxids)?);
        bytes[32..].copy_from_slice(reserved[0]);
        if double_sha256(&bytes) != coinbase.outputs[pos][6..38] {
            return Err(format!("block stdin transaction 0 output {} at byte offset 81: witness commitment mismatch", pos));
        }
    }

    let mut kh20 = FxHashSet::default();
    let mut wrapped20 = FxHashSet::default();
    for x in &keys {
        if let Some((kh, wr)) = key_hashes_from_x(x) {
            kh20.extend(kh);
            wrapped20.extend(wr);
        }
    }

    let delta_path = index_dir.join("delta_blocks.jsonl");
    let mut kept_lines = Vec::new();
    match File::open(&delta_path) {
        Ok(f) => for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| format!("{} line {}: {}", delta_path.display(), i + 1, e))?;
            let rec: DeltaBlockRecord = serde_json::from_str(&line)
                .map_err(|e| format!("{} line {}: invalid DeltaBlockRecord: {}", delta_path.display(), i + 1, e))?;
            if rec.height < height {
                kept_lines.push(line);
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("{} byte offset 0: open: {}", delta_path.display(), e)),
    }
    let rec = DeltaBlockRecord {
        height,
        block_hash: block_hash.to_string(),
        kh20: kh20.iter().map(hex::encode).collect(),
        wrapped20: wrapped20.iter().map(hex::encode).collect(),
        sh20: sh20.iter().map(hex::encode).collect(),
        wsh32: wsh32.iter().map(hex::encode).collect(),
        mr32: mr32.iter().map(hex::encode).collect(),
    };
    kept_lines.push(serde_json::to_string(&rec)
        .map_err(|e| format!("{} line {}: serialize: {}", delta_path.display(), kept_lines.len() + 1, e))?);
    // Drop records at or above this height; re-applying replaces this height and all
    // later records. Publish the replacement journal atomically after syncing it.
    let tmp_path = index_dir.join("delta_blocks.jsonl.tmp");
    let mut out = BufWriter::new(File::create(&tmp_path)
        .map_err(|e| format!("{} byte offset 0: create: {}", tmp_path.display(), e))?);
    for (i, l) in kept_lines.iter().enumerate() {
        writeln!(out, "{}", l).map_err(|e| format!("{} line {}: write: {}", tmp_path.display(), i + 1, e))?;
    }
    drop(finish_synced_file(out, &tmp_path)?);
    fs::rename(&tmp_path, &delta_path)
        .map_err(|e| format!("{} byte offset 0: rename over {}: {}", tmp_path.display(), delta_path.display(), e))?;
    sync_parent(&delta_path)
}

#[derive(Default)]
struct DeltaIndex {
    signature: DeltaSignature,
    heights: Vec<u64>,
    max_height: Option<u64>,
    loaded_at: u64,
    pk20: Vec<[u8; 20]>,
    sh20: Vec<[u8; 20]>,
    sh32: Vec<[u8; 32]>,
    available: bool,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct DeltaSignature {
    mtime: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DeltaSignature {
    fn from_metadata(meta: &fs::Metadata) -> io::Result<Self> {
        Ok(Self {
            mtime: Some(meta.modified()?),
            len: meta.len(),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(meta),
        })
    }
}

fn delta_signature(path: &Path) -> io::Result<DeltaSignature> {
    match fs::metadata(path) {
        Ok(meta) => DeltaSignature::from_metadata(&meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DeltaSignature::default()),
        Err(e) => Err(e),
    }
}

impl DeltaIndex {
    fn load(path: &Path) -> io::Result<Self> {
        let mut index = Self::default();
        match File::open(path) {
            Ok(file) => {
                let meta = file.metadata()?;
                index.signature = DeltaSignature::from_metadata(&meta)?;
                for line in BufReader::new(file).lines() {
                    let rec: DeltaBlockRecord = serde_json::from_str(&line?)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    index.heights.push(rec.height);
                    Self::append(&mut index.pk20, rec.kh20.into_iter().chain(rec.wrapped20))?;
                    Self::append(&mut index.sh20, rec.sh20.into_iter())?;
                    Self::append(&mut index.sh32, rec.wsh32.into_iter().chain(rec.mr32))?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        index.heights.sort_unstable();
        index.max_height = index.heights.last().copied();
        index.pk20.sort_unstable();
        index.pk20.dedup();
        index.sh20.sort_unstable();
        index.sh20.dedup();
        index.sh32.sort_unstable();
        index.sh32.dedup();
        index.pk20.shrink_to_fit();
        index.sh20.shrink_to_fit();
        index.sh32.shrink_to_fit();
        if delta_signature(path)? != index.signature {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "delta changed during load"));
        }
        index.available = true;
        index.loaded_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Ok(index)
    }

    fn append<const N: usize>(out: &mut Vec<[u8; N]>, values: impl Iterator<Item = String>) -> io::Result<()> {
        for value in values {
            let mut bytes = [0; N];
            hex::decode_to_slice(value, &mut bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.push(bytes);
        }
        Ok(())
    }

    fn hit20(&self, h: &[u8; 20]) -> bool {
        self.pk20.binary_search(h).is_ok() || self.sh20.binary_search(h).is_ok()
    }

    fn hit32(&self, h: &[u8; 32]) -> bool {
        self.sh32.binary_search(h).is_ok()
    }

    fn script_hit(&self, spk: &[u8]) -> bool {
        match recognize(spk, false) {
            Recognized::P2PKH(h) | Recognized::P2WPKH(h) | Recognized::P2SH(h) => self.hit20(&h),
            Recognized::P2WSH(h) | Recognized::P2MR(h) => self.hit32(&h),
            _ => false,
        }
    }
}

fn binary_search_file<const N: usize>(path: &Path, target: &[u8; N]) -> io::Result<bool> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if N == 0 || len % N as u64 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid table length"));
    }
    let mut low = 0u64;
    let mut high = len / N as u64;
    let mut buf = [0u8; N];
    while low < high {
        let mid = low + (high - low) / 2;
        f.seek(SeekFrom::Start(mid * N as u64))?;
        f.read_exact(&mut buf)?;
        match buf.cmp(target) {
            std::cmp::Ordering::Equal => return Ok(true),
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
        }
    }
    Ok(false)
}

fn evaluate_script_level(index_dir: &str, spk: &[u8], delta: &DeltaIndex) -> &'static str {
    let dir = Path::new(index_dir);
    let hit = match recognize(spk, false) {
        Recognized::Unclassified => return "UNCLASSIFIED",
        Recognized::Unknown => return "UNDETERMINED",
        Recognized::P2PK(k) => return if key_x(k, false).is_some() { "EXPOSED_AT_REST" } else { "UNDETERMINED" },
        Recognized::P2TR(k) => return if key_x(k, true).is_some() { "EXPOSED_AT_REST" } else { "UNDETERMINED" },
        Recognized::Multisig { required, keys } => {
            return if keys.iter().filter(|k| key_x(k, false).is_some()).count() >= required {
                "EXPOSED_AT_REST"
            } else { "UNDETERMINED" };
        }
        Recognized::P2PKH(h) | Recognized::P2WPKH(h) => {
            binary_search_file(&dir.join("pubkey_hash_index.bin"), &h)
                .map(|hit| hit || delta.pk20.binary_search(&h).is_ok())
        }
        Recognized::P2SH(h) => lookup_raw_hash_20(dir, &h, delta).map(|(pk, sh)| pk || sh),
        Recognized::P2WSH(h) | Recognized::P2MR(h) => lookup_raw_hash_32(dir, &h, delta),
    };
    if !delta.available { return "UNDETERMINED"; }
    match hit {
        Ok(true) => "EXPOSED_AT_REST",
        Ok(false) if dir.join("pubkey_hash_index.bin").exists() => "EXPOSED_ON_SPEND",
        _ => "UNDETERMINED",
    }
}

fn lookup_pubkey_hash_20(dir: &Path, h: &[u8; 20], delta: &DeltaIndex) -> io::Result<bool> {
    Ok(binary_search_file(&dir.join("pubkey_hash_index.bin"), h)? || delta.pk20.binary_search(h).is_ok())
}

fn lookup_raw_hash_20(dir: &Path, h: &[u8; 20], delta: &DeltaIndex) -> io::Result<(bool, bool)> {
    let pk = binary_search_file(&dir.join("pubkey_hash_index.bin"), h)?;
    let sh = binary_search_file(&dir.join("script_hash_index_20.bin"), h)?;
    Ok((pk || delta.pk20.binary_search(h).is_ok(), sh || delta.sh20.binary_search(h).is_ok()))
}

fn lookup_raw_hash_32(dir: &Path, h: &[u8; 32], delta: &DeltaIndex) -> io::Result<bool> {
    Ok(binary_search_file(&dir.join("script_hash_index_32.bin"), h)? || delta.hit32(h))
}

fn lookup_cross_diff_20(dir: &Path, h: &[u8; 20]) -> io::Result<bool> {
    binary_search_file(&dir.join("cross_format_diff_20.bin"), h)
}

fn lookup_cross_diff_32(dir: &Path, h: &[u8; 32]) -> io::Result<bool> {
    binary_search_file(&dir.join("cross_format_diff_32.bin"), h)
}

struct PendingTable {
    path: PathBuf,
    tmp_path: Option<PathBuf>,
    count: u64,
}

fn read_bin_record<const N: usize>(reader: &mut impl Read, path: &Path, offset: u64) -> Result<Option<[u8; N]>, String> {
    let mut record = [0u8; N];
    let mut filled = 0;
    while filled < N {
        match reader.read(&mut record[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(format!("{} record {} at byte offset {}: short read ({}/{} bytes)",
                path.display(), offset / N as u64 + 1, offset, filled, N)),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("{} byte offset {}: read: {}", path.display(), offset + filled as u64, e)),
        }
    }
    Ok(Some(record))
}

fn check_merge_counts(old_count: u64, delta_count: u64, written: u64) -> Result<(), String> {
    let upper = old_count.checked_add(delta_count).ok_or_else(|| "record count overflow".to_string())?;
    if written < old_count || written > upper {
        return Err(format!("record count {} outside [{}, {}]", written, old_count, upper));
    }
    Ok(())
}

fn merge_sorted_bin_file<const N: usize>(bin_path: &Path, mut delta_items: Vec<[u8; N]>, created: &mut Vec<PathBuf>) -> Result<PendingTable, String> {
    let file = File::open(bin_path).map_err(|e| format!("{} byte offset 0: open base table: {}", bin_path.display(), e))?;
    let metadata = file.metadata().map_err(|e| format!("{} byte offset 0: metadata: {}", bin_path.display(), e))?;
    if !metadata.is_file() {
        return Err(format!("{} byte offset 0: base table is not a regular file", bin_path.display()));
    }
    if metadata.len() % N as u64 != 0 {
        return Err(format!("{} record {} at byte offset {}: length {} is not a multiple of {}",
            bin_path.display(), metadata.len() / N as u64 + 1, metadata.len() / N as u64 * N as u64, metadata.len(), N));
    }
    delta_items.sort_unstable();
    delta_items.dedup();
    if delta_items.is_empty() {
        return Ok(PendingTable { path: bin_path.to_path_buf(), tmp_path: None, count: metadata.len() / N as u64 });
    }
    let tmp_path = bin_path.with_extension("bin.tmp");
    let tmp = File::create(&tmp_path).map_err(|e| format!("{} byte offset 0: create: {}", tmp_path.display(), e))?;
    created.push(tmp_path.clone());
    let mut out = BufWriter::with_capacity(256 * 1024, tmp);
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut old_count = 0u64;
    let mut prev = None;
    let mut read_next = |reader: &mut BufReader<File>| -> Result<Option<[u8; N]>, String> {
        let item = read_bin_record(reader, bin_path, old_count * N as u64)?;
        if let Some(cur) = item {
            if prev.is_some_and(|p| p >= cur) {
                return Err(format!("{} record {} at byte offset {}: base table is not strictly ascending",
                    bin_path.display(), old_count + 1, old_count * N as u64));
            }
            prev = Some(cur);
            old_count += 1;
        }
        Ok(item)
    };

    let mut cur_file = read_next(&mut reader)?;
    let mut idx = 0usize;
    let mut total_written = 0u64;

    while cur_file.is_some() || idx < delta_items.len() {
        let item = match (cur_file, delta_items.get(idx)) {
            (Some(f_item), Some(d_item)) => match f_item.cmp(d_item) {
                std::cmp::Ordering::Less => {
                    cur_file = read_next(&mut reader)?;
                    f_item
                }
                std::cmp::Ordering::Greater => {
                    idx += 1;
                    *d_item
                }
                std::cmp::Ordering::Equal => {
                    cur_file = read_next(&mut reader)?;
                    idx += 1;
                    f_item
                }
            },
            (Some(f_item), None) => {
                cur_file = read_next(&mut reader)?;
                f_item
            }
            (None, Some(d_item)) => {
                idx += 1;
                *d_item
            }
            (None, None) => break,
        };
        out.write_all(&item).map_err(|e| format!("{} record {} at byte offset {}: write: {}",
            tmp_path.display(), total_written + 1, total_written * N as u64, e))?;
        total_written += 1;
    }
    let file = finish_synced_file(out, &tmp_path)?;
    check_merge_counts(old_count, delta_items.len() as u64, total_written)
        .map_err(|e| format!("{} byte offset {}: {}", tmp_path.display(), total_written * N as u64, e))?;
    let length = file.metadata().map_err(|e| format!("{} byte offset 0: metadata: {}", tmp_path.display(), e))?.len();
    let expected = total_written.checked_mul(N as u64)
        .ok_or_else(|| format!("{} byte offset 0: output length overflow", tmp_path.display()))?;
    if length != expected {
        return Err(format!("{} byte offset {}: expected length {}, got {}", tmp_path.display(), length, expected, length));
    }
    Ok(PendingTable { path: bin_path.to_path_buf(), tmp_path: Some(tmp_path), count: total_written })
}

fn commit_merged_table(table: &PendingTable) -> Result<(), String> {
    if let Some(tmp) = &table.tmp_path {
        fs::rename(tmp, &table.path).map_err(|e|
            format!("{} byte offset 0: rename over {}: {}", tmp.display(), table.path.display(), e))?;
        sync_parent(&table.path)?;
    }
    Ok(())
}

fn decode_delta_items<const N: usize>(path: &Path, line: usize, field: &str, values: &[String], out: &mut Vec<[u8; N]>) -> Result<(), String> {
    for (i, value) in values.iter().enumerate() {
        let mut bytes = [0u8; N];
        hex::decode_to_slice(value, &mut bytes).map_err(|e|
            format!("{} line {} field {} item {}: expected {}-byte hex: {}", path.display(), line, field, i + 1, N, e))?;
        out.push(bytes);
    }
    Ok(())
}

fn compact_delta(index_dir: &str) -> Result<(), String> {
    let dir = Path::new(index_dir);
    let delta_path = dir.join("delta_blocks.jsonl");
    let file = match File::open(&delta_path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("No delta_blocks.jsonl to compact.");
            return Ok(());
        },
        Err(e) => return Err(format!("{} byte offset 0: open: {}", delta_path.display(), e)),
    };
    let mut pk20: Vec<[u8; 20]> = Vec::new();
    let mut sh20: Vec<[u8; 20]> = Vec::new();
    let mut sh32: Vec<[u8; 32]> = Vec::new();
    let mut blocks_compacted = 0usize;

    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("{} line {}: {}", delta_path.display(), i + 1, e))?;
        let rec: DeltaBlockRecord = serde_json::from_str(&line)
            .map_err(|e| format!("{} line {}: invalid DeltaBlockRecord: {}", delta_path.display(), i + 1, e))?;
        decode_delta_items(&delta_path, i + 1, "kh20", &rec.kh20, &mut pk20)?;
        decode_delta_items(&delta_path, i + 1, "wrapped20", &rec.wrapped20, &mut pk20)?;
        decode_delta_items(&delta_path, i + 1, "sh20", &rec.sh20, &mut sh20)?;
        decode_delta_items(&delta_path, i + 1, "wsh32", &rec.wsh32, &mut sh32)?;
        decode_delta_items(&delta_path, i + 1, "mr32", &rec.mr32, &mut sh32)?;
        blocks_compacted += 1;
    }

    // Every merge is a set union of the base and delta. After a crash with temps
    // written or some tables renamed but the delta still present, --compact again
    // converges to the same tables. Stale *.bin.tmp files are truncated next run.
    let mut created = Vec::new();
    let staged = (|| -> Result<_, String> {
        let pk = merge_sorted_bin_file(&dir.join("pubkey_hash_index.bin"), pk20, &mut created)?;
        let sh20 = merge_sorted_bin_file(&dir.join("script_hash_index_20.bin"), sh20, &mut created)?;
        let sh32 = merge_sorted_bin_file(&dir.join("script_hash_index_32.bin"), sh32, &mut created)?;
        Ok([pk, sh20, sh32])
    })();
    let tables = match staged {
        Ok(tables) => tables,
        Err(e) => {
            for tmp in created {
                if let Err(cleanup) = fs::remove_file(&tmp) {
                    eprintln!("WARNING: {}: remove temporary table: {}", tmp.display(), cleanup);
                }
            }
            return Err(e);
        },
    };
    for table in &tables {
        commit_merged_table(table)?;
    }
    fs::remove_file(&delta_path).map_err(|e| format!("{} byte offset 0: remove: {}", delta_path.display(), e))?;
    sync_parent(&delta_path)?;
    println!(
        "Compacted {} delta blocks into base tables: pubkey_hash={}, sh20={}, sh32={}",
        blocks_compacted, tables[0].count, tables[1].count, tables[2].count
    );
    Ok(())
}

fn query_script(index_dir: &str, spk_hex: &str) {
    let spk = hex::decode(spk_hex.trim()).expect("Invalid scriptPubKey hex");
    let delta = DeltaIndex::load(&Path::new(index_dir).join("delta_blocks.jsonl"));
    match delta {
        Ok(delta) => println!("{}", evaluate_script_level(index_dir, &spk, &delta)),
        Err(e) => { eprintln!("Cannot load delta: {}", e); println!("UNDETERMINED"); }
    }
}

struct HttpRequest {
    path: String,
    head: bool,
}

fn request_remaining(accepted_at: Instant, now: Instant) -> Duration {
    Duration::from_secs(10).saturating_sub(now.saturating_duration_since(accepted_at))
}

struct RequestReader<'a> {
    stream: &'a std::net::TcpStream,
    accepted_at: Instant,
}

impl Read for RequestReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = request_remaining(self.accepted_at, Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request deadline expired"));
        }
        self.stream.set_read_timeout(Some(Duration::from_secs(5).min(remaining)))?;
        let result = self.stream.read(buf);
        if request_remaining(self.accepted_at, Instant::now()).is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request deadline expired"));
        }
        result
    }
}

fn request_read_error(error: io::Error, head: bool) -> (u16, bool) {
    let code = if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) { 408 } else { 400 };
    (code, head)
}

fn read_http_request(reader: &mut impl BufRead) -> Result<HttpRequest, (u16, bool)> {
    let mut line = Vec::new();
    (&mut *reader).take(8193).read_until(b'\n', &mut line).map_err(|e| request_read_error(e, false))?;
    if line.len() > 8192 { return Err((414, false)); }
    let head = line.starts_with(b"HEAD ");
    if !line.ends_with(b"\r\n") { return Err((400, head)); }
    let text = std::str::from_utf8(&line).map_err(|_| (400u16, head))?;
    let parts: Vec<_> = text.trim_end_matches("\r\n").split(' ').collect();
    if parts.len() != 3 || !parts[1].starts_with('/')
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
        || parts[0].is_empty() || !parts[0].bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || parts[1].bytes().any(|b| b.is_ascii_control()) {
        return Err((400, head));
    }
    let method = parts[0].to_owned();
    let path = parts[1].to_owned();
    let mut total = 0;
    loop {
        line.clear();
        let remaining = 65536 - total;
        (&mut *reader).take((remaining + 1) as u64).read_until(b'\n', &mut line).map_err(|e| request_read_error(e, head))?;
        total += line.len();
        if total > 65536 || !line.ends_with(b"\r\n") { return Err((400, head)); }
        if line == b"\r\n" { break; }
        if !line.contains(&b':') || total == 65536 { return Err((400, head)); }
    }
    if method != "GET" && method != "HEAD" { return Err((405, head)); }
    Ok(HttpRequest { path, head })
}

fn write_http_response(mut stream: &std::net::TcpStream, status: &str, body: &str, head: bool) -> io::Result<()> {
    let allow = if status.starts_with("405") { "Allow: GET, HEAD\r\n" } else { "" };
    write!(stream, "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        status, body.len(), allow)?;
    if !head { stream.write_all(body.as_bytes())?; }
    Ok(())
}

fn serve_http(index_dir: &str, bind_addr: &str) {
    let listener = Arc::new(std::net::TcpListener::bind(bind_addr).expect("Failed to bind HTTP port"));
    let shared = Arc::new(RwLock::new(Arc::new(DeltaIndex::default())));
    let reload_shared = Arc::clone(&shared);
    let delta_path = Path::new(index_dir).join("delta_blocks.jsonl");
    std::thread::spawn(move || loop {
        let current = Arc::clone(&reload_shared.read().unwrap());
        match delta_signature(&delta_path) {
            Ok(signature) if !current.available || signature != current.signature => {
                match DeltaIndex::load(&delta_path) {
                    Ok(index) => *reload_shared.write().unwrap() = Arc::new(index),
                    Err(e) => eprintln!("Delta reload failed: {}", e),
                }
            }
            Err(e) => eprintln!("Delta stat failed: {}", e),
            _ => {}
        }
        std::thread::sleep(Duration::from_secs(2));
    });
    let threads = env::var("BTC_INDEXER_THREADS").ok()
        .and_then(|s| s.parse::<usize>().ok()).filter(|n| *n > 0).unwrap_or(8);
    println!("Exposure index HTTP server listening on {} ({} workers)", bind_addr, threads);
    let mut workers = Vec::new();
    for _ in 0..threads {
        let listener = Arc::clone(&listener);
        let shared = Arc::clone(&shared);
        let index_dir = index_dir.to_owned();
        workers.push(std::thread::spawn(move || loop {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) => { eprintln!("HTTP accept failed: {}", e); continue; }
            };
            let accepted_at = Instant::now();
            if stream.set_write_timeout(Some(Duration::from_secs(30))).is_err() { continue; }
            let mut path = String::from("<unread request>");
            let mut head = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let request = read_http_request(&mut BufReader::new(RequestReader { stream: &stream, accepted_at }));
                let (status, body) = match request {
                    Ok(request) => {
                        path = request.path;
                        head = request.head;
                        let delta = Arc::clone(&shared.read().unwrap());
                        http_response(&index_dir, &path, &delta)
                            .unwrap_or_else(|_| ("503 Service Unavailable", r#"{"error":"index unavailable"}"#.to_owned()))
                    }
                    Err((code, request_head)) => {
                        head = request_head;
                        let status = match code {
                            405 => "405 Method Not Allowed",
                            408 => "408 Request Timeout",
                            414 => "414 URI Too Long",
                            _ => "400 Bad Request",
                        };
                        (status, serde_json::json!({"error": status}).to_string())
                    }
                };
                write_http_response(&stream, status, &body, head)
            }));
            let response = match result {
                Ok(response) => response,
                Err(_) => {
                    eprintln!("HTTP request panicked: {}", path);
                    write_http_response(&stream, "500 Internal Server Error", r#"{"error":"internal error"}"#, head)
                }
            };
            if let Err(e) = response {
                eprintln!("HTTP response failed: {}", e);
            }
        }));
    }
    for worker in workers { worker.join().expect("HTTP worker panicked"); }
}

fn http_response(index_dir: &str, path: &str, delta: &DeltaIndex) -> io::Result<(&'static str, String)> {
    let dir = Path::new(index_dir);
    let ready = dir.join("pubkey_hash_index.bin").exists();
    let last_h = fs::read_to_string(dir.join("last_indexed_height")).ok()
        .and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    if path.split('?').next() == Some("/snapshots/manifest.json") {
        return Ok(match fs::read_to_string(dir.parent().unwrap_or(dir).join("snapshots/manifest.json")) {
            Ok(body) => ("200 OK", body),
            Err(e) if e.kind() == io::ErrorKind::NotFound => ("404 Not Found", r#"{"error":"manifest not found"}"#.to_owned()),
            Err(e) => return Err(e),
        });
    }
    if path.starts_with("/snapshots/download/") || path == "/snapshots/download" {
        return Ok(("410 Gone", r#"{"error":"downloads moved","manifest":"/snapshots/manifest.json"}"#.to_owned()));
    }
    if path.starts_with("/lookup/") && !delta.available {
        return Err(io::Error::new(io::ErrorKind::Other, "delta unavailable"));
    }
    let response = if path == "/readyz" {
        if ready && delta.available {
            ("200 OK", serde_json::json!({"ready": true, "delta_ready": true}).to_string())
        } else {
            let reason = if !ready { "base index unavailable" } else { "delta unavailable" };
            ("503 Service Unavailable", serde_json::json!({"ready": false, "reason": reason}).to_string())
        }
    } else if path == "/healthz" {
        let stats_val: serde_json::Value = fs::read_to_string(dir.join("stats.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Null);
        (
            "200 OK",
            serde_json::json!({
                "status": "ok",
                "base_index_ready": ready,
                "delta_ready": delta.available,
                "last_indexed_height": last_h,
                "stats": stats_val,
                "delta_blocks": delta.heights.len(),
                "delta_max_height": delta.max_height,
                "delta_loaded_at": delta.loaded_at,
                "delta_entries_20": delta.pk20.len() + delta.sh20.len(),
                "delta_entries_32": delta.sh32.len()
            })
            .to_string(),
        )
    } else if let Some(hex_str) = path.strip_prefix("/lookup/diff/") {
        let clean = hex_str.split('?').next().unwrap_or("").trim().to_lowercase();
        match hex::decode(&clean) {
            Ok(bytes) if bytes.len() == 20 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(&bytes);
                let in_diff = lookup_cross_diff_20(dir, &h)?;
                (
                    "200 OK",
                    serde_json::json!({
                        "hash": clean,
                        "byte_len": 20,
                        "delta_hit": delta.hit20(&h),
                        "in_cross_format_diff": in_diff,
                        "base_index_ready": ready,
                        "last_indexed_height": last_h
                    })
                    .to_string(),
                )
            }
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes);
                let in_diff = lookup_cross_diff_32(dir, &h)?;
                (
                    "200 OK",
                    serde_json::json!({
                        "hash": clean,
                        "byte_len": 32,
                        "delta_hit": delta.hit32(&h),
                        "in_cross_format_diff": in_diff,
                        "base_index_ready": ready,
                        "last_indexed_height": last_h
                    })
                    .to_string(),
                )
            }
            _ => (
                "400 Bad Request",
                r#"{"error":"expected 20-byte (40 hex) or 32-byte (64 hex) hash"}"#.to_string(),
            ),
        }
    } else if let Some(hex_str) = path.strip_prefix("/lookup/hash/") {
        let clean = hex_str.split('?').next().unwrap_or("").trim().to_lowercase();
        match hex::decode(&clean) {
            Ok(bytes) if bytes.len() == 20 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(&bytes);
                let (in_pk, in_sh20) = lookup_raw_hash_20(dir, &h, delta)?;
                let in_diff = lookup_cross_diff_20(dir, &h)?;
                (
                    "200 OK",
                    serde_json::json!({
                        "hash": clean,
                        "byte_len": 20,
                        "delta_hit": delta.hit20(&h),
                        "in_pubkey_hash_index": in_pk,
                        "in_script_hash_20_index": in_sh20,
                        "in_script_hash_32_index": false,
                        "in_cross_format_diff": in_diff,
                        "base_index_ready": ready,
                        "last_indexed_height": last_h
                    })
                    .to_string(),
                )
            }
            Ok(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes);
                let in_sh32 = lookup_raw_hash_32(dir, &h, delta)?;
                let in_diff = lookup_cross_diff_32(dir, &h)?;
                (
                    "200 OK",
                    serde_json::json!({
                        "hash": clean,
                        "byte_len": 32,
                        "delta_hit": delta.hit32(&h),
                        "in_pubkey_hash_index": false,
                        "in_script_hash_20_index": false,
                        "in_script_hash_32_index": in_sh32,
                        "in_cross_format_diff": in_diff,
                        "base_index_ready": ready,
                        "last_indexed_height": last_h
                    })
                    .to_string(),
                )
            }
            _ => (
                "400 Bad Request",
                r#"{"error":"expected 20-byte (40 hex) or 32-byte (64 hex) hash"}"#.to_string(),
            ),
        }
    } else if let Some(hex_str) = path.strip_prefix("/lookup/pubkey/") {
        let clean = hex_str.split('?').next().unwrap_or("").trim().to_lowercase();
        match hex::decode(&clean) {
            Ok(bytes) => {
                let xonly = bytes.len() == 32;
                if let Some(x) = key_x(&bytes, xonly) {
                    if let Some((kh, wrapped)) = key_hashes_from_x(&x) {
                        let mut any_published = false;
                        for h in &kh {
                            if lookup_pubkey_hash_20(dir, h, delta)? {
                                any_published = true;
                                break;
                            }
                        }
                        if !any_published {
                            for w in &wrapped {
                                if lookup_pubkey_hash_20(dir, w, delta)? {
                                    any_published = true;
                                    break;
                                }
                            }
                        }
                        let kh_hex: Vec<String> = kh.iter().map(hex::encode).collect();
                        let w_hex: Vec<String> = wrapped.iter().map(hex::encode).collect();
                        (
                            "200 OK",
                            serde_json::json!({
                                "input_pubkey": clean,
                                "valid_curve_point": true,
                                "x_coord": hex::encode(x),
                                "published_on_chain": any_published,
                                "derived_key_hashes_20": kh_hex,
                                "derived_wrapped_p2sh_p2wpkh_hashes_20": w_hex,
                                "base_index_ready": ready,
                                "last_indexed_height": last_h
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            "200 OK",
                            serde_json::json!({
                                "input_pubkey": clean,
                                "valid_curve_point": false,
                                "published_on_chain": false,
                                "base_index_ready": ready,
                                "last_indexed_height": last_h
                            })
                            .to_string(),
                        )
                    }
                } else {
                    (
                        "200 OK",
                        serde_json::json!({
                            "input_pubkey": clean,
                            "valid_curve_point": false,
                            "published_on_chain": false,
                            "base_index_ready": ready,
                            "last_indexed_height": last_h
                        })
                        .to_string(),
                    )
                }
            }
            Err(_) => ("400 Bad Request", r#"{"error":"invalid hex"}"#.to_string()),
        }
    } else if let Some(hex_str) = path.strip_prefix("/lookup/script/") {
        let clean = hex_str.split('?').next().unwrap_or("").trim().to_lowercase();
        match hex::decode(&clean) {
            Ok(spk) => {
                let (script_type, target_hash, in_pk, in_sh20, in_sh32, structural_key_valid) =
                    match recognize(&spk, false) {
                        Recognized::Unclassified => ("UNCLASSIFIED", None, false, false, false, None),
                        Recognized::Unknown => ("UNKNOWN", None, false, false, false, None),
                        Recognized::P2PK(k) => (
                            "P2PK",
                            Some(hex::encode(k)),
                            false,
                            false,
                            false,
                            Some(key_x(k, false).is_some()),
                        ),
                        Recognized::P2TR(k) => (
                            "P2TR",
                            Some(hex::encode(k)),
                            false,
                            false,
                            false,
                            Some(key_x(k, true).is_some()),
                        ),
                        Recognized::Multisig { required, keys } => {
                            let valid = keys.iter().filter(|k| key_x(k, false).is_some()).count();
                            ("BARE_MULTISIG", None, false, false, false, Some(valid >= required))
                        }
                        Recognized::P2PKH(h) => {
                            let (pk, sh) = lookup_raw_hash_20(dir, &h, delta)?;
                            ("P2PKH", Some(hex::encode(h)), pk, sh, false, None)
                        }
                        Recognized::P2WPKH(h) => {
                            let (pk, sh) = lookup_raw_hash_20(dir, &h, delta)?;
                            ("P2WPKH", Some(hex::encode(h)), pk, sh, false, None)
                        }
                        Recognized::P2SH(h) => {
                            let (pk, sh) = lookup_raw_hash_20(dir, &h, delta)?;
                            ("P2SH", Some(hex::encode(h)), pk, sh, false, None)
                        }
                        Recognized::P2WSH(h) => {
                            let sh32 = lookup_raw_hash_32(dir, &h, delta)?;
                            ("P2WSH", Some(hex::encode(h)), false, false, sh32, None)
                        }
                        Recognized::P2MR(h) => {
                            let sh32 = lookup_raw_hash_32(dir, &h, delta)?;
                            ("P2MR", Some(hex::encode(h)), false, false, sh32, None)
                        }
                    };
                (
                    "200 OK",
                    serde_json::json!({
                        "script_pubkey": clean,
                        "script_type": script_type,
                        "delta_hit": delta.script_hit(&spk),
                        "target_hash": target_hash,
                        "structural_key_valid": structural_key_valid,
                        "in_pubkey_hash_index": in_pk,
                        "in_script_hash_20_index": in_sh20,
                        "in_script_hash_32_index": in_sh32,
                        "base_index_ready": ready,
                        "last_indexed_height": last_h
                    })
                    .to_string(),
                )
            }
            Err(_) => ("400 Bad Request", r#"{"error":"invalid hex"}"#.to_string()),
        }
    } else if let Some(q) = path.strip_prefix("/lookup/batch?hashes=") {
        let mut results = serde_json::Map::new();
        for item in q.split(',').take(200) {
            let clean = item.trim().to_lowercase();
            if clean.is_empty() {
                continue;
            }
            if let Ok(bytes) = hex::decode(&clean) {
                if bytes.len() == 20 {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(&bytes);
                    let (in_pk, in_sh20) = lookup_raw_hash_20(dir, &h, delta)?;
                    results.insert(
                        clean,
                        serde_json::json!({
                            "byte_len": 20,
                        "delta_hit": delta.hit20(&h),
                            "in_pubkey_hash_index": in_pk,
                            "in_script_hash_20_index": in_sh20,
                            "in_script_hash_32_index": false
                        }),
                    );
                } else if bytes.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&bytes);
                    let in_sh32 = lookup_raw_hash_32(dir, &h, delta)?;
                    results.insert(
                        clean,
                        serde_json::json!({
                            "byte_len": 32,
                        "delta_hit": delta.hit32(&h),
                            "in_pubkey_hash_index": false,
                            "in_script_hash_20_index": false,
                            "in_script_hash_32_index": in_sh32
                        }),
                    );
                }
            }
        }
        (
            "200 OK",
            serde_json::json!({
                "base_index_ready": ready,
                "last_indexed_height": last_h,
                "results": results
            })
            .to_string(),
        )
    } else if let Some(hex_str) = path.strip_prefix("/classify/") {
        let clean = hex_str.split('?').next().unwrap_or("").trim();
        match hex::decode(clean) {
            Ok(spk) => {
                let level = evaluate_script_level(index_dir, &spk, delta);
                let action = match level {
                    "EXPOSED_AT_REST" | "UNDETERMINED" => "MIGRATE",
                    "EXPOSED_ON_SPEND" => "SWEEP_WHEN_SPENDING",
                    "NOT_EXPOSED" => "NONE",
                    _ => "NONE",
                };
                (
                    "200 OK",
                    format!(
                        r#"{{"script_pubkey":"{}","level":"{}","action":"{}"}}"#,
                        clean, level, action
                    ),
                )
            }
            Err(_) => ("400 Bad Request", r#"{"error":"invalid hex"}"#.to_string()),
        }
    } else {
        ("404 Not Found", r#"{"error":"not found"}"#.to_string())
    };
    Ok(response)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--self-test" {
        run_self_test(&args[2]);
    } else if args.len() >= 4 && args[1] == "--scan-blocks" {
        scan_blocks_dir(&args[2], &args[3]);
    } else if args.len() >= 5 && args[1] == "--apply-block-hex" {
        let result = args[3].parse::<u64>()
            .map_err(|e| format!("height argument {:?}: {}", args[3], e))
            .and_then(|height| apply_block_hex(&args[2], height, &args[4]));
        if let Err(e) = result {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    } else if args.len() >= 4 && args[1] == "--query" {
        query_script(&args[2], &args[3]);
    } else if args.len() >= 3 && args[1] == "--compact" {
        if let Err(e) = compact_delta(&args[2]) {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    } else if args.len() >= 4 && args[1] == "--serve" {
        serve_http(&args[2], &args[3]);
    } else {
        eprintln!("Usage:");
        eprintln!("  btc-indexer --self-test <test_vectors_070.json>");
        eprintln!("  btc-indexer --scan-blocks <blocks_dir> <out_dir>");
        eprintln!("  btc-indexer --apply-block-hex <index_dir> <height> <block_hash>");
        eprintln!("  btc-indexer --compact <index_dir>");
        eprintln!("  btc-indexer --query <index_dir> <script_pubkey_hex>");
        eprintln!("  btc-indexer --serve <index_dir> <bind_addr>");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const TABLES: [&str; 3] = ["pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin"];

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> io::Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = env::temp_dir().join(format!("btc-integrity-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?.as_nanos(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
        fn tables(&self) -> io::Result<()> {
            fs::write(self.0.join(TABLES[0]), [2; 20])?;
            fs::write(self.0.join(TABLES[1]), [2; 20])?;
            fs::write(self.0.join(TABLES[2]), [2; 32])
        }
        fn snapshot(&self) -> io::Result<Vec<Vec<u8>>> {
            TABLES.iter().chain(std::iter::once(&"delta_blocks.jsonl"))
                .map(|name| fs::read(self.0.join(name))).collect()
        }
        fn no_table_temps(&self) {
            for name in TABLES {
                assert!(!self.0.join(name).with_extension("bin.tmp").exists());
            }
        }
        fn compact(&self) -> Result<(), String> {
            compact_delta(self.0.to_str().ok_or_else(|| "non-UTF-8 test directory".to_string())?)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            if let Err(e) = fs::remove_dir_all(&self.0) {
                eprintln!("WARNING: {}: test cleanup: {}", self.0.display(), e);
            }
        }
    }

    fn delta_record(height: u64) -> DeltaBlockRecord {
        DeltaBlockRecord {
            height, block_hash: hex::encode([1; 32]),
            kh20: vec![hex::encode([1; 20]), hex::encode([1; 20])],
            wrapped20: vec![hex::encode([3; 20])], sh20: vec![hex::encode([3; 20])],
            wsh32: vec![hex::encode([1; 32])], mr32: vec![hex::encode([3; 32])],
        }
    }

    #[test]
    fn record_reader_distinguishes_eof_short_reads_and_io_errors() -> TestResult {
        struct Fragmented { bytes: io::Cursor<Vec<u8>>, interrupted: bool, fail: bool }
        impl Read for Fragmented {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                if self.fail { return Err(io::Error::from(io::ErrorKind::PermissionDenied)); }
                let n = buf.len().min(2);
                self.bytes.read(&mut buf[..n])
            }
        }
        let path = Path::new("test.bin");
        let mut reader = Fragmented { bytes: io::Cursor::new(vec![7; 4]), interrupted: false, fail: false };
        assert_eq!(read_bin_record::<4>(&mut reader, path, 0)?, Some([7; 4]));
        assert_eq!(read_bin_record::<4>(&mut reader, path, 4)?, None);
        let error = read_bin_record::<4>(&mut io::Cursor::new([7; 3]), path, 8).err();
        assert!(error.is_some_and(|e| e.contains("test.bin") && e.contains("offset 8") && e.contains("short read")));
        reader.fail = true;
        assert!(read_bin_record::<4>(&mut reader, path, 4).is_err());
        Ok(())
    }

    #[test]
    fn merge_missing_base_including_empty_delta() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join(TABLES[0]);
        for delta in [vec![], vec![[1; 20]]] {
            let mut created = Vec::new();
            assert!(merge_sorted_bin_file(&path, delta, &mut created).is_err());
            assert!(created.is_empty() && !path.exists());
            temp.no_table_temps();
        }
        fs::create_dir(&path)?;
        assert!(merge_sorted_bin_file(&path, vec![[1; 20]], &mut Vec::new()).is_err());
        temp.no_table_temps();
        Ok(())
    }

    #[test]
    fn merge_rejects_short_unsorted_and_duplicate_base() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join(TABLES[0]);
        for original in [vec![1; 21], [[3; 20], [2; 20]].concat(), [[2; 20], [2; 20]].concat()] {
            fs::write(&path, &original)?;
            let mut created = Vec::new();
            assert!(merge_sorted_bin_file(&path, vec![[1; 20]], &mut created).is_err());
            assert_eq!(fs::read(&path)?, original);
            for tmp in created { fs::remove_file(tmp)?; }
        }
        Ok(())
    }

    #[test]
    fn merge_empty_delta_checks_metadata_without_reading() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join(TABLES[0]);
        fs::write(&path, [[3; 20], [2; 20]].concat())?;
        let mut created = Vec::new();
        let table = merge_sorted_bin_file::<20>(&path, vec![], &mut created)?;
        assert_eq!(table.count, 2);
        assert!(table.tmp_path.is_none() && created.is_empty());
        fs::write(&path, [1; 21])?;
        assert!(merge_sorted_bin_file::<20>(&path, vec![], &mut created).is_err());
        temp.no_table_temps();
        Ok(())
    }

    #[test]
    fn merge_count_bounds() {
        assert!(check_merge_counts(3, 2, 2).is_err());
        assert!(check_merge_counts(3, 2, 6).is_err());
        assert!(check_merge_counts(u64::MAX, 1, u64::MAX).is_err());
        for written in 3..=5 { assert!(check_merge_counts(3, 2, written).is_ok()); }
        assert!(check_merge_counts(0, 0, 0).is_ok());
    }

    #[test]
    fn merge_writes_sorted_union() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join(TABLES[0]);
        let original = [[2; 20], [4; 20]].concat();
        fs::write(&path, &original)?;
        let mut created = Vec::new();
        let table = merge_sorted_bin_file(&path, vec![[5; 20], [1; 20], [2; 20], [1; 20]], &mut created)?;
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(table.count, 4);
        commit_merged_table(&table)?;
        assert_eq!(fs::read(&path)?, [[1; 20], [2; 20], [4; 20], [5; 20]].concat());
        temp.no_table_temps();
        Ok(())
    }

    #[test]
    fn compact_rejects_bad_delta_lines_without_changes() -> TestResult {
        let temp = TempDir::new()?;
        temp.tables()?;
        let good = serde_json::to_string(&delta_record(1))? + "\n";
        let mut bad_lines = vec![b"{broken}\n".to_vec(), b"\n".to_vec(), b"{}\n".to_vec(), vec![0xff, b'\n']];
        for field in ["kh20", "wrapped20", "sh20", "wsh32", "mr32"] {
            let n = if field.ends_with("20") { 20 } else { 32 };
            for value in ["z".repeat(n * 2), "00".repeat(n - 1), "00".repeat(n + 1)] {
                let mut rec = serde_json::to_value(delta_record(2))?;
                rec[field] = serde_json::json!([value]);
                bad_lines.push((serde_json::to_string(&rec)? + "\n").into_bytes());
            }
        }
        for bad in bad_lines {
            fs::write(temp.0.join("delta_blocks.jsonl"), [good.as_bytes(), &bad].concat())?;
            let before = temp.snapshot()?;
            let error = temp.compact().err();
            assert!(error.is_some_and(|e| e.contains("delta_blocks.jsonl line 2")));
            assert_eq!(temp.snapshot()?, before);
            temp.no_table_temps();
        }
        Ok(())
    }

    #[test]
    fn compact_later_table_failure_keeps_all_originals() -> TestResult {
        let temp = TempDir::new()?;
        temp.tables()?;
        fs::write(temp.0.join(TABLES[2]), [[3; 32], [2; 32]].concat())?;
        fs::write(temp.0.join("delta_blocks.jsonl"), serde_json::to_string(&delta_record(1))? + "\n")?;
        let before = temp.snapshot()?;
        assert!(temp.compact().is_err());
        assert_eq!(temp.snapshot()?, before);
        temp.no_table_temps();
        Ok(())
    }

    #[test]
    fn compact_crash_recovery_and_repeat_are_idempotent() -> TestResult {
        let clean = TempDir::new()?;
        let crash = TempDir::new()?;
        let delta = serde_json::to_string(&delta_record(1))? + "\n";
        for temp in [&clean, &crash] {
            temp.tables()?;
            fs::write(temp.0.join("delta_blocks.jsonl"), &delta)?;
        }
        clean.compact()?;
        let mut created = Vec::new();
        let pk = merge_sorted_bin_file(&crash.0.join(TABLES[0]), vec![[1; 20], [3; 20]], &mut created)?;
        let _sh20 = merge_sorted_bin_file(&crash.0.join(TABLES[1]), vec![[3; 20]], &mut created)?;
        let _sh32 = merge_sorted_bin_file(&crash.0.join(TABLES[2]), vec![[1; 32], [3; 32]], &mut created)?;
        commit_merged_table(&pk)?;
        assert!(crash.0.join(TABLES[1]).with_extension("bin.tmp").exists());
        assert!(crash.0.join("delta_blocks.jsonl").exists());
        crash.compact()?;
        for name in TABLES { assert_eq!(fs::read(crash.0.join(name))?, fs::read(clean.0.join(name))?); }
        assert!(!crash.0.join("delta_blocks.jsonl").exists());
        crash.no_table_temps();
        fs::write(crash.0.join("delta_blocks.jsonl"), &delta)?;
        crash.compact()?;
        for name in TABLES { assert_eq!(fs::read(crash.0.join(name))?, fs::read(clean.0.join(name))?); }
        assert!(!crash.0.join("delta_blocks.jsonl").exists());
        crash.no_table_temps();
        Ok(())
    }

    #[test]
    fn compact_missing_delta_noop_and_open_error() -> TestResult {
        let temp = TempDir::new()?;
        temp.compact()?;
        assert_eq!(fs::read_dir(&temp.0)?.count(), 0);
        fs::create_dir(temp.0.join("delta_blocks.jsonl"))?;
        assert!(temp.compact().is_err());
        temp.no_table_temps();
        Ok(())
    }

    // Independent serializer: build both forms directly from transaction components.
    struct TestTx {
        coinbase: bool,
        script_sig: Vec<u8>,
        outputs: Vec<Vec<u8>>,
        witness: Vec<Vec<u8>>,
    }
    fn put_count(out: &mut Vec<u8>, n: usize) {
        match n {
            0..=252 => out.push(n as u8),
            253..=65535 => { out.push(253); out.extend_from_slice(&(n as u16).to_le_bytes()); },
            65536..=0xffff_ffff => { out.push(254); out.extend_from_slice(&(n as u32).to_le_bytes()); },
            _ => { out.push(255); out.extend_from_slice(&(n as u64).to_le_bytes()); },
        }
    }
    impl TestTx {
        fn serialize(&self, full: bool) -> Vec<u8> {
            let mut bytes = 2u32.to_le_bytes().to_vec();
            let segwit = full && !self.witness.is_empty();
            if segwit { bytes.extend_from_slice(&[0, 1]); }
            put_count(&mut bytes, 1);
            bytes.extend_from_slice(&if self.coinbase { [0; 32] } else { [9; 32] });
            bytes.extend_from_slice(&(if self.coinbase { u32::MAX } else { 1u32 }).to_le_bytes());
            put_count(&mut bytes, self.script_sig.len());
            bytes.extend_from_slice(&self.script_sig);
            bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            put_count(&mut bytes, self.outputs.len());
            for output in &self.outputs {
                bytes.extend_from_slice(&50u64.to_le_bytes());
                put_count(&mut bytes, output.len());
                bytes.extend_from_slice(output);
            }
            if segwit {
                put_count(&mut bytes, self.witness.len());
                for item in &self.witness {
                    put_count(&mut bytes, item.len());
                    bytes.extend_from_slice(item);
                }
            }
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes
        }
    }
    fn test_root(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 { hashes.push(hashes[hashes.len() - 1]); }
            hashes = hashes.chunks_exact(2).map(|p| double_sha256(&p.concat())).collect();
        }
        hashes[0]
    }
    fn fixture() -> Vec<TestTx> {
        let spend = TestTx { coinbase: false, script_sig: vec![], outputs: vec![vec![0x51]],
            witness: vec![vec![0x31; 253], vec![0x51]] };
        let legacy = TestTx { coinbase: false, script_sig: vec![1, 7], outputs: vec![vec![0x51]], witness: vec![] };
        let root = test_root(vec![[0; 32], double_sha256(&spend.serialize(true)), double_sha256(&legacy.serialize(true))]);
        let reserved = vec![0x42; 32];
        let commitment = double_sha256(&[root.as_slice(), &reserved].concat());
        let prefix = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let coinbase = TestTx { coinbase: true, script_sig: vec![1, 1],
            // The higher matching output wins, and bytes after the commitment are allowed.
            outputs: vec![[prefix.as_slice(), &[0; 32]].concat(), vec![0x51],
                [prefix.as_slice(), commitment.as_slice(), &[0x99]].concat()], witness: vec![reserved] };
        vec![coinbase, spend, legacy]
    }
    fn block_bytes(txs: &[TestTx], full: bool) -> Vec<u8> {
        let mut bytes = vec![0; 80];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        let root = test_root(txs.iter().map(|tx| double_sha256(&tx.serialize(false))).collect());
        bytes[36..68].copy_from_slice(&root);
        put_count(&mut bytes, txs.len());
        for tx in txs { bytes.extend_from_slice(&tx.serialize(full)); }
        bytes
    }
    fn header_hash(bytes: &[u8]) -> String {
        let mut hash = double_sha256(&bytes[..80]);
        hash.reverse();
        hex::encode(hash)
    }
    fn rejected_without_change(bytes: &[u8], hash: &str, message: &str) -> TestResult {
        let temp = TempDir::new()?;
        let valid = block_bytes(&fixture(), true);
        apply_block(&temp.0, SEGWIT_ACTIVATION_HEIGHT, &header_hash(&valid), &hex::encode(&valid))?;
        let path = temp.0.join("delta_blocks.jsonl");
        let before = fs::read(&path)?;
        let error = apply_block(&temp.0, SEGWIT_ACTIVATION_HEIGHT + 1, hash, &hex::encode(bytes)).err();
        assert!(error.is_some_and(|e| e.contains(message)), "expected error containing {message}");
        assert_eq!(fs::read(&path)?, before);
        assert!(!temp.0.join("delta_blocks.jsonl.tmp").exists());
        Ok(())
    }

    #[test]
    fn apply_synthetic_block_and_height_replacement() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join("delta_blocks.jsonl");
        let original = format!("  {}  \n", serde_json::to_string(&delta_record(1))?);
        fs::write(&path, &original)?;
        let txs = fixture();
        for tx in &txs {
            let full = tx.serialize(true);
            let parsed = parse_single_transaction(&full).ok_or("test transaction did not parse")?;
            let (txid, wtxid) = transaction_hashes(&full, &parsed)?;
            assert_eq!(txid, double_sha256(&tx.serialize(false)));
            assert_eq!(wtxid, double_sha256(&full));
        }
        let bytes = block_bytes(&txs, true);
        let hash = header_hash(&bytes);
        for height in [SEGWIT_ACTIVATION_HEIGHT, SEGWIT_ACTIVATION_HEIGHT + 1, SEGWIT_ACTIVATION_HEIGHT] {
            apply_block(&temp.0, height, &hash, &hex::encode(&bytes))?;
        }
        let journal = fs::read_to_string(&path)?;
        assert!(journal.starts_with(&original));
        let records: Vec<DeltaBlockRecord> = journal.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].height, SEGWIT_ACTIVATION_HEIGHT);
        assert_eq!(records[1].block_hash, hash);
        assert!(!records[1].wsh32.is_empty());
        assert!(!temp.0.join("delta_blocks.jsonl.tmp").exists());
        let empty = TempDir::new()?;
        apply_block(&empty.0, SEGWIT_ACTIVATION_HEIGHT, &hash, &hex::encode(&bytes))?;
        assert_eq!(fs::read_to_string(empty.0.join("delta_blocks.jsonl"))?.lines().count(), 1);
        Ok(())
    }

    #[test]
    fn apply_rejects_truncation_and_trailing_bytes() -> TestResult {
        let bytes = block_bytes(&fixture(), true);
        let hash = header_hash(&bytes);
        rejected_without_change(&bytes[..bytes.len() - 1], &hash, "transaction 2")?;
        let mut trailing = bytes;
        trailing.extend_from_slice(&[0, 0]);
        rejected_without_change(&trailing, &hash, "2 trailing bytes")
    }

    #[test]
    fn apply_rejects_wrong_header_hash() -> TestResult {
        let bytes = block_bytes(&fixture(), true);
        rejected_without_change(&bytes, &hex::encode([0; 32]), "header hash mismatch")?;
        for bad in ["aa".to_string(), "z".repeat(64)] {
            rejected_without_change(&bytes, &bad, "invalid block_hash argument")?;
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_non_witness_mutation() -> TestResult {
        let txs = fixture();
        let mut bytes = block_bytes(&txs, true);
        let hash = header_hash(&bytes);
        bytes[81 + txs[0].serialize(true).len()] ^= 1; // Second transaction's version.
        rejected_without_change(&bytes, &hash, "transaction merkle root mismatch")
    }

    #[test]
    fn apply_rejects_witness_mutation() -> TestResult {
        let mut txs = fixture();
        txs[1].witness[0][0] ^= 1;
        let bytes = block_bytes(&txs, true);
        rejected_without_change(&bytes, &header_hash(&bytes), "witness commitment mismatch")
    }

    #[test]
    fn apply_rejects_concatenated_partial_and_full_blocks() -> TestResult {
        let txs = fixture();
        let bytes = block_bytes(&txs, true);
        for cut in [81 + txs[0].serialize(true).len(), 81 + txs[0].serialize(true).len() + 20] {
            let joined_hex = format!("{}{}", hex::encode(&bytes[..cut]), hex::encode(&bytes));
            rejected_without_change(&hex::decode(joined_hex)?, &header_hash(&bytes), "block stdin")?;
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_stripped_segwit_block_after_activation() -> TestResult {
        let bytes = block_bytes(&fixture(), false);
        let hash = header_hash(&bytes);
        rejected_without_change(&bytes, &hash, "invalid witness reserved value")?;
        let temp = TempDir::new()?;
        apply_block(&temp.0, SEGWIT_ACTIVATION_HEIGHT - 1, &hash, &hex::encode(bytes))?;
        Ok(())
    }

    #[test]
    fn apply_rejects_invalid_witness_commitment_and_reserved_value() -> TestResult {
        for case in 0..6 {
            let mut txs = fixture();
            let expected = match case {
                0 => { txs[0].outputs = vec![vec![0x51]]; "missing witness commitment" },
                1 => { txs[0].witness = vec![vec![0; 31]]; "invalid witness reserved value" },
                2 => { txs[0].witness.push(vec![]); "invalid witness reserved value" },
                3 => { txs[0].witness.clear(); "invalid witness reserved value" },
                4 => { txs[0].outputs[2][6] ^= 1; "witness commitment mismatch" },
                _ => { txs[0].witness[0][0] ^= 1; "witness commitment mismatch" },
            };
            let bytes = block_bytes(&txs, true);
            rejected_without_change(&bytes, &header_hash(&bytes), expected)?;
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_corrupt_existing_delta() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.0.join("delta_blocks.jsonl");
        let bytes = block_bytes(&fixture(), true);
        let first = serde_json::to_string(&delta_record(1))? + "\n";
        for bad in [b"{broken}\n".to_vec(), b"\n".to_vec(), vec![0xff, b'\n']] {
            let before = [first.as_bytes(), &bad].concat();
            fs::write(&path, &before)?;
            let error = apply_block(&temp.0, SEGWIT_ACTIVATION_HEIGHT, &header_hash(&bytes), &hex::encode(&bytes)).err();
            assert!(error.is_some_and(|e| e.contains("delta_blocks.jsonl line 2")));
            assert_eq!(fs::read(&path)?, before);
            assert!(!temp.0.join("delta_blocks.jsonl.tmp").exists());
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_zero_transactions_and_invalid_count() -> TestResult {
        let bytes = block_bytes(&fixture(), true);
        let hash = header_hash(&bytes);
        let mut zero = bytes[..80].to_vec();
        zero.push(0);
        rejected_without_change(&zero, &hash, "zero transactions")?;
        rejected_without_change(&bytes[..80], &hash, "invalid transaction count")?;
        zero[80] = 255;
        zero.extend_from_slice(&u64::MAX.to_le_bytes());
        rejected_without_change(&zero, &hash, "transaction 0")?;
        rejected_without_change(&bytes[..79], &hash, "block header too short")
    }

    #[test]
    fn apply_genesis_known_answer() -> TestResult {
        let temp = TempDir::new()?;
        let raw_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
        let hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let bytes = hex::decode(raw_hex)?;
        let mut root = bytes[36..68].to_vec();
        root.reverse();
        assert_eq!(hex::encode(root), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        apply_block(&temp.0, 0, &hash.to_uppercase(), raw_hex)?;
        let journal = fs::read_to_string(temp.0.join("delta_blocks.jsonl"))?;
        assert_eq!(journal.lines().count(), 1);
        let rec: DeltaBlockRecord = serde_json::from_str(journal.trim())?;
        assert_eq!(rec.height, 0);
        assert_eq!(rec.block_hash, hash.to_uppercase());
        assert_eq!(rec.kh20.len(), 6);
        assert_eq!(rec.wrapped20.len(), 6);
        assert!(rec.sh20.is_empty() && rec.wsh32.is_empty() && rec.mr32.is_empty());
        Ok(())
    }

    #[test]
    fn transaction_hashes_match_mainnet_known_answers() -> TestResult {
        for (raw, txid, wtxid) in [
            ("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff58038ae10e1b4d696e656420627920416e74506f6f6c383035e401520146211c5efabe6d6d705c6afaaa5a4093075d9681bf89c95bc2c2ff7b658640dbfef0779bf640a32c100000000000000000001b52190a3d0100000000ffffffff07220200000000000017a91442402a28dd61f2718a4b27ae72a4791d5bbdade7876fd2b9120000000017a9145249bdf2c131d43995cff42e8feee293f79297a8870000000000000000266a24aa21a9ed8725f9959af4a87c2df7f25a8730f57d168a1c15c6f6ec266f9082dc2690746e00000000000000002f6a2d434f52450164db24a662e20bbdf72d1cc6e973dbb2d12897d54e3ecda72cb7961caa4b541b1e322bcfe0b5a0300000000000000000146a12455853415401000d130f0e0e0b041f1200130000000000000000296a277379736f811cb79783664705ecf0b06e5e16ebe9b16e160749ca853aa3d97c851625a090b5230000000000000000002b6a2952534b424c4f434b3ab77f2a9818b00ac5bdc716d9b73b017513a832dd6f7308ee6999f322008f6a7c0120000000000000000000000000000000000000000000000000000000000000000000000000",
                "d25abb21a3d59f030f8bb6f8da57c083f984b2923a4a4033e304c9e9e66b9444",
                "45fe6169960c778ae3c793f80375e8f89c4d50204a46c1d4febc69cffeec3185"),
            ("01000000000101ee80c3ad85d0278760fbe760efe957ba1c6997edec940cd81756fffa7ec35b2b01000000171600149c5e4041ca41d62d1f1178faab50a259e0dc3cb9fdffffff02e00f9700000000001600148dd466ad8bcf24f40bd17777fcbab46523c332ee567005010000000017a914867a243736b61b12963fd78efbaadbc437d1b4ec8702483045022100e4fd88da8afcb85c69347c219ba933709d3575410f395934dc75ed3afd413fb402204fde4ca8a9002df396d71797f9c8fe59dae564c343b6f3b548342c69f80888810121038176e2771011753209cc0db70a460779da9980964f53f2d955b66bd51640220e00000000",
                "c5effe4aa829cd637e8d26a551a677b52e55edac4484db29fbb09a6737ae6825",
                "d6059f0a208f608c60df29d839bf43cccef9284e6290eb5cbe67da0853575a43"),
        ] {
            let bytes = hex::decode(raw)?;
            let parsed = parse_single_transaction(&bytes).ok_or("known transaction did not parse")?;
            let (mut actual_txid, mut actual_wtxid) = transaction_hashes(&bytes, &parsed)?;
            actual_txid.reverse();
            actual_wtxid.reverse();
            assert_eq!(hex::encode(actual_txid), txid);
            assert_eq!(hex::encode(actual_wtxid), wtxid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod serving_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = env::temp_dir().join(format!("btc-serving-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn tables(&self) {
            for name in ["pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin",
                "cross_format_diff_20.bin", "cross_format_diff_32.bin"] {
                fs::write(self.0.join(name), []).unwrap();
            }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
    }

    fn block(height: u64, n: u8) -> String {
        serde_json::to_string(&DeltaBlockRecord {
            height, block_hash: hex::encode([n; 32]),
            kh20: vec![hex::encode([n; 20]), hex::encode([n; 20])],
            wrapped20: vec![hex::encode([n + 1; 20])],
            sh20: vec![hex::encode([n + 2; 20])],
            wsh32: vec![hex::encode([n + 3; 32])],
            mr32: vec![hex::encode([n + 4; 32])],
        }).unwrap() + "\n"
    }

    #[test]
    fn delta_families_missing_and_rollback() {
        let temp = TempDir::new();
        let path = temp.0.join("delta_blocks.jsonl");
        let missing = DeltaIndex::load(&path).unwrap();
        assert!(missing.available && missing.pk20.is_empty() && missing.sh20.is_empty() && missing.sh32.is_empty());
        assert_eq!(missing.max_height, None);
        fs::write(&path, block(10, 1) + &block(11, 10)).unwrap();
        let index = DeltaIndex::load(&path).unwrap();
        assert_eq!(index.heights, vec![10, 11]);
        assert_eq!(index.max_height, Some(11));
        assert_eq!(index.pk20.len(), 4);
        assert_eq!(index.sh20.len(), 2);
        assert_eq!(index.sh32.len(), 4);
        for n in [1, 10] {
            assert!(index.pk20.binary_search(&[n; 20]).is_ok());
            assert!(index.pk20.binary_search(&[n + 1; 20]).is_ok());
            assert!(index.sh20.binary_search(&[n + 2; 20]).is_ok());
            assert!(index.hit32(&[n + 3; 32]) && index.hit32(&[n + 4; 32]));
            assert!(index.pk20.binary_search(&[n + 2; 20]).is_err());
            assert!(index.sh20.binary_search(&[n; 20]).is_err());
        }
        assert!(!index.hit20(&[99; 20]) && !index.hit32(&[99; 32]));
        fs::write(&path, block(10, 1)).unwrap();
        assert_ne!(delta_signature(&path).unwrap(), index.signature);
        let rolled_back = DeltaIndex::load(&path).unwrap();
        assert_eq!(rolled_back.heights, vec![10]);
        assert_eq!(rolled_back.max_height, Some(10));
        assert!(!rolled_back.hit20(&[10; 20]) && !rolled_back.hit32(&[13; 32]));
        fs::remove_file(&path).unwrap();
        assert!(DeltaIndex::load(&path).unwrap().heights.is_empty());
    }

    #[test]
    fn malformed_delta_is_an_error() {
        let temp = TempDir::new();
        let path = temp.0.join("delta_blocks.jsonl");
        fs::write(&path, "{broken}\n").unwrap();
        assert!(DeltaIndex::load(&path).is_err());
    }

    #[test]
    fn table_lookup_and_errors() {
        let temp = TempDir::new();
        let path = temp.0.join("table.bin");
        assert!(binary_search_file(&path, &[1; 20]).is_err());
        fs::write(&path, [[1u8; 20], [3; 20], [5; 20]].concat()).unwrap();
        for n in [1, 3, 5] { assert!(binary_search_file(&path, &[n; 20]).unwrap()); }
        for n in [0, 2, 6] { assert!(!binary_search_file(&path, &[n; 20]).unwrap()); }
        fs::write(&path, [0; 21]).unwrap();
        assert!(binary_search_file(&path, &[1; 20]).is_err());
        fs::write(&path, []).unwrap();
        assert!(!binary_search_file(&path, &[1; 20]).unwrap());
    }

    #[test]
    fn request_parsing_and_limits() {
        fn parse(bytes: &[u8]) -> Result<HttpRequest, (u16, bool)> {
            read_http_request(&mut io::Cursor::new(bytes))
        }
        let get = parse(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert_eq!(get.path, "/healthz");
        assert!(!get.head);
        assert!(parse(b"HEAD /healthz HTTP/1.0\r\n\r\n").unwrap().head);
        assert_eq!(parse(b"POST / HTTP/1.1\r\n\r\n").err(), Some((405, false)));
        assert_eq!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n").err(), Some((400, false)));
        assert_eq!(parse(b"GET /\r\n\r\n").err(), Some((400, false)));
        assert_eq!(parse(b"HEAD / HTTP/1.1\r\nMalformed\r\n\r\n").err(), Some((400, true)));
        assert_eq!(parse(b"HEAD / HTTP/1.1\r\nHost: x\r\n").err(), Some((400, true)));
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "x".repeat(8192));
        assert_eq!(parse(long.as_bytes()).err(), Some((414, false)));
        let headers = format!("GET / HTTP/1.1\r\nX: {}", "x".repeat(65536));
        assert_eq!(parse(headers.as_bytes()).err(), Some((400, false)));
    }

    #[test]
    fn request_deadline_remaining_and_timeout_errors() {
        let accepted_at = Instant::now();
        assert_eq!(request_remaining(accepted_at, accepted_at), Duration::from_secs(10));
        assert_eq!(request_remaining(accepted_at, accepted_at + Duration::from_secs(9)), Duration::from_secs(1));
        assert!(request_remaining(accepted_at, accepted_at + Duration::from_secs(10)).is_zero());
        assert!(request_remaining(accepted_at, accepted_at + Duration::from_secs(11)).is_zero());
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
            assert_eq!(request_read_error(io::Error::from(kind), true), (408, true));
        }
    }

    #[test]
    fn expired_request_returns_408_without_waiting_for_data() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(RequestReader {
            stream: &stream,
            accepted_at: Instant::now() - Duration::from_secs(10),
        });
        assert_eq!(read_http_request(&mut reader).err(), Some((408, false)));
    }

    #[test]
    fn pubkey_lookup_needs_only_pubkey_table() {
        let temp = TempDir::new();
        let table = temp.0.join("pubkey_hash_index.bin");
        fs::write(&table, []).unwrap();
        fs::write(temp.0.join("delta_blocks.jsonl"), block(10, 1)).unwrap();
        let mut delta = DeltaIndex::load(&temp.0.join("delta_blocks.jsonl")).unwrap();
        assert!(!temp.0.join("script_hash_index_20.bin").exists());
        assert!(lookup_pubkey_hash_20(&temp.0, &[1; 20], &delta).unwrap());
        assert!(lookup_pubkey_hash_20(&temp.0, &[2; 20], &delta).unwrap());
        assert!(!lookup_pubkey_hash_20(&temp.0, &[3; 20], &delta).unwrap());
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let bytes = hex::decode(key).unwrap();
        let (kh, wrapped) = key_hashes_from_x(&key_x(&bytes, false).unwrap()).unwrap();
        let path = format!("/lookup/pubkey/{}", key);
        for h in [kh[0], wrapped[0]] {
            delta.pk20 = vec![h];
            let (status, body) = http_response(temp.0.to_str().unwrap(), &path, &delta).unwrap();
            assert_eq!(status, "200 OK");
            assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["published_on_chain"], true);
        }
        fs::remove_file(table).unwrap();
        assert!(lookup_pubkey_hash_20(&temp.0, &delta.pk20[0], &delta).is_err());
        assert!(http_response(temp.0.to_str().unwrap(), &path, &delta).is_err());
    }

    #[test]
    fn readiness_requires_base_table_and_initial_delta_load() {
        let temp = TempDir::new();
        let dir = temp.0.to_str().unwrap();
        let table = temp.0.join("pubkey_hash_index.bin");
        fs::write(&table, []).unwrap();
        let unavailable = DeltaIndex::default();
        let loaded = DeltaIndex::load(&temp.0.join("delta_blocks.jsonl")).unwrap();
        for (delta, expected_status, ready) in [
            (&unavailable, "503 Service Unavailable", false), (&loaded, "200 OK", true),
        ] {
            let (status, body) = http_response(dir, "/readyz", delta).unwrap();
            assert_eq!(status, expected_status);
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["ready"], ready);
            if !ready { assert_eq!(json["reason"], "delta unavailable"); }
            let (status, body) = http_response(dir, "/healthz", delta).unwrap();
            assert_eq!(status, "200 OK");
            assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["delta_ready"], ready);
        }
        fs::remove_file(table).unwrap();
        assert_eq!(http_response(dir, "/readyz", &loaded).unwrap().0, "503 Service Unavailable");
    }

    #[test]
    fn capacity_is_bounded_without_changing_small_counts() {
        assert_eq!(capped_capacity(usize::MAX, 12), 12);
        assert_eq!(capped_capacity(3, 12), 3);
        assert_eq!(capped_capacity(1, 0), 0);
        let mut tx = vec![1, 0, 0, 0, 255];
        tx.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_single_transaction(&tx).is_none());
    }

    #[test]
    fn delta_is_not_cross_format_evidence_and_table_errors_propagate() {
        let temp = TempDir::new();
        temp.tables();
        fs::write(temp.0.join("delta_blocks.jsonl"), block(10, 1)).unwrap();
        let delta = DeltaIndex::load(&temp.0.join("delta_blocks.jsonl")).unwrap();
        let dir = temp.0.to_str().unwrap();
        for endpoint in ["hash", "diff"] {
            let (status, body) = http_response(dir, &format!("/lookup/{}/{}", endpoint, hex::encode([2; 20])), &delta).unwrap();
            assert_eq!(status, "200 OK");
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["delta_hit"], true);
            assert_eq!(json["in_cross_format_diff"], false);
        }
        let (_, body) = http_response(dir, &format!("/lookup/batch?hashes={},{}", hex::encode([2; 20]), hex::encode([4; 32])), &delta).unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["results"].as_object().unwrap().values().all(|v| v["delta_hit"] == true));
        let spk = [vec![0, 20], vec![2; 20]].concat();
        assert_eq!(evaluate_script_level(dir, &spk, &delta), "EXPOSED_AT_REST");
        let (_, body) = http_response(dir, &format!("/lookup/script/{}", hex::encode(&spk)), &delta).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["delta_hit"], true);
        assert_eq!(http_response(dir, "/snapshots/download/file", &delta).unwrap().0, "410 Gone");
        assert_eq!(http_response(dir, "/snapshots/manifest.json", &delta).unwrap().0, "404 Not Found");
        fs::remove_file(temp.0.join("pubkey_hash_index.bin")).unwrap();
        assert!(http_response(dir, &format!("/lookup/hash/{}", hex::encode([2; 20])), &delta).is_err());
        assert_eq!(evaluate_script_level(dir, &spk, &delta), "UNDETERMINED");
        let (_, health) = http_response(dir, "/healthz", &delta).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&health).unwrap()["base_index_ready"], false);
    }

    #[test]
    fn head_has_get_headers_without_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, _) = listener.accept().unwrap();
        write_http_response(&stream, "200 OK", "{}", true).unwrap();
        drop(stream);
        let response = client.join().unwrap();
        assert!(response.contains("Content-Length: 2\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
    }
}
