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


const RULES_VERSION: &str = "btc-indexer/shape-rules-1";
const DIGEST_FILES: [&str; 8] = [
    "state/x.bin", "state/f20.bin", "state/f32.bin", "state/r20.bin", "state/r32.bin",
    "pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin",
];

fn display_hash(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    hex::encode(bytes)
}

fn parse_display_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected 64 lowercase hexadecimal characters".to_string());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|e| e.to_string())?;
    bytes.reverse();
    Ok(bytes)
}

fn parse_chain_list(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bytes.is_empty() { return Err("chain list line 1: empty file".to_string()); }
    if bytes.last() != Some(&b'\n') {
        return Err(format!("chain list line {}: missing final line feed",
            bytes.iter().filter(|&&b| b == b'\n').count() + 1));
    }
    let mut hashes = Vec::new();
    let mut seen = FxHashSet::default();
    for (i, line) in bytes[..bytes.len() - 1].split(|&b| b == b'\n').enumerate() {
        let parse = || -> Result<[u8; 32], String> {
            let line = std::str::from_utf8(line).map_err(|_| "non-ASCII content".to_string())?;
            let (height, hash) = line.split_once(' ').ok_or_else(|| "expected <height> <hash>".to_string())?;
            if height != i.to_string() { return Err(format!("expected height {}", i)); }
            parse_display_hash(hash)
        };
        let hash = parse().map_err(|e| format!("chain list line {}: {}", i + 1, e))?;
        if !seen.insert(hash) { return Err(format!("chain list line {}: duplicate hash", i + 1)); }
        hashes.push(hash);
    }
    Ok(hashes)
}

#[derive(Serialize)]
struct ScanFileInfo {
    bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<u64>,
    sha256: String,
}

// Sync all scan files before publication; compute digests while writing.
struct ScanWriter {
    path: PathBuf,
    tmp: PathBuf,
    out: BufWriter<File>,
    hasher: Sha256,
    bytes: u64,
    previous: Option<Vec<u8>>,
}

impl ScanWriter {
    fn new(path: PathBuf) -> Result<Self, String> {
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("{} byte offset 0: create: {}", tmp.display(), e))?;
        Ok(Self { path, tmp, out: BufWriter::with_capacity(256 * 1024, file),
            hasher: Sha256::new(), bytes: 0, previous: None })
    }
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.out.write_all(bytes).map_err(|e|
            format!("{} byte offset {}: write: {}", self.tmp.display(), self.bytes, e))?;
        self.hasher.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(())
    }
    fn record(&mut self, key: &[u8], suffix: &[u8]) -> Result<(), String> {
        if self.previous.as_deref().is_some_and(|p| p >= key) {
            return Err(format!("{} byte offset {}: keys not strictly increasing", self.path.display(), self.bytes));
        }
        self.write_all(key)?;
        self.write_all(suffix)?;
        let previous = self.previous.get_or_insert_with(Vec::new);
        previous.clear();
        previous.extend_from_slice(key);
        Ok(())
    }
    fn finish(self, width: Option<u64>) -> Result<ScanFileInfo, String> {
        if width.is_some_and(|w| w == 0 || self.bytes % w != 0) {
            return Err(format!("{}: invalid record size", self.path.display()));
        }
        drop(finish_synced_file(self.out, &self.tmp)?);
        fs::rename(&self.tmp, &self.path).map_err(|e|
            format!("{}: rename to {}: {}", self.tmp.display(), self.path.display(), e))?;
        sync_parent(&self.path)?;
        Ok(ScanFileInfo { bytes: self.bytes, records: width.map(|w| self.bytes / w),
            sha256: hex::encode(self.hasher.finalize()) })
    }
}

fn finish_scan_output(writer: ScanWriter, files: &mut std::collections::BTreeMap<String, ScanFileInfo>,
    name: &str, width: Option<u64>) -> Result<(), String> {
    files.insert(name.to_string(), writer.finish(width)?);
    Ok(())
}

fn write_scan_output(out: &Path, files: &mut std::collections::BTreeMap<String, ScanFileInfo>,
    name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut writer = ScanWriter::new(out.join(name))?;
    writer.write_all(bytes)?;
    finish_scan_output(writer, files, name, None)
}

fn state_digest(rules: &str, height: u64, display_block_hash: &[u8; 32],
    hashes: &[[u8; 32]; 8]) -> Result<[u8; 32], String> {
    let length = u8::try_from(rules.len()).map_err(|_| "rules version too long".to_string())?;
    if !rules.is_ascii() { return Err("rules version is not ASCII".to_string()); }
    let mut hasher = Sha256::new();
    hasher.update([length]);
    hasher.update(rules.as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(display_block_hash);
    for hash in hashes { hasher.update(hash); }
    Ok(hasher.finalize().into())
}

fn read_scan_shard(path: &Path, width: usize) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| format!("{} byte offset 0: read: {}", path.display(), e))?;
    if bytes.len() % width != 0 {
        return Err(format!("{} byte offset {}: truncated record", path.display(), bytes.len()));
    }
    fs::remove_file(path).map_err(|e| format!("{}: remove: {}", path.display(), e))?;
    Ok(bytes)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for c in bytes.chunks(3) {
        let value = ((c[0] as u32) << 16) | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        for i in 0..4 {
            result.push(if i > c.len() { '=' } else { ALPHABET[((value >> (18 - i * 6)) & 63) as usize] as char });
        }
    }
    result
}

struct ChainRpc { authority: String, auth: String }
impl ChainRpc {
    fn new(url: &str, cookie: &Path) -> Result<Self, String> {
        let authority = url.strip_prefix("http://").and_then(|s| s.strip_suffix('/'))
            .ok_or_else(|| "RPC URL must be http://<host>:<port>/".to_string())?;
        let (host, port) = authority.rsplit_once(':').ok_or_else(|| "RPC URL requires a port".to_string())?;
        if host.is_empty() || host.bytes().any(|b| b.is_ascii_whitespace() || b"/?#@".contains(&b))
            || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|&p| p != 0).is_none()
            || (!host.starts_with('[') && host.contains(':')) {
            return Err("RPC URL must be http://<host>:<port>/".to_string());
        }
        let cookie_text = fs::read_to_string(cookie).map_err(|e| format!("{}: read cookie: {}", cookie.display(), e))?;
        let cookie_text = cookie_text.trim_end();
        if !cookie_text.starts_with("__cookie__:") || cookie_text.len() == 11
            || cookie_text.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(format!("{}: invalid RPC cookie", cookie.display()));
        }
        Ok(Self { authority: authority.to_string(), auth: base64(cookie_text.as_bytes()) })
    }
    fn request(&self, value: &serde_json::Value) -> Result<serde_json::Value, String> {
        use std::net::TcpStream;
        let body = serde_json::to_vec(value).map_err(|e| format!("RPC request JSON: {}", e))?;
        let mut socket = TcpStream::connect(&self.authority).map_err(|e| format!("RPC connect: {}", e))?;
        socket.set_read_timeout(Some(Duration::from_secs(60))).map_err(|e| format!("RPC timeout: {}", e))?;
        socket.set_write_timeout(Some(Duration::from_secs(60))).map_err(|e| format!("RPC timeout: {}", e))?;
        write!(socket, "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.authority, self.auth, body.len()).map_err(|e| format!("RPC write headers: {}", e))?;
        socket.write_all(&body).map_err(|e| format!("RPC write body: {}", e))?;
        let mut reader = BufReader::new(socket);
        let mut header = Vec::new();
        loop {
            if header.len() >= 65536 { return Err("RPC response headers too large".to_string()); }
            let mut b = [0];
            reader.read_exact(&mut b).map_err(|e| format!("RPC read headers: {}", e))?;
            header.push(b[0]);
            if header.ends_with(b"\r\n\r\n") { break; }
        }
        let header = std::str::from_utf8(&header).map_err(|_| "RPC invalid HTTP headers".to_string())?;
        let mut lines = header.split("\r\n");
        let status = lines.next().ok_or_else(|| "RPC missing HTTP status".to_string())?;
        let mut fields = status.split_whitespace();
        if fields.next() != Some("HTTP/1.1") || fields.next() != Some("200") {
            return Err("RPC requires HTTP/1.1 status 200".to_string());
        }
        let mut length = None;
        for line in lines.filter(|l| !l.is_empty()) {
            let (name, value) = line.split_once(':').ok_or_else(|| "RPC malformed HTTP header".to_string())?;
            if name.eq_ignore_ascii_case("transfer-encoding") { return Err("RPC Transfer-Encoding unsupported".to_string()); }
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() { return Err("RPC duplicate Content-Length".to_string()); }
                let text = value.trim();
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("RPC invalid Content-Length".to_string());
                }
                length = Some(text.parse::<usize>().map_err(|_| "RPC invalid Content-Length".to_string())?);
            }
        }
        let length = length.ok_or_else(|| "RPC missing Content-Length".to_string())?;
        if length > 16 * 1024 * 1024 { return Err("RPC response too large".to_string()); }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).map_err(|e| format!("RPC read body: {}", e))?;
        serde_json::from_slice(&body).map_err(|e| format!("RPC invalid response JSON: {}", e))
    }
    fn result(response: &serde_json::Value, id: u64) -> Result<&serde_json::Value, String> {
        if !response.is_object() || response["id"].as_u64() != Some(id)
            || response.get("error").is_some_and(|e| !e.is_null()) {
            return Err(format!("RPC invalid response or error for id {}", id));
        }
        response.get("result").ok_or_else(|| format!("RPC missing result for id {}", id))
    }
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let response = self.request(&serde_json::json!({"jsonrpc":"1.0","id":0,"method":method,"params":params}))?;
        Ok(Self::result(&response, 0)?.clone())
    }
    fn info(&self) -> Result<u64, String> {
        let info = self.call("getblockchaininfo", serde_json::json!([]))?;
        if info["initialblockdownload"].as_bool() != Some(false) { return Err("RPC node is in IBD or missing IBD status".to_string()); }
        let blocks = info["blocks"].as_u64().ok_or_else(|| "RPC invalid blocks".to_string())?;
        if info["headers"].as_u64() != Some(blocks) { return Err("RPC blocks and headers differ".to_string()); }
        Ok(blocks)
    }
}

fn export_chain_list(url: &str, cookie: &Path, height: u64, out: &Path) -> Result<(), String> {
    match fs::symlink_metadata(out) {
        Ok(_) => return Err(format!("{}: refusing to overwrite existing file", out.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("{}: metadata: {}", out.display(), e)),
    }
    let rpc = ChainRpc::new(url, cookie)?;
    let depth = height.checked_add(100).ok_or_else(|| "export height overflow".to_string())?;
    let tip = rpc.info()?;
    if depth > tip { return Err(format!("height {} requires at least 100 confirmations below tip {}", height, tip)); }
    let mut writer = ScanWriter::new(out.to_path_buf())?;
    let mut seen = FxHashSet::default();
    let mut final_hash = [0; 32];
    let mut start = 0u64;
    loop {
        let end = start.saturating_add(999).min(height);
        let calls: Vec<_> = (start..=end).map(|h| serde_json::json!(
            {"jsonrpc":"1.0","id":h,"method":"getblockhash","params":[h]})).collect();
        let response = rpc.request(&serde_json::Value::Array(calls))?;
        let results = response.as_array().ok_or_else(|| "RPC batch result is not an array".to_string())?;
        let mut by_id = std::collections::BTreeMap::new();
        for result in results {
            let id = result["id"].as_u64().filter(|&id| id >= start && id <= end)
                .ok_or_else(|| "RPC unexpected batch id".to_string())?;
            let text = ChainRpc::result(result, id)?.as_str().ok_or_else(|| format!("RPC hash at height {} is not text", id))?;
            let hash = parse_display_hash(text).map_err(|e| format!("RPC hash at height {}: {}", id, e))?;
            if by_id.insert(id, hash).is_some() || !seen.insert(hash) { return Err(format!("RPC duplicate result at height {}", id)); }
        }
        for h in start..=end {
            let hash = by_id.get(&h).ok_or_else(|| format!("RPC missing batch id {}", h))?;
            writer.write_all(format!("{} {}\n", h, display_hash(hash)).as_bytes())?;
            final_hash = *hash;
        }
        if end == height { break; }
        start = end + 1;
    }
    let final_tip = rpc.info()?;
    let recheck = rpc.call("getblockhash", serde_json::json!([height]))?;
    let recheck = recheck.as_str().ok_or_else(|| "RPC recheck hash is not text".to_string())?;
    if parse_display_hash(recheck)? != final_hash || depth > final_tip {
        return Err(format!("chain changed during export at height {}", height));
    }
    // Refuse overwrites again to protect destination files created during export.
    if out.try_exists().map_err(|e| format!("{}: metadata: {}", out.display(), e))? {
        return Err(format!("{}: refusing to overwrite existing file", out.display()));
    }
    writer.finish(None)?;
    println!("Exported chain list: tip={}, H={}, hash={}", tip, height, display_hash(&final_hash));
    Ok(())
}

struct BlockExtract {
    x: FxHashMap<[u8; 32], u8>,
    h20: FxHashMap<[u8; 20], u8>,
    h32: FxHashMap<[u8; 32], u8>,
    transactions: usize,
}

fn unmutated_merkle_root(mut hashes: Vec<[u8; 32]>) -> Result<[u8; 32], String> {
    if hashes.is_empty() { return Err("empty merkle tree".to_string()); }
    while hashes.len() > 1 {
        let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
        for pair in hashes.chunks(2) {
            if pair.len() == 2 && pair[0] == pair[1] { return Err("mutated merkle tree".to_string()); }
            let mut bytes = [0; 64];
            bytes[..32].copy_from_slice(&pair[0]);
            bytes[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(double_sha256(&bytes));
        }
        hashes = next;
    }
    Ok(hashes[0])
}

fn extract_block(block: &[u8], height: u64, expected_hash: &[u8; 32],
    expected_prev: &[u8; 32]) -> Result<BlockExtract, String> {
    let error = |offset: usize, message: &str| format!("height {} hash {} byte offset {}: {}",
        height, display_hash(expected_hash), offset, message);
    if block.len() < 80 { return Err(error(block.len(), "short header")); }
    if double_sha256(&block[..80]) != *expected_hash { return Err(error(0, "header hash mismatch")); }
    if block[4..36] != expected_prev[..] || (height == 0 && *expected_prev != [0; 32]) {
        return Err(error(4, "previous block hash mismatch"));
    }
    let mut r = Reader::new(&block[80..]);
    let ntx = r.count().filter(|&n| n != 0).ok_or_else(|| error(80, "missing or zero transaction count"))?;
    let mut txs = Vec::with_capacity(capped_capacity(ntx, block.len() - 80));
    let mut txids = Vec::new();
    let mut wtxids = Vec::new();
    let mut has_witness = false;
    for i in 0..ntx {
        let start = r.pos;
        let tx = parse_transaction_from_reader(&mut r)
            .ok_or_else(|| error(80 + start, &format!("transaction {} does not parse", i)))?;
        let (txid, wtxid) = transaction_hashes(&r.data[start..r.pos], &tx)
            .map_err(|e| error(80 + start, &e))?;
        has_witness |= tx.witnesses.iter().any(|w| !w.is_empty());
        txids.push(txid);
        wtxids.push(if i == 0 { [0; 32] } else { wtxid });
        txs.push(tx);
    }
    if r.pos != r.data.len() { return Err(error(80 + r.pos, "trailing bytes")); }
    if unmutated_merkle_root(txids).map_err(|e| error(36, &e))? != block[36..68] {
        return Err(error(36, "transaction merkle root mismatch"));
    }
    let coinbase = &txs[0];
    let commit_pos = coinbase.outputs.iter().rposition(|out|
        out.len() >= 38 && out.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]));
    if has_witness || (commit_pos.is_some() && height >= SEGWIT_ACTIVATION_HEIGHT) {
        let pos = commit_pos.ok_or_else(|| error(81, "missing witness commitment output"))?;
        let reserved = coinbase.witnesses.first().filter(|w| w.len() == 1 && w[0].len() == 32)
            .ok_or_else(|| error(81, "invalid witness reserved value"))?;
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&merkle_root(wtxids).map_err(|e| error(81, &e))?);
        bytes[32..].copy_from_slice(reserved[0]);
        if double_sha256(&bytes) != coinbase.outputs[pos][6..38] { return Err(error(81, "witness commitment mismatch")); }
    }
    let mut local_x = FxHashMap::default();
    let mut local_h20 = FxHashMap::default();
    let mut local_h32 = FxHashMap::default();
    let record_x = |lx: &mut FxHashMap<[u8; 32], u8>, data: &[u8], xonly: bool, flags: u8| {
        if let Some(x) = fast_candidate_x(data, xonly) { *lx.entry(x).or_insert(0) |= flags; }
    };
    for tx in txs {
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
                    *local_h20.entry(h).or_insert(0) |= 1;
                }
                Recognized::P2WPKH(h) => {
                    *local_h20.entry(h).or_insert(0) |= 2;
                }
                Recognized::P2SH(h) => {
                    *local_h20.entry(h).or_insert(0) |= 4;
                }
                Recognized::P2WSH(h) | Recognized::P2MR(h) => {
                    *local_h32.entry(h).or_insert(0) |= 1;
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
                    let h = hash160(redeem);
                    *local_h20.entry(h).or_insert(0) |= 8;
                    let sha = sha256(redeem);
                    let mut w = [0u8; 34];
                    w[0] = 0x00;
                    w[1] = 0x20;
                    w[2..34].copy_from_slice(&sha);
                    let w_h160 = hash160(&w);
                    *local_h20.entry(w_h160).or_insert(0) |= 8 | 16;
                    *local_h32.entry(sha).or_insert(0) |= 2 | 4;
                    for (_, d) in Instructions::new(redeem) {
                        if let Some(data) = d {
                            record_x(&mut local_x, data, false, 1 | 2 | 32);
                        }
                    }
                    if let Recognized::P2WSH(_) = recognize(redeem, false) {
                        if let Some(&wscript) = witness.last() {
                            let wsha = sha256(wscript);
                            let ws_h160 = hash160(wscript);
                            *local_h20.entry(ws_h160).or_insert(0) |= 8 | 16;
                            let mut ww = [0u8; 34];
                            ww[0] = 0x00;
                            ww[1] = 0x20;
                            ww[2..34].copy_from_slice(&wsha);
                            *local_h20.entry(hash160(&ww)).or_insert(0) |= 8;
                            *local_h32.entry(wsha).or_insert(0) |= 2 | 4;
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
                    if stack.len() >= 2 && stack[stack.len() - 1].starts_with(&[0x50]) {
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
                                *local_x.entry(ix).or_insert(0) |= 1 | 2 | 32;
                                let wsha_s = sha256(script);
                                *local_h32.entry(wsha_s).or_insert(0) |= 2 | 4;
                                let sh_s = hash160(script);
                                *local_h20.entry(sh_s).or_insert(0) |= 8 | 16;
                                let mut ww = [0u8; 34];
                                ww[0] = 0x00;
                                ww[1] = 0x20;
                                ww[2..34].copy_from_slice(&wsha_s);
                                *local_h20.entry(hash160(&ww)).or_insert(0) |= 8 | 16;
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
                                let version = control[0] & 254;
                                for (_, d) in Instructions::new(script) {
                                    if let Some(data) = d {
                                        if data.len() == 33 || data.len() == 65 {
                                            if let Some(x) = key_x(data, false) {
                                                *local_x.entry(x).or_insert(0) |= 1 | 2 | 32;
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
                    if !is_p2tr_script && !last_w.is_empty() {
                        let wsha = sha256(last_w);
                        *local_h32.entry(wsha).or_insert(0) |= 2;
                        let sh_direct = hash160(last_w);
                        *local_h20.entry(sh_direct).or_insert(0) |= 8 | 16;
                        let mut ww = [0u8; 34];
                        ww[0] = 0x00;
                        ww[1] = 0x20;
                        ww[2..34].copy_from_slice(&wsha);
                        *local_h20.entry(hash160(&ww)).or_insert(0) |= 8 | 16;
                        for (_, d) in Instructions::new(last_w) {
                            if let Some(data) = d {
                                record_x(&mut local_x, data, false, 1 | 2 | 32);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(BlockExtract { x: local_x, h20: local_h20, h32: local_h32, transactions: ntx })
}

fn flush_scan_map<const N: usize>(map: &mut FxHashMap<[u8; N], u8>,
    shards: &[Mutex<ScanWriter>], shift: u8) -> Result<(), String> {
    let mut buckets: Vec<Vec<u8>> = (0..shards.len()).map(|_| Vec::new()).collect();
    for (key, mask) in map.drain() {
        let bucket = &mut buckets[(key[0] >> shift) as usize];
        bucket.extend_from_slice(&key);
        bucket.push(mask);
    }
    for (i, bytes) in buckets.into_iter().enumerate() {
        if !bytes.is_empty() {
            shards[i].lock().map_err(|_| format!("scan shard {}: poisoned writer", i))?.write_all(&bytes)?;
        }
    }
    Ok(())
}

fn make_scan_shards(dir: &Path, prefix: &str, count: usize) -> Result<Vec<Mutex<ScanWriter>>, String> {
    (0..count).map(|i| ScanWriter::new(dir.join(format!("{}_{:02}.bin", prefix, i))).map(Mutex::new)).collect()
}

fn finish_scan_shards(shards: Vec<Mutex<ScanWriter>>) -> Result<(), String> {
    for (i, shard) in shards.into_iter().enumerate() {
        shard.into_inner().map_err(|_| format!("scan shard {}: poisoned writer", i))?.finish(None)?;
    }
    Ok(())
}

fn missing_directory_levels(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut missing = Vec::new();
    for level in path.ancestors() {
        if level.as_os_str().is_empty() { break; }
        match fs::symlink_metadata(level) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(level.to_path_buf()),
            Err(e) => return Err(format!("{}: metadata: {}", level.display(), e)),
            Ok(_) => break,
        }
    }
    missing.reverse();
    Ok(missing)
}

fn withdraw_failed_checkpoint(path: &Path, error: String) -> String {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => error,
        Err(e) => format!("{}; {} may remain in the output directory and must not be used: metadata: {}",
            error, path.display(), e),
        Ok(_) => match fs::remove_file(path) {
            Ok(()) => match sync_parent(path) {
                Ok(()) => format!("{}; {}: removed", error, path.display()),
                Err(e) => format!("{}; {}: removed but the directory sync failed: {}", error, path.display(), e),
            },
            Err(e) => format!("{}; {} remains in the output directory and must not be used: remove: {}",
                error, path.display(), e),
        },
    }
}

fn scan_blocks_dir(blocks_dir: &str, out_dir: &str, chain_list: &str) -> Result<usize, String> {
    if out_dir.is_empty() { return Err("output directory path must not be empty".to_string()); }
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let t0 = Instant::now();
    let chain = parse_chain_list(&fs::read(chain_list)
        .map_err(|e| format!("{}: read: {}", chain_list, e))?)
        .map_err(|e| format!("{}: {}", chain_list, e))?;
    let height = (chain.len() - 1) as u64;
    let block_hash = display_hash(&chain[chain.len() - 1]);
    let by_hash: FxHashMap<[u8; 32], usize> = chain.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let out_path = Path::new(out_dir);
    match fs::read_dir(out_path) {
        Ok(mut entries) => if let Some(entry) = entries.next() {
            entry.map_err(|e| format!("{}: directory entry: {}", out_path.display(), e))?;
            return Err(format!("{}: output directory must be absent or empty", out_path.display()));
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("{}: read output directory: {}", out_path.display(), e)),
    }
    let xor_path = Path::new(blocks_dir).join("xor.dat");
    match fs::read(&xor_path) {
        Ok(bytes) if bytes.iter().any(|&b| b != 0) => return Err(format!("{}: obfuscated block files are not supported", xor_path.display())),
        Ok(_) => {},
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("{}: read: {}", xor_path.display(), e)),
    }
    let mut blk_files = Vec::new();
    for entry in fs::read_dir(blocks_dir).map_err(|e| format!("{}: read directory: {}", blocks_dir, e))? {
        let path = entry.map_err(|e| format!("{}: directory entry: {}", blocks_dir, e))?.path();
        if path.file_name().and_then(|n| n.to_str()).is_some_and(|s| s.starts_with("blk") && s.ends_with(".dat")) {
            blk_files.push(path);
        }
    }
    blk_files.sort();
    let shard_dir = out_path.join("shards");
    let state_dir = out_path.join("state");
    let missing_dirs = missing_directory_levels(&shard_dir)?;
    fs::create_dir_all(&shard_dir).map_err(|e| format!("{}: create: {}", shard_dir.display(), e))?;
    for dir in missing_dirs { sync_parent(&dir)?; }
    fs::create_dir(&state_dir).map_err(|e| format!("{}: create: {}", state_dir.display(), e))?;
    sync_parent(&state_dir)?;
    let mut manifest = std::collections::BTreeMap::new();
    println!("[1/4] Found {} blk*.dat files in {}.", blk_files.len(), blocks_dir);
    let x_shards = make_scan_shards(&shard_dir, "x", 64)?;
    let h20_shards = make_scan_shards(&shard_dir, "h20", 64)?;
    let h32_shards = make_scan_shards(&shard_dir, "h32", 16)?;
    let seen: Vec<_> = (0..chain.len()).map(|_| AtomicBool::new(false)).collect();
    let stopped = AtomicBool::new(false);
    let total_blocks = AtomicUsize::new(0);
    let total_txs = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let files_done = AtomicUsize::new(0);
    let io_pool = rayon::ThreadPoolBuilder::new().num_threads(6).build()
        .map_err(|e| format!("scan worker pool: {}", e))?;
    io_pool.install(|| blk_files.par_iter().try_for_each(|path| -> Result<(), String> {
        let result = (|| -> Result<(), String> {
            if stopped.load(Ordering::Relaxed) { return Ok(()); }
            let mut file = File::open(path).map_err(|e| format!("{} byte offset 0: open: {}", path.display(), e))?;
            let mut buf = Vec::with_capacity(135 * 1024 * 1024);
            file.read_to_end(&mut buf).map_err(|e| format!("{} byte offset {}: read: {}", path.display(), buf.len(), e))?;
            let mut local_x = FxHashMap::default();
            let mut local_h20 = FxHashMap::default();
            let mut local_h32 = FxHashMap::default();
            let mut pos = 0;
            while pos + 8 <= buf.len() {
                if stopped.load(Ordering::Relaxed) { return Ok(()); }
                if buf[pos..pos + 4] != [0xf9, 0xbe, 0xb4, 0xd9] { pos += 1; continue; }
                let size = u32::from_le_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]) as usize;
                pos += 8;
                if size < 80 || size > buf.len() - pos { break; }
                let offset = pos;
                let block = &buf[pos..pos + size];
                pos += size;
                let hash = double_sha256(&block[..80]);
                let Some(&h) = by_hash.get(&hash) else { skipped.fetch_add(1, Ordering::Relaxed); continue; };
                if seen[h].swap(true, Ordering::Relaxed) {
                    return Err(format!("{} byte offset {}: duplicate block height {} hash {}", path.display(), offset, h, display_hash(&hash)));
                }
                let prev = if h == 0 { &[0; 32] } else { &chain[h - 1] };
                let extracted = extract_block(block, h as u64, &chain[h], prev)
                    .map_err(|e| format!("{} record byte offset {}: {}", path.display(), offset, e))?;
                for (k, m) in extracted.x { *local_x.entry(k).or_insert(0) |= m; }
                for (k, m) in extracted.h20 { *local_h20.entry(k).or_insert(0) |= m; }
                for (k, m) in extracted.h32 { *local_h32.entry(k).or_insert(0) |= m; }
                total_blocks.fetch_add(1, Ordering::Relaxed);
                total_txs.fetch_add(extracted.transactions, Ordering::Relaxed);
                if local_x.len() + local_h20.len() + local_h32.len() >= 1_500_000 {
                    flush_scan_map(&mut local_x, &x_shards, 2)?;
                    flush_scan_map(&mut local_h20, &h20_shards, 2)?;
                    flush_scan_map(&mut local_h32, &h32_shards, 4)?;
                }
            }
            flush_scan_map(&mut local_x, &x_shards, 2)?;
            flush_scan_map(&mut local_h20, &h20_shards, 2)?;
            flush_scan_map(&mut local_h32, &h32_shards, 4)?;
            let done = files_done.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 250 == 0 || done == blk_files.len() {
                println!("  -> [1/4] Scanned {} / {} blk files ({:.1}%) in {:.1}s",
                    done, blk_files.len(), done as f64 * 100.0 / blk_files.len() as f64, t0.elapsed().as_secs_f64());
            }
            Ok(())
        })();
        if result.is_err() { stopped.store(true, Ordering::Relaxed); }
        result
    }))?;
    let missing: Vec<_> = seen.iter().enumerate().filter_map(|(h, s)| (!s.load(Ordering::Relaxed)).then_some(h)).collect();
    if !missing.is_empty() {
        return Err(format!("{}: {} listed blocks missing; first heights {:?}", blocks_dir, missing.len(), &missing[..missing.len().min(10)]));
    }
    finish_scan_shards(x_shards)?;
    finish_scan_shards(h20_shards)?;
    finish_scan_shards(h32_shards)?;
    println!("[1.5/4] Block scan finished in {:.1}s ({} blocks, {} txs).",
        t0.elapsed().as_secs_f64(), total_blocks.load(Ordering::Relaxed), total_txs.load(Ordering::Relaxed));
    println!("  -> Skipped {} records not in chain list.", skipped.load(Ordering::Relaxed));
    // Step 1B: Reduce h32_00..15.bin immediately to free 33 GB SSD space
    let mut census = Census::default();
    census.funded_hash32_p2wsh = Some(0);
    let mut f32_state = ScanWriter::new(state_dir.join("f32.bin"))?;
    let mut r32_state = ScanWriter::new(state_dir.join("r32.bin"))?;
    let mut total_wsh32 = 0usize;
    let mut total_cross_diff_32 = 0usize;
    {
        println!("[2a/4] Reducing 16 H32 shards into script_hash_index_32.bin & cross_format_diff_32.bin...");
        let _ = io::stdout().flush();
        let mut script32_file =
            ScanWriter::new(out_path.join("script_hash_index_32.bin"))?;
        let mut cross32_file =
            ScanWriter::new(out_path.join("cross_format_diff_32.bin"))?;
        for s in 0..16 {
            let h32_path = shard_dir.join(format!("h32_{:02}.bin", s));
            let raw_h32 = read_scan_shard(&h32_path, 33)?;
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
                if m & 1 != 0 { f32_state.record(&h, &[])?; }
                if m & 6 != 0 { r32_state.record(&h, &[m & 6])?; }
                if (m & 1) != 0 {
                    if let Some(count) = &mut census.funded_hash32_p2wsh { *count += 1; }
                }
                if (m & 1) != 0 && (m & 2) != 0 {
                    script32_file.write_all(&h)?;
                    total_wsh32 += 1;
                }
                if (m & 1) != 0 && (m & 4) != 0 {
                    cross32_file.write_all(&h)?;
                    total_cross_diff_32 += 1;
                }
            }
        }
        finish_scan_output(script32_file, &mut manifest, "script_hash_index_32.bin", Some(32))?;
        finish_scan_output(cross32_file, &mut manifest, "cross_format_diff_32.bin", Some(32))?;
    }
    finish_scan_output(f32_state, &mut manifest, "state/f32.bin", Some(32))?;
    finish_scan_output(r32_state, &mut manifest, "state/r32.bin", Some(33))?;

    // Step 1C: Deduplicate h20_00..63.bin into funded_00..63.bin (freeing ~56 GB SSD space) and populate 2.0 GiB FundedBloom
    println!("[2b/4] Deduplicating 64 H20 shards and building 2.0 GiB FundedBloom filter...");
    let _ = io::stdout().flush();
    let bloom = FundedBloom::new();
    let mut total_sh20 = 0usize;
    let mut f20_state = ScanWriter::new(state_dir.join("f20.bin"))?;
    let mut r20_state = ScanWriter::new(state_dir.join("r20.bin"))?;
    {
        let mut script20_idx_file =
            ScanWriter::new(out_path.join("script_hash_index_20.bin"))?;
        for s in 0..64 {
            let h20_path = shard_dir.join(format!("h20_{:02}.bin", s));
            let raw_h20 = read_scan_shard(&h20_path, 21)?;

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
            for &(h, m) in &funded_shard {
                if m & 7 != 0 { f20_state.record(&h, &[m & 7])?; }
                if m & 24 != 0 { r20_state.record(&h, &[m & 24])?; }
            }
            funded_shard.retain(|&(_, m)| (m & 7) != 0);

            let funded_path = shard_dir.join(format!("funded_{:02}.bin", s));
            let mut ff = ScanWriter::new(funded_path.clone())?;
            for &(h, m) in &funded_shard {
                census.record_hash20(m);
                bloom.insert(&h);
                if (m & 4) != 0 && (m & 8) != 0 {
                    script20_idx_file.write_all(&h)?;
                    total_sh20 += 1;
                }
                ff.write_all(&h)?;
                ff.write_all(&[m])?;
            }
            ff.finish(Some(21))?;
        }
        finish_scan_output(script20_idx_file, &mut manifest, "script_hash_index_20.bin", Some(20))?;
    }
    finish_scan_output(f20_state, &mut manifest, "state/f20.bin", Some(21))?;
    finish_scan_output(r20_state, &mut manifest, "state/r20.bin", Some(21))?;

    // Step 2: Deduplicate x_00..x_63 and emit Bloom-filtered candidate 20-byte hashes into cand_00..cand_63 (~20 GB total)
    println!("[2c/4] Deriving 6 encodings across 64 X shards with FundedBloom filtering...");
    let _ = io::stdout().flush();
    let t1 = Instant::now();
    let cand_shards = make_scan_shards(&shard_dir, "cand", 64)?;
    let mut x_state = ScanWriter::new(state_dir.join("x.bin"))?;

    let mut x_flags_vec: Vec<u8> = Vec::with_capacity(700_000_000);
    for s in 0..64 {
        let x_path = shard_dir.join(format!("x_{:02}.bin", s));
        let raw = read_scan_shard(&x_path, 33)?;
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
        for &(x, fl) in &deduped {
            x_state.record(&x, &[fl])?;
            x_flags_vec.push(fl);
        }

        deduped.par_chunks(32768).enumerate().try_for_each(|(c_idx, chunk)| -> Result<(), String> {
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
                    cand_shards[i].lock().map_err(|_| format!("candidate shard {}: poisoned writer", i))?.write_all(&buf)?;
                }
            }
            Ok(())
        })?;
        if (s + 1) % 8 == 0 || s == 63 {
            println!("  -> [2c/4] Processed X shard {} / 64 in {:.1}s", s + 1, t1.elapsed().as_secs_f64());
            let _ = io::stdout().flush();
        }
    }
    finish_scan_shards(cand_shards)?;
    drop(bloom);

    let total_unique_x = x_flags_vec.len();
    if x_state.bytes / 33 != total_unique_x as u64 {
        return Err(format!("{}: X record count differs from total_unique_x", state_dir.join("x.bin").display()));
    }
    finish_scan_output(x_state, &mut manifest, "state/x.bin", Some(33))?;
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
        ScanWriter::new(out_path.join("pubkey_hash_index.bin"))?;
    let mut matched_files: Vec<PathBuf> = Vec::with_capacity(64);

    let mut total_exposed_h160 = 0usize;

    for s in 0..64 {
        let funded_path = shard_dir.join(format!("funded_{:02}.bin", s));
        let raw_f = read_scan_shard(&funded_path, 21)?;

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
        let raw_cand = read_scan_shard(&cand_path, 25)?;

        let matched_pairs: Mutex<Vec<([u8; 20], u32)>> = Mutex::new(Vec::new());
        raw_cand.par_chunks(25 * 32768).try_for_each(|chunk| -> Result<(), String> {
            let mut local_matches: Vec<([u8; 20], u32)> = Vec::new();
            for rec in chunk.chunks_exact(25) {
                let mut h = [0u8; 20];
                h.copy_from_slice(&rec[0..20]);
                let Ok(pos) = funded_shard.binary_search_by(|probe| probe.0.cmp(&h)) else {
                    continue;
                };
                let mask = funded_shard[pos].1;
                let x_id = u32::from_le_bytes([rec[20], rec[21], rec[22], rec[23]]);
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
                matched_pairs.lock().map_err(|_| format!("{}: poisoned match collector", cand_path.display()))?.extend(local_matches);
            }
            Ok(())
        })?;
        drop(raw_cand);
        drop(funded_shard);

        let mut pairs = matched_pairs.into_inner().map_err(|_| format!("{}: poisoned match collector", cand_path.display()))?;
        pairs.par_sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        pairs.dedup();

        let mut last_written: Option<[u8; 20]> = None;
        for &(h, _) in &pairs {
            if last_written != Some(h) {
                pubkey_idx_file.write_all(&h)?;
                total_exposed_h160 += 1;
                last_written = Some(h);
            }
        }

        let m_path = shard_dir.join(format!("matched_{:02}.bin", s));
        {
            let mut mf = ScanWriter::new(m_path.clone())?;
            for &(h, x_id) in &pairs {
                mf.write_all(&h)?;
                mf.write_all(&x_id.to_le_bytes())?;
            }
            for h in shard_cross_sh20 {
                mf.write_all(&h)?;
                mf.write_all(&u32::MAX.to_le_bytes())?;
            }
            mf.finish(Some(24))?;
        }
        matched_files.push(m_path);
    }
    finish_scan_output(pubkey_idx_file, &mut manifest, "pubkey_hash_index.bin", Some(20))?;

    // Step 4: Write cross_format_diff_20.bin and stats.json
    let mut cross20_file =
        ScanWriter::new(out_path.join("cross_format_diff_20.bin"))?;
    let mut total_cross_diff_20 = 0usize;

    for m_path in matched_files {
        let raw_m = read_scan_shard(&m_path, 24)?;
        let mut diff_hashes: Vec<[u8; 20]> = Vec::new();
        for rec in raw_m.chunks_exact(24) {
            let mut h = [0u8; 20];
            h.copy_from_slice(&rec[0..20]);
            let x_id = u32::from_le_bytes([rec[20], rec[21], rec[22], rec[23]]);
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
            cross20_file.write_all(&h)?;
            total_cross_diff_20 += 1;
        }
    }
    finish_scan_output(cross20_file, &mut manifest, "cross_format_diff_20.bin", Some(20))?;
    fs::remove_dir_all(&shard_dir).map_err(|e| format!("{}: remove directory: {}", shard_dir.display(), e))?;
    sync_parent(&shard_dir)?;

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
        "scan_height": height,
        "scan_block_hash": block_hash,
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
    write_scan_output(out_path, &mut manifest, "stats.json",
        &serde_json::to_vec_pretty(&stats_json).map_err(|e| format!("stats.json: serialize: {}", e))?)?;
    write_scan_output(out_path, &mut manifest, "last_indexed_height", format!("{}\n", height).as_bytes())?;
    let mut file_hashes = [[0; 32]; 8];
    for (i, name) in DIGEST_FILES.iter().enumerate() {
        let info = manifest.get(*name).ok_or_else(|| format!("checkpoint: missing {}", name))?;
        hex::decode_to_slice(&info.sha256, &mut file_hashes[i])
            .map_err(|e| format!("checkpoint {}: invalid digest: {}", name, e))?;
    }
    let mut tip_display = chain[chain.len() - 1];
    tip_display.reverse();
    let checkpoint = serde_json::json!({
        "format": "btc-indexer-checkpoint/1", "height": height, "block_hash": block_hash,
        "rules_version": RULES_VERSION, "files": manifest,
        "state_digest": hex::encode(state_digest(RULES_VERSION, height, &tip_display, &file_hashes)?),
    });
    let mut checkpoint_file = ScanWriter::new(out_path.join("checkpoint.json"))?;
    checkpoint_file.write_all(&serde_json::to_vec_pretty(&checkpoint)
        .map_err(|e| format!("checkpoint.json: serialize: {}", e))?)?;
    // checkpoint.json is written last, after all other output files are written, synced and renamed
    // and their directories synced; it records each file's size and SHA-256. A scan is complete only
    // if the process exits with status 0. Removing checkpoint.json after failed publication is best
    // effort: removal can fail, or the process can stop before it runs. Callers must not use the
    // output directory of a run that did not exit with status 0.
    checkpoint_file.finish(None)
        .map_err(|e| withdraw_failed_checkpoint(&out_path.join("checkpoint.json"), e))?;

    let mut out = io::stdout().lock();
    let _ = writeln!(out,
        "[4/4] Index build completed in {:.1}s (total {:.1}s)!",
        t2.elapsed().as_secs_f64(),
        t0.elapsed().as_secs_f64()
    );
    let _ = writeln!(out, "  - Exposed H160 entries written: {} ({:.2} MB)", total_exposed_h160, (total_exposed_h160 * 20) as f64 / 1e6);
    let _ = writeln!(out, "  - Revealed P2SH entries written: {} ({:.2} MB)", total_sh20, (total_sh20 * 20) as f64 / 1e6);
    let _ = writeln!(out, "  - Revealed P2WSH entries written: {} ({:.2} MB)", total_wsh32, (total_wsh32 * 32) as f64 / 1e6);
    let _ = writeln!(out, "  - Minimal Cross-Format Diff 20B entries: {} ({:.2} MB)", total_cross_diff_20, (total_cross_diff_20 * 20) as f64 / 1e6);
    let _ = writeln!(out, "  - Minimal Cross-Format Diff 32B entries: {} ({:.2} MB)", total_cross_diff_32, (total_cross_diff_32 * 32) as f64 / 1e6);
    let _ = writeln!(out, "  - Cross-type reuse stats:");
    let _ = writeln!(out, "      * Keys in both P2PK and P2PKH: {}", c_p2pk_p2pkh);
    let _ = writeln!(out, "      * Keys in both P2PKH and P2WPKH: {}", c_pkh_wpkh);
    let _ = writeln!(out, "      * Keys funded under both Compressed and Uncompressed encodings: {}", c_comp_uncomp);
    let _ = writeln!(out, "  - Census stats:");
    if let Some(rows) = stats_json["census"].as_object() {
        for (name, value) in rows { let _ = writeln!(out, "      * {}: {}", name, value); }
    }
    Ok(skipped.load(Ordering::Relaxed))
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
    } else if args.len() == 5 && args[1] == "--scan-blocks" {
        if let Err(e) = scan_blocks_dir(&args[2], &args[3], &args[4]) {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    } else if args.len() == 6 && args[1] == "--export-chain-list" {
        let result = args[4].parse::<u64>()
            .map_err(|e| format!("height argument {:?}: {}", args[4], e))
            .and_then(|h| export_chain_list(&args[2], Path::new(&args[3]), h, Path::new(&args[5])));
        if let Err(e) = result {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
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
        eprintln!("  btc-indexer --scan-blocks <blocks_dir> <out_dir> <chain_list>");
        eprintln!("  btc-indexer --export-chain-list <rpc_url> <cookie_file> <height> <out_file>");
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
        lock_time: u32,
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
            bytes.extend_from_slice(&self.lock_time.to_le_bytes());
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
            witness: vec![vec![0x31; 253], vec![0x51]], lock_time: 0 };
        let legacy = TestTx { coinbase: false, script_sig: vec![1, 7], outputs: vec![vec![0x51]], witness: vec![], lock_time: 0 };
        let root = test_root(vec![[0; 32], double_sha256(&spend.serialize(true)), double_sha256(&legacy.serialize(true))]);
        let reserved = vec![0x42; 32];
        let commitment = double_sha256(&[root.as_slice(), &reserved].concat());
        let prefix = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let coinbase = TestTx { coinbase: true, script_sig: vec![1, 1],
            // The higher matching output wins, and bytes after the commitment are allowed.
            outputs: vec![[prefix.as_slice(), &[0; 32]].concat(), vec![0x51],
                [prefix.as_slice(), commitment.as_slice(), &[0x99]].concat()], witness: vec![reserved], lock_time: 0 };
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
    mod chain_scan {
        use super::*;
        use std::net::TcpListener;
        use std::sync::atomic::AtomicBool;

        fn push(data: &[u8]) -> Vec<u8> {
            let mut out = if data.len() <= 75 { vec![data.len() as u8] }
                else { vec![0x4c, data.len() as u8] };
            out.extend_from_slice(data);
            out
        }
        fn p2sh(script: &[u8]) -> Vec<u8> { [vec![0xa9, 20], hash160(script).to_vec(), vec![0x87]].concat() }
        fn p2wsh(script: &[u8]) -> Vec<u8> { [vec![0, 32], sha256(script).to_vec()].concat() }

        fn branch_transactions(height: u32) -> Result<Vec<TestTx>, String> {
            let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .map_err(|e| e.to_string())?;
            let pk = PublicKey::from_slice(&key).map_err(|e| e.to_string())?;
            let uncompressed = pk.serialize_uncompressed().to_vec();
            let mut hybrid = uncompressed.clone();
            hybrid[0] = 6 + (hybrid[64] & 1);
            let mut odd_key = key.clone();
            odd_key[0] = 3;
            let mut odd_hybrid = PublicKey::from_slice(&odd_key).map_err(|e| e.to_string())?
                .serialize_uncompressed().to_vec();
            odd_hybrid[0] = 7;
            let mut invalid = vec![2];
            invalid.extend_from_slice(&[0xff; 32]);
            let multisig = [vec![0x52], push(&key), push(&uncompressed), vec![0x52, 0xae]].concat();
            let p2pk = [push(&key), vec![0xac]].concat();
            let wpkh = [vec![0, 20], hash160(&key).to_vec()].concat();
            let tapscript = [push(&key[1..]), vec![0xac], push(&key[1..]), vec![0xba],
                push(&hybrid), push(&invalid)].concat();
            let mut control = vec![0xc0];
            control.extend_from_slice(&key[1..]);
            let control2 = [control.clone(), vec![0x19; 64]].concat();
            let mut future_control = control.clone();
            future_control[0] = 0xc2;
            let bad_control = [vec![0xc0], vec![0xff; 32]].concat();
            let sig = vec![0x30; 64];
            let annex = vec![0x50, 0x01];
            let mut outputs = vec![
                [vec![0x76, 0xa9, 20], hash160(&key).to_vec(), vec![0x88, 0xac]].concat(),
                wpkh.clone(), p2sh(&wpkh), p2sh(&multisig), p2wsh(&multisig), p2sh(&p2wsh(&multisig)),
                [vec![0x51, 32], key[1..].to_vec()].concat(), p2pk.clone(), multisig.clone(),
                [push(&uncompressed), vec![0xac]].concat(), [push(&hybrid), vec![0xac]].concat(),
                [push(&odd_hybrid), vec![0xac]].concat(), [vec![0x6a], push(&invalid)].concat(),
                [vec![0x6a], push(&key)].concat(), push(&invalid),
                p2sh(&key), p2sh(&[]), p2wsh(&key), p2wsh(&control), p2wsh(&tapscript),
                p2sh(&tapscript), p2wsh(&p2pk), p2wsh(&[]),
            ];
            for path in [Vec::new(), vec![[0x19; 32]; 2]] {
                for hash in leaf_hashes(&RevealedLeaf { version: 192, script: tapscript.clone(), path }) {
                    outputs.push([vec![0, 32], hash.to_vec()].concat());
                }
            }
            let cases = vec![
                ([push(&sig), push(&key)].concat(), vec![]),
                (vec![], vec![sig.clone(), key.clone()]),
                (push(&wpkh), vec![sig.clone(), key.clone()]),
                ([vec![0], push(&sig), push(&sig), push(&multisig)].concat(), vec![]),
                (vec![], vec![vec![], sig.clone(), sig.clone(), multisig.clone()]),
                (push(&p2wsh(&multisig)), vec![vec![], sig.clone(), sig.clone(), multisig]),
                (vec![], vec![sig.clone()]),
                (vec![], vec![sig.clone(), annex.clone()]),
                (vec![], vec![sig.clone(), tapscript.clone(), control.clone()]),
                (vec![], vec![sig.clone(), tapscript.clone(), control, annex.clone()]),
                (vec![], vec![sig.clone(), tapscript.clone(), control2.clone()]),
                (vec![], vec![sig.clone(), tapscript.clone(), control2, annex]),
                (push(&sig), vec![]),
                (push(&key), vec![]),
                (vec![0], vec![]),
                (vec![], vec![sig.clone(), key]),
                (vec![], vec![sig.clone(), tapscript.clone(), {
                    let mut c = vec![0xc0]; c.extend_from_slice(&pk.serialize()[1..]); c
                }]),
                ([push(&sig), push(&uncompressed)].concat(), vec![]),
                (vec![], vec![sig.clone(), hybrid]),
                (push(&p2pk), vec![]),
                (vec![], vec![sig.clone(), vec![]]),
                (vec![], vec![sig.clone(), tapscript.clone(), future_control]),
                (vec![], vec![sig.clone(), tapscript.clone(), bad_control]),
            ];
            let mut txs = vec![TestTx { coinbase: true, script_sig: push(&height.to_le_bytes()),
                outputs: std::mem::take(&mut outputs), witness: vec![vec![0x42; 32]], lock_time: 0 }];
            for (i, (script_sig, witness)) in cases.into_iter().enumerate() {
                txs.push(TestTx { coinbase: false, script_sig, witness,
                    outputs: vec![[vec![0x6a], push(&(i as u32).to_le_bytes())].concat()], lock_time: 0 });
            }
            let root = merkle_root(std::iter::once([0; 32])
                .chain(txs.iter().skip(1).map(|t| double_sha256(&t.serialize(true)))).collect())?;
            let commitment = double_sha256(&[root.as_slice(), &[0x42; 32]].concat());
            txs[0].outputs.push([vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed], commitment.to_vec()].concat());
            Ok(txs)
        }

        fn synthetic_chain(count: u32) -> Result<Vec<Vec<u8>>, String> {
            let mut chain = Vec::new();
            let mut prev = [0; 32];
            for h in 0..count {
                let mut block = block_bytes(&branch_transactions(h)?, true);
                block[4..36].copy_from_slice(&prev);
                block[68..72].copy_from_slice(&h.to_le_bytes());
                prev = double_sha256(&block[..80]);
                chain.push(block);
            }
            Ok(chain)
        }
        fn record(block: &[u8]) -> Vec<u8> {
            [vec![0xf9, 0xbe, 0xb4, 0xd9], (block.len() as u32).to_le_bytes().to_vec(), block.to_vec()].concat()
        }
        fn write_chain(dir: &Path, chain: &[Vec<u8>]) -> TestResult {
            fs::create_dir_all(dir.join("blocks"))?;
            let mut list = String::new();
            for (h, block) in chain.iter().enumerate() { list.push_str(&format!("{} {}\n", h, header_hash(block))); }
            fs::write(dir.join("chain-list.txt"), list)?;
            fs::write(dir.join("blocks/blk00000.dat"), chain.iter().flat_map(|b| record(b)).collect::<Vec<_>>())?;
            Ok(())
        }
        fn scan(dir: &Path, name: &str) -> Result<usize, String> {
            scan_blocks_dir(dir.join("blocks").to_str().ok_or("test blocks path")?,
                dir.join(name).to_str().ok_or("test output path")?,
                dir.join("chain-list.txt").to_str().ok_or("test list path")?)
        }

        struct HandCase {
            name: &'static str,
            tx: TestTx,
            expected: BlockExtract,
        }

        fn hand_expected(x: &[([u8; 32], u8)], h20: &[([u8; 20], u8)],
            h32: &[([u8; 32], u8)]) -> BlockExtract {
            BlockExtract { x: x.iter().copied().collect(), h20: h20.iter().copied().collect(),
                h32: h32.iter().copied().collect(), transactions: 2 }
        }

        fn hand_case(name: &'static str, script_sig: Vec<u8>, witness: Vec<Vec<u8>>,
            outputs: Vec<Vec<u8>>, expected: BlockExtract) -> HandCase {
            HandCase { name, tx: TestTx { coinbase: false, script_sig, outputs, witness, lock_time: 0 }, expected }
        }

        fn literal_x(text: &str) -> Result<[u8; 32], String> {
            let mut x = [0; 32];
            hex::decode_to_slice(text, &mut x).map_err(|e| e.to_string())?;
            Ok(x)
        }

        fn compressed(x: &[u8; 32]) -> Vec<u8> { [vec![2], x.to_vec()].concat() }
        fn pkh(hash: [u8; 20]) -> Vec<u8> {
            [vec![0x76, 0xa9, 20], hash.to_vec(), vec![0x88, 0xac]].concat()
        }
        fn wpkh(hash: [u8; 20]) -> Vec<u8> { [vec![0, 20], hash.to_vec()].concat() }
        fn multisig_2of3(keys: &[Vec<u8>; 3]) -> Vec<u8> {
            [vec![0x52], push(&keys[0]), push(&keys[1]), push(&keys[2]), vec![0x53, 0xae]].concat()
        }

        // Each row lists the full mapping and numeric masks; expected values bypass extractors, recognizers, and script-role inference.
        fn hand_cases() -> Result<Vec<HandCase>, String> {
            let g = literal_x("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?;
            let g2 = literal_x("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")?;
            let g3 = literal_x("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")?;
            let g4 = literal_x("e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13")?;
            let g5 = literal_x("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")?;
            let g6 = literal_x("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556")?;
            let g7 = literal_x("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")?;
            let g8 = literal_x("2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01")?;
            let g9 = literal_x("acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe")?;
            let g10 = literal_x("a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7")?;
            let g11 = literal_x("774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb")?;
            let g12 = literal_x("d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a")?;
            let g13 = literal_x("f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8")?;
            let g14 = literal_x("499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4")?;
            let g15 = literal_x("d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e")?;
            let g16 = literal_x("e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a")?;
            let g17 = literal_x("defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")?;
            let uncompressed = hex::decode(concat!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")).map_err(|e| e.to_string())?;
            let hybrid = hex::decode(concat!("06c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")).map_err(|e| e.to_string())?;
            let mut cases = vec![
                hand_case("output P2PKH", vec![], vec![], vec![pkh([0x11; 20])],
                    hand_expected(&[], &[([0x11; 20], 1)], &[])),
                hand_case("output P2WPKH", vec![], vec![], vec![wpkh([0x12; 20])],
                    hand_expected(&[], &[([0x12; 20], 2)], &[])),
                hand_case("output P2SH", vec![], vec![], vec![[vec![0xa9, 20], vec![0x13; 20], vec![0x87]].concat()],
                    hand_expected(&[], &[([0x13; 20], 4)], &[])),
                hand_case("output P2WSH", vec![], vec![], vec![[vec![0, 32], vec![0x14; 32]].concat()],
                    hand_expected(&[], &[], &[([0x14; 32], 1)])),
                hand_case("output P2TR", vec![], vec![], vec![[vec![0x51, 32], g3.to_vec()].concat()],
                    hand_expected(&[(g3, 11)], &[], &[])),
                hand_case("output compressed P2PK", vec![], vec![], vec![[push(&compressed(&g4)), vec![0xac]].concat()],
                    hand_expected(&[(g4, 55)], &[], &[])),
                hand_case("output uncompressed P2PK", vec![], vec![], vec![[push(&uncompressed), vec![0xac]].concat()],
                    hand_expected(&[(g, 55)], &[], &[])),
                hand_case("output hybrid P2PK", vec![], vec![], vec![[push(&hybrid), vec![0xac]].concat()],
                    hand_expected(&[(g2, 55)], &[], &[])),
                hand_case("output bare 1-of-2", vec![], vec![], vec![[vec![0x51], push(&compressed(&g6)),
                    push(&compressed(&g7)), vec![0x52, 0xae]].concat()],
                    hand_expected(&[(g6, 51), (g7, 51)], &[], &[])),
                hand_case("output OP_RETURN valid point", vec![], vec![], vec![[vec![0x6a], push(&compressed(&g5))].concat()],
                    hand_expected(&[(g5, 19)], &[], &[])),
                hand_case("output unknown witness version", vec![], vec![], vec![[vec![0x52, 32], vec![0x15; 32]].concat()],
                    hand_expected(&[], &[], &[])),
                hand_case("input P2PKH", [push(&[0x30; 64]), push(&compressed(&g8))].concat(), vec![], vec![],
                    hand_expected(&[(g8, 33)], &[], &[])),
                hand_case("input P2WPKH", vec![], vec![vec![0x31; 64], compressed(&g9)], vec![],
                    hand_expected(&[(g9, 33)], &[], &[])),
            ];
            let redeem = wpkh(hash160(&compressed(&g10)));
            let wrapped = [vec![0, 32], sha256(&redeem).to_vec()].concat();
            cases.push(hand_case("input P2SH-P2WPKH", push(&redeem), vec![vec![0x32; 64], compressed(&g10)], vec![],
                hand_expected(&[(g10, 33)], &[(hash160(&redeem), 8), (hash160(&wrapped), 24)], &[(sha256(&redeem), 6)])));

            // Current rules skip curve validation for compressed candidates' x; the three multisig scripts use distinct candidates.
            for (name, base, role) in [("input P2SH 2-of-3", 0x21, 0),
                ("input P2WSH 2-of-3", 0x24, 1), ("input P2SH-P2WSH", 0x27, 2)] {
                let xs = [[base; 32], [base + 1; 32], [base + 2; 32]];
                let script = multisig_2of3(&xs.map(|x| compressed(&x)));
                let wrapped = [vec![0, 32], sha256(&script).to_vec()].concat();
                let double_wrapped = [vec![0, 32], sha256(&wrapped).to_vec()].concat();
                let (script_sig, witness, h20, h32) = match role {
                    0 => ([vec![0], push(&[0x33; 64]), push(&[0x34; 64]), push(&script)].concat(), vec![],
                        vec![(hash160(&script), 8), (hash160(&wrapped), 24)], vec![(sha256(&script), 6)]),
                    1 => (vec![], vec![vec![], vec![0x35; 64], vec![0x36; 64], script.clone()],
                        vec![(hash160(&script), 24), (hash160(&wrapped), 24)], vec![(sha256(&script), 2)]),
                    _ => (push(&wrapped), vec![vec![], vec![0x37; 64], vec![0x38; 64], script.clone()],
                        vec![(hash160(&script), 24), (hash160(&wrapped), 8), (hash160(&double_wrapped), 24)],
                        vec![(sha256(&script), 6), (sha256(&wrapped), 6)]),
                };
                cases.push(hand_case(name, script_sig, witness, vec![],
                    hand_expected(&xs.map(|x| (x, 35)), &h20, &h32)));
            }
            for (name, signature, annex) in [("input P2TR key path", vec![0x39; 64], None),
                ("input P2TR key path annex", vec![0x3a; 64], Some(vec![0x50, 0x3b]))] {
                let mut witness = vec![signature.clone()];
                if let Some(ref bytes) = annex { witness.push(bytes.clone()); }
                // Without UTXOs, shape rules treat a signature or a full stack's trailing annex as a native witness script.
                let script = annex.as_ref().unwrap_or(&signature);
                let wrapped = [vec![0, 32], sha256(script).to_vec()].concat();
                cases.push(hand_case(name, vec![], witness, vec![], hand_expected(&[],
                    &[(hash160(script), 24), (hash160(&wrapped), 24)], &[(sha256(script), 2)])));
            }

            // Build expected TapLeaf and two-level TapBranch values directly from tagged-hash byte preimages.
            for (name, internal, signing, second, path) in [
                ("input P2TR script path zero", g13, g14, None, false),
                ("input P2TR script path two", g15, g16, Some(g17), true),
            ] {
                let mut script = [vec![32], signing.to_vec(), vec![0xac]].concat();
                let mut xs = vec![(internal, 35), (signing, 35)];
                if let Some(x) = second {
                    script.extend([vec![32], x.to_vec(), vec![0xba]].concat());
                    xs.push((x, 35));
                }
                let mut control = [vec![0xc0], internal.to_vec()].concat();
                let wrapped = [vec![0, 32], sha256(&script).to_vec()].concat();
                let leaf = tagged_hash(b"TapLeaf", &[vec![0xc0, script.len() as u8], script.clone()].concat());
                let mut h32 = vec![(sha256(&script), 6), (leaf, 6)];
                if path {
                    let a = [0x41; 32];
                    let b = [0xe2; 32];
                    control.extend_from_slice(&a);
                    control.extend_from_slice(&b);
                    let branch = tagged_hash(b"TapBranch", &if leaf < a { [leaf, a].concat() } else { [a, leaf].concat() });
                    let root = tagged_hash(b"TapBranch", &if branch < b { [branch, b].concat() } else { [b, branch].concat() });
                    h32.extend([(branch, 6), (root, 6)]);
                }
                cases.push(hand_case(name, vec![], vec![vec![0x3c; 64], script.clone(), control], vec![],
                    hand_expected(&xs, &[(hash160(&script), 24), (hash160(&wrapped), 24)], &h32)));
            }
            let key_script = compressed(&[0x61; 32]);
            cases.push(hand_case("two pushes pubkey redeem", [push(&[0x3d; 64]), push(&key_script)].concat(),
                vec![], vec![p2sh(&key_script)], hand_expected(&[([0x61; 32], 33)], &[(hash160(&key_script), 4)], &[])));
            cases.push(hand_case("empty redeem", [push(&[0x3e; 64]), vec![0]].concat(), vec![], vec![p2sh(&[])],
                hand_expected(&[], &[(hash160(&[]), 4)], &[])));
            let key_script = compressed(&[0x62; 32]);
            cases.push(hand_case("two elements pubkey witness script", vec![], vec![vec![0x3f; 64], key_script.clone()],
                vec![p2wsh(&key_script)], hand_expected(&[([0x62; 32], 33)], &[], &[(sha256(&key_script), 1)])));
            let script = [vec![32], g11.to_vec(), vec![0xba]].concat();
            let control = [vec![0xc0], g12.to_vec()].concat();
            let wrapped = [vec![0, 32], sha256(&script).to_vec()].concat();
            let leaf = tagged_hash(b"TapLeaf", &[vec![0xc0, 34], script.clone()].concat());
            cases.push(hand_case("witness script looks like control", vec![],
                vec![vec![0x40; 64], script.clone(), control.clone()], vec![p2wsh(&control)],
                hand_expected(&[(g11, 35), (g12, 35)], &[(hash160(&script), 24), (hash160(&wrapped), 24)],
                    &[(sha256(&control), 1), (sha256(&script), 6), (leaf, 6)])));
            for (name, prefix, x) in [("off-curve compressed 02 push", 2, [0xff; 32]),
                ("off-curve compressed 03 push", 3, [0; 32])] {
                cases.push(hand_case(name, vec![], vec![], vec![push(&[vec![prefix], x.to_vec()].concat())],
                    hand_expected(&[(x, 19)], &[], &[])));
            }
            Ok(cases)
        }

        fn committed_transactions(mut spends: Vec<TestTx>, height: u32) -> Vec<TestTx> {
            let has_witness = spends.iter().any(|tx| !tx.witness.is_empty());
            let mut coinbase = TestTx { coinbase: true, script_sig: push(&height.to_le_bytes()),
                outputs: vec![vec![0x51]], witness: vec![], lock_time: 0 };
            if has_witness {
                let root = test_root(std::iter::once([0; 32])
                    .chain(spends.iter().map(|tx| double_sha256(&tx.serialize(true)))).collect());
                let commitment = double_sha256(&[root.as_slice(), &[0x42; 32]].concat());
                coinbase.witness = vec![vec![0x42; 32]];
                coinbase.outputs.push([vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed], commitment.to_vec()].concat());
            }
            spends.insert(0, coinbase);
            spends
        }

        fn assert_hand_extract(block: &[u8], expected: &BlockExtract, name: &str) -> TestResult {
            let actual = extract_block(block, 0, &double_sha256(&block[..80]), &[0; 32])?;
            assert_eq!(actual.transactions, expected.transactions, "{} transactions", name);
            assert_eq!(actual.x, expected.x, "{} x", name);
            assert_eq!(actual.h20, expected.h20, "{} h20", name);
            assert_eq!(actual.h32, expected.h32, "{} h32", name);
            Ok(())
        }

        fn merge_hand_expected(target: &mut BlockExtract, source: BlockExtract) {
            for (key, mask) in source.x { *target.x.entry(key).or_insert(0) |= mask; }
            for (key, mask) in source.h20 { *target.h20.entry(key).or_insert(0) |= mask; }
            for (key, mask) in source.h32 { *target.h32.entry(key).or_insert(0) |= mask; }
        }

        fn hand_merge_cases() -> Vec<HandCase> {
            let mut cases = vec![
                hand_case("merge x output push", vec![], vec![], vec![push(&compressed(&[0x63; 32]))],
                    hand_expected(&[([0x63; 32], 19)], &[], &[])),
                hand_case("merge x input push", push(&compressed(&[0x63; 32])), vec![], vec![],
                    hand_expected(&[([0x63; 32], 33)],
                        &[(hash160(&compressed(&[0x63; 32])), 8),
                            (hash160(&[vec![0, 32], sha256(&compressed(&[0x63; 32])).to_vec()].concat()), 24)],
                        &[(sha256(&compressed(&[0x63; 32])), 6)])),
                hand_case("merge x P2PK", vec![], vec![], vec![[push(&compressed(&[0x63; 32])), vec![0xac]].concat()],
                    hand_expected(&[([0x63; 32], 55)], &[], &[])),
            ];
            for (name, output, mask) in [("merge funded P2PKH", pkh([0x64; 20]), 1),
                ("merge funded P2WPKH", wpkh([0x64; 20]), 2),
                ("merge funded P2SH", [vec![0xa9, 20], vec![0x64; 20], vec![0x87]].concat(), 4)] {
                cases.push(hand_case(name, vec![], vec![], vec![output], hand_expected(&[], &[([0x64; 20], mask)], &[])));
            }
            let script = vec![0x51, 0x52, 0x75];
            let wrapped = [vec![0, 32], sha256(&script).to_vec()].concat();
            cases.push(hand_case("merge reveal", vec![], vec![vec![0x65; 64], script.clone()], vec![],
                hand_expected(&[], &[(hash160(&script), 24), (hash160(&wrapped), 24)], &[(sha256(&script), 2)])));
            cases.push(hand_case("merge fund revealed forms", vec![], vec![], vec![p2sh(&script), p2wsh(&script)],
                hand_expected(&[], &[(hash160(&script), 4)], &[(sha256(&script), 1)])));
            cases
        }

        #[test]
        fn extractor_hand_specified_rows_and_transaction_union() -> TestResult {
            for case in hand_cases()?.into_iter().chain(hand_merge_cases()) {
                let block = block_bytes(&committed_transactions(vec![case.tx], 0), true);
                assert_hand_extract(&block, &case.expected, case.name)?;
            }
            let mut expected = hand_expected(&[], &[], &[]);
            let mut txs = Vec::new();
            let mut txids = FxHashSet::default();
            for (i, mut case) in hand_cases()?.into_iter().chain(hand_merge_cases()).enumerate() {
                // Witness differences do not change txid; lock time keeps transactions unique in merged blocks without affecting extraction.
                case.tx.lock_time = u32::try_from(i + 1)?;
                assert!(txids.insert(double_sha256(&case.tx.serialize(false))), "duplicate txid for {}", case.name);
                merge_hand_expected(&mut expected, case.expected);
                txs.push(case.tx);
            }
            assert_eq!(expected.x[&[0x63; 32]], 55);
            assert_eq!(expected.h20[&[0x64; 20]], 7);
            assert_eq!(expected.h20[&hash160(&[0x51, 0x52, 0x75])], 28);
            assert_eq!(expected.h32[&sha256(&[0x51, 0x52, 0x75])], 3);
            expected.transactions = txs.len() + 1;
            assert_hand_extract(&block_bytes(&committed_transactions(txs, 0), true), &expected, "union")
        }

        #[test]
        fn real_scan_persisted_state_matches_hand_specified_union() -> TestResult {
            let temp = TempDir::new()?;
            let mut chain = Vec::new();
            let mut prev = [0; 32];
            let mut expected = hand_expected(&[], &[], &[]);
            for (height, case) in hand_cases()?.into_iter().chain(hand_merge_cases()).enumerate() {
                let mut block = block_bytes(&committed_transactions(vec![case.tx], height as u32), true);
                block[4..36].copy_from_slice(&prev);
                prev = double_sha256(&block[..80]);
                chain.push(block);
                merge_hand_expected(&mut expected, case.expected);
            }
            write_chain(&temp.0, &chain)?;
            assert_eq!(scan(&temp.0, "out")?, 0);
            for (name, mut records) in [
                ("x.bin", expected.x.iter().map(|(k, m)| [k.to_vec(), vec![*m]].concat()).collect::<Vec<_>>()),
                ("f20.bin", expected.h20.iter().filter(|(_, m)| **m & 7 != 0)
                    .map(|(k, m)| [k.to_vec(), vec![m & 7]].concat()).collect()),
                ("r20.bin", expected.h20.iter().filter(|(_, m)| **m & 24 != 0)
                    .map(|(k, m)| [k.to_vec(), vec![m & 24]].concat()).collect()),
                ("f32.bin", expected.h32.iter().filter(|(_, m)| **m & 1 != 0).map(|(k, _)| k.to_vec()).collect()),
                ("r32.bin", expected.h32.iter().filter(|(_, m)| **m & 6 != 0)
                    .map(|(k, m)| [k.to_vec(), vec![m & 6]].concat()).collect()),
            ] {
                records.sort();
                assert_eq!(fs::read(temp.0.join("out/state").join(name))?, records.concat(), "{}", name);
            }
            Ok(())
        }

        fn fixture_key(number: u8) -> Result<PublicKey, String> {
            let mut secret = [0; 32];
            secret[31] = number;
            let secret = secp256k1::SecretKey::from_slice(&secret).map_err(|e| e.to_string())?;
            Ok(PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret))
        }

        fn rich_fixture_chain() -> Result<Vec<Vec<u8>>, String> {
            let mut spends = Vec::new();
            let mut funding = Vec::new();
            for case in hand_cases()? {
                // Fund in other blocks to cover every reveal/cross form while keeping each row's test independent.
                for (hash, mask) in case.expected.h20 {
                    if mask & 8 != 0 { funding.push([vec![0xa9, 20], hash.to_vec(), vec![0x87]].concat()); }
                }
                for (hash, mask) in case.expected.h32 {
                    if mask & 2 != 0 { funding.push([vec![0, 32], hash.to_vec()].concat()); }
                }
                // The standard key spend's pubkey hash appears in an earlier funding transaction.
                for x in case.expected.x.keys() {
                    funding.push(pkh(hash160(&compressed(x))));
                    funding.push(wpkh(hash160(&compressed(x))));
                    funding.push(p2sh(&wpkh(hash160(&compressed(x)))));
                }
                spends.push(case.tx);
            }
            // Fund all six SEC encodings and their wrapped forms for an already-published key.
            let mut key = fixture_key(100)?.serialize();
            for prefix in [2, 3] {
                key[0] = prefix;
                let uncompressed = PublicKey::from_slice(&key).map_err(|e| e.to_string())?.serialize_uncompressed();
                let mut hybrid = uncompressed;
                hybrid[0] = prefix + 4;
                for encoding in [&key[..], &uncompressed[..], &hybrid[..]] {
                    let hash = hash160(encoding);
                    funding.push(pkh(hash));
                    funding.push(p2sh(&wpkh(hash)));
                }
            }
            funding.sort();
            funding.dedup();
            spends.insert(0, TestTx { coinbase: false, script_sig: vec![], outputs: funding, witness: vec![], lock_time: 0 });
            // Use a separate transaction per key; multiple funding forms for the same key specifically test cross_type_reuse.
            for number in 100..108 {
                let point = fixture_key(number)?;
                let key = point.serialize().to_vec();
                let uncompressed = point.serialize_uncompressed().to_vec();
                let mut hybrid = uncompressed.clone();
                hybrid[0] = 6 + (hybrid[64] & 1);
                spends.push(TestTx { coinbase: false, script_sig: vec![], witness: vec![], lock_time: 0, outputs: vec![
                    [push(&key), vec![0xac]].concat(), pkh(hash160(&key)), wpkh(hash160(&key)),
                    p2sh(&wpkh(hash160(&key))), pkh(hash160(&uncompressed)), pkh(hash160(&hybrid)),
                ] });
            }
            // Annex, future leaf versions, and invalid controls each use separate signing and internal keys.
            for (number, version, paths, annex, bad_control) in [
                (120, 0xc0, 0, true, false), (123, 0xc0, 2, true, false),
                (126, 0xc2, 0, false, false), (129, 0xc0, 0, false, true),
            ] {
                let key = fixture_key(number)?.serialize();
                let internal = fixture_key(number + 1)?.serialize();
                let uncompressed = fixture_key(number + 2)?.serialize_uncompressed();
                let mut hybrid = uncompressed;
                hybrid[0] = 6 + (hybrid[64] & 1);
                let script = [push(&key[1..]), vec![0xad], push(&key), push(&hybrid),
                    push(&[vec![2], vec![0xff; 32]].concat())].concat();
                let mut control = [vec![version], if bad_control { vec![0xff; 32] } else { internal[1..].to_vec() }].concat();
                for index in 0..paths { control.extend_from_slice(&[number + index; 32]); }
                let mut witness = vec![vec![number; 64], script.clone(), control];
                if annex { witness.push(vec![0x50, number]); }
                spends.push(TestTx { coinbase: false, script_sig: vec![], witness, lock_time: 0,
                    outputs: vec![p2sh(&script), p2wsh(&script), p2sh(&p2wsh(&script))] });
            }
            let p2pk = [push(&fixture_key(140)?.serialize()), vec![0xac]].concat();
            spends.push(TestTx { coinbase: false, script_sig: push(&[0x45; 64]), witness: vec![], outputs: vec![p2pk], lock_time: 0 });
            let redeem = [push(&fixture_key(141)?.serialize()), vec![0xac]].concat();
            spends.push(TestTx { coinbase: false, script_sig: push(&redeem), witness: vec![],
                outputs: vec![p2sh(&redeem), p2wsh(&redeem)], lock_time: 0 });
            spends.push(TestTx { coinbase: false, script_sig: vec![], witness: vec![vec![0x46; 64], vec![]],
                outputs: vec![p2wsh(&[])], lock_time: 0 });
            let count = spends.len().max(40);
            let mut spends = spends.into_iter();
            let mut chain = Vec::new();
            let mut prev = [0; 32];
            for height in 0..count {
                let txs = committed_transactions(spends.next().into_iter().collect(), height as u32);
                let mut block = block_bytes(&txs, true);
                block[4..36].copy_from_slice(&prev);
                block[68..72].copy_from_slice(&(height as u32).to_le_bytes());
                prev = double_sha256(&block[..80]);
                chain.push(block);
            }
            Ok(chain)
        }

        #[test]
        #[ignore]
        fn write_scan_fixture() -> TestResult {
            let dir = PathBuf::from(env::var("BTC_INDEXER_FIXTURE_DIR")?);
            write_chain(&dir, &rich_fixture_chain()?)?;
            Ok(())
        }

        #[test]
        fn chain_list_strict_format() -> TestResult {
            let a = "01".repeat(32);
            let b = "ab".repeat(32);
            let valid = format!("0 {}\n1 {}\n", a, b);
            assert_eq!(parse_chain_list(valid.as_bytes())?.len(), 2);
            let cases = vec![
                ("".to_string(), 1), (format!("0 {}", a), 1), (format!("0 {}\n1 {}", a, b), 2),
                (format!("0 {}\r\n", a), 1), (format!("00 {}\n", a), 1),
                (format!("1 {}\n", a), 1), (format!("0 {}\n2 {}\n", a, b), 2),
                (format!("0 {}\n1 {}\n", a, a), 2), (format!("0 {}\n", b.to_uppercase()), 1),
                (format!("0 {} \n", a), 1), (format!("0  {}\n", a), 1),
                (format!("0 {}\n\n", a), 2), ("0 00\n".to_string(), 1),
                (format!("0 {}g\n", &a[..63]), 1), (format!("0 {}\n", "\u{e9}".repeat(32)), 1),
                (format!("0 {}\n1\t{}\n", a, b), 2), (format!("+0 {}\n", a), 1),
            ];
            for (input, line) in cases {
                let err = parse_chain_list(input.as_bytes()).err().ok_or("invalid chain list accepted")?;
                assert!(err.contains(&format!("line {}:", line)), "{}", err);
            }
            Ok(())
        }

        fn extraction_error(block: &[u8], expected: &[u8; 32], prev: &[u8; 32], message: &str) -> TestResult {
            let err = extract_block(block, 0, expected, prev).err().ok_or("invalid block accepted")?;
            assert!(err.contains(message) && err.contains("height 0") && err.contains(&display_hash(expected))
                && err.contains("byte offset"), "{}", err);
            Ok(())
        }

        #[test]
        fn extractor_validation_negatives() -> TestResult {
            let valid = block_bytes(&fixture(), true);
            let hash = double_sha256(&valid[..80]);
            assert_eq!(extract_block(&valid, 0, &hash, &[0; 32])?.transactions, 3);
            extraction_error(&valid[..79], &hash, &[0; 32], "short header")?;
            extraction_error(&valid, &[9; 32], &[0; 32], "header hash mismatch")?;
            extraction_error(&valid, &hash, &[1; 32], "previous block hash mismatch")?;
            let mut block = valid.clone(); block.push(0);
            extraction_error(&block, &hash, &[0; 32], "trailing bytes")?;
            let mut block = valid[..90].to_vec();
            extraction_error(&block, &hash, &[0; 32], "does not parse")?;
            block = valid[..80].to_vec();
            extraction_error(&block, &hash, &[0; 32], "transaction count")?;
            block.push(0);
            extraction_error(&block, &hash, &[0; 32], "transaction count")?;
            block = valid.clone(); block[36] ^= 1;
            extraction_error(&block, &double_sha256(&block[..80]), &[0; 32], "merkle root mismatch")?;
            let mut txs = fixture();
            let last = txs.last().ok_or("missing fixture tx")?;
            txs.push(TestTx { coinbase: last.coinbase, script_sig: last.script_sig.clone(),
                outputs: last.outputs.clone(), witness: last.witness.clone(), lock_time: last.lock_time });
            block = block_bytes(&txs, true);
            extraction_error(&block, &double_sha256(&block[..80]), &[0; 32], "mutated merkle tree")?;
            let mut txs = fixture(); txs[0].outputs[2][6] ^= 1;
            block = block_bytes(&txs, true);
            extraction_error(&block, &double_sha256(&block[..80]), &[0; 32], "witness commitment mismatch")?;
            let mut txs = fixture(); txs[0].witness.clear();
            block = block_bytes(&txs, true);
            extraction_error(&block, &double_sha256(&block[..80]), &[0; 32], "reserved value")?;
            let mut txs = fixture(); txs[0].outputs.clear();
            block = block_bytes(&txs, true);
            extraction_error(&block, &double_sha256(&block[..80]), &[0; 32], "missing witness commitment")?;
            Ok(())
        }

        #[test]
        fn digest_known_answer() -> TestResult {
            let block = std::array::from_fn(|i| i as u8);
            let hashes = DIGEST_FILES.map(|name| sha256(name.as_bytes()));
            assert_eq!(1 + RULES_VERSION.len() + 8 + 32 + 8 * 32, 322);
            assert_eq!(hex::encode(hashes[0]), "ec8bb72991f2b1c7899099920b58572b5ad622a3ab0ffdd0dcf900997d011530");
            assert_eq!(hex::encode(state_digest(RULES_VERSION, 975019, &block, &hashes)?),
                "c226df66cefb911b70f1859d0e04b87d7b6efa9572eb631f992f066b5e2199fa");
            Ok(())
        }

        #[test]
        fn real_scan_state_checkpoint_and_fail_closed_cases() -> TestResult {
            let temp = TempDir::new()?;
            let chain = synthetic_chain(40)?;
            write_chain(&temp.0, &chain)?;
            let mut first = vec![0x77, 0x88, 0x99];
            let mut second = Vec::new();
            for (h, b) in chain.iter().enumerate().rev() {
                if h % 2 == 0 { first.extend(record(b)); } else { second.extend(record(b)); }
            }
            let mut stale = chain[0].clone(); stale[76] ^= 1;
            first.extend(record(&stale));
            first.extend([0; 64]);
            second.extend([0xf9, 0xbe, 0xb4, 0xd9, 0xff, 0xff, 0, 0, 1, 2]);
            fs::write(temp.0.join("blocks/blk00000.dat"), &first)?;
            fs::write(temp.0.join("blocks/blk00001.dat"), &second)?;
            assert_eq!(scan(&temp.0, "out")?, 1);
            let out = temp.0.join("out");
            let stats: serde_json::Value = serde_json::from_slice(&fs::read(out.join("stats.json"))?)?;
            let checkpoint: serde_json::Value = serde_json::from_slice(&fs::read(out.join("checkpoint.json"))?)?;
            assert_eq!(stats["scan_height"], 39);
            assert_eq!(stats["scan_block_hash"], header_hash(&chain[39]));
            assert_eq!(checkpoint["format"], "btc-indexer-checkpoint/1");
            assert_eq!(checkpoint["rules_version"], RULES_VERSION);
            assert_eq!(checkpoint["height"], 39);
            assert_eq!(checkpoint["block_hash"], stats["scan_block_hash"]);
            assert_eq!(fs::read(out.join("last_indexed_height"))?, b"39\n");
            assert_ne!(fs::read(out.join("stats.json"))?.last(), Some(&b'\n'));
            assert_ne!(fs::read(out.join("checkpoint.json"))?.last(), Some(&b'\n'));
            assert!(!out.join("shards").exists());
            let mut expected_x = FxHashMap::default();
            let mut expected_h20 = FxHashMap::default();
            let mut expected_h32 = FxHashMap::default();
            for (h, b) in chain.iter().enumerate() {
                let prev = if h == 0 { [0; 32] } else { double_sha256(&chain[h - 1][..80]) };
                let e = extract_block(b, h as u64, &double_sha256(&b[..80]), &prev)?;
                for (k, m) in e.x { *expected_x.entry(k).or_insert(0u8) |= m; }
                for (k, m) in e.h20 { *expected_h20.entry(k).or_insert(0u8) |= m; }
                for (k, m) in e.h32 { *expected_h32.entry(k).or_insert(0u8) |= m; }
            }
            assert!(expected_x.contains_key(&[0xff; 32]));
            for (name, key_width, width, expected) in [
                ("state/x.bin", 32, 33, expected_x.iter().map(|(k,m)| [k.to_vec(), vec![*m]].concat()).collect::<Vec<_>>()),
                ("state/f20.bin", 20, 21, expected_h20.iter().filter(|(_,m)| **m & 7 != 0).map(|(k,m)| [k.to_vec(), vec![m & 7]].concat()).collect()),
                ("state/r20.bin", 20, 21, expected_h20.iter().filter(|(_,m)| **m & 24 != 0).map(|(k,m)| [k.to_vec(), vec![m & 24]].concat()).collect()),
                ("state/f32.bin", 32, 32, expected_h32.iter().filter(|(_,m)| **m & 1 != 0).map(|(k,_)| k.to_vec()).collect()),
                ("state/r32.bin", 32, 33, expected_h32.iter().filter(|(_,m)| **m & 6 != 0).map(|(k,m)| [k.to_vec(), vec![m & 6]].concat()).collect()),
            ] {
                let bytes = fs::read(out.join(name))?;
                assert_eq!(bytes.len() % width, 0);
                let records: Vec<_> = bytes.chunks_exact(width).collect();
                assert!(records.windows(2).all(|w| w[0][..key_width] < w[1][..key_width]));
                let mut expected = expected; expected.sort();
                assert_eq!(bytes, expected.concat(), "{}", name);
            }
            assert_eq!(fs::metadata(out.join("state/x.bin"))?.len() / 33,
                stats["unique_published_x_coords"].as_u64().ok_or("missing x count")?);
            for name in ["pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin",
                "cross_format_diff_20.bin", "cross_format_diff_32.bin"] {
                assert!(fs::metadata(out.join(name))?.len() > 0, "empty fixture table {}", name);
            }
            let entries = checkpoint["files"].as_object().ok_or("missing checkpoint files")?;
            assert_eq!(entries.len(), 12);
            for (name, meta) in entries {
                let bytes = fs::read(out.join(name))?;
                assert_eq!(meta["bytes"], bytes.len() as u64);
                assert_eq!(meta["sha256"], hex::encode(sha256(&bytes)));
                if let Some(records) = meta.get("records") {
                    let width = if name == "state/x.bin" || name == "state/r32.bin" { 33 }
                        else if name == "state/f20.bin" || name == "state/r20.bin" { 21 }
                        else if name.ends_with("32.bin") { 32 } else { 20 };
                    assert_eq!(records.as_u64(), Some(bytes.len() as u64 / width));
                } else { assert!(name == "stats.json" || name == "last_indexed_height"); }
            }
            let mut hashes = [[0; 32]; 8];
            for (i, name) in DIGEST_FILES.iter().enumerate() { hashes[i] = sha256(&fs::read(out.join(name))?); }
            let mut display = double_sha256(&chain[39][..80]); display.reverse();
            assert_eq!(checkpoint["state_digest"], hex::encode(state_digest(RULES_VERSION, 39, &display, &hashes)?));
            assert!(scan(&temp.0, "out").err().is_some_and(|e| e.contains("empty")));
            fs::write(temp.0.join("blocks/xor.dat"), [0, 1])?;
            assert!(scan(&temp.0, "xor").err().is_some_and(|e| e.contains("xor.dat")));
            fs::write(temp.0.join("blocks/xor.dat"), [0; 8])?;
            fs::write(temp.0.join("blocks/blk00000.dat"), record(&chain[0]))?;
            fs::write(temp.0.join("blocks/blk00001.dat"), record(&chain[0]))?;
            assert!(scan(&temp.0, "duplicate").err().is_some_and(|e| e.contains("duplicate block")));
            fs::write(temp.0.join("blocks/blk00001.dat"), [])?;
            assert!(scan(&temp.0, "missing").err().is_some_and(|e| e.contains("39 listed blocks missing")));
            Ok(())
        }

        fn fake_export(mode: &'static str, height: u64) -> TestResult {
            let temp = TempDir::new()?;
            fs::write(temp.0.join("cookie"), "__cookie__:secret\n")?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let url = format!("http://{}/", listener.local_addr()?);
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let thread = std::thread::spawn(move || -> Result<Vec<usize>, String> {
                let mut batch_sizes = Vec::new();
                loop {
                    let (mut stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if worker_stop.load(Ordering::Relaxed) { return Ok(batch_sizes); }
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        },
                        Err(e) => return Err(e.to_string()),
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
                    let mut header = String::new();
                    let mut length = None;
                    let mut authorized = false;
                    loop {
                        header.clear();
                        if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0 {
                            return Err("fake RPC premature EOF".to_string());
                        }
                        if header == "\r\n" { break; }
                        if header == "Authorization: Basic X19jb29raWVfXzpzZWNyZXQ=\r\n" { authorized = true; }
                        if let Some(n) = header.strip_prefix("Content-Length: ") {
                            length = Some(n.trim().parse::<usize>().map_err(|e| e.to_string())?);
                        }
                    }
                    if !authorized { return Err("fake RPC authorization mismatch".to_string()); }
                    let mut body = vec![0; length.ok_or("fake RPC missing Content-Length")?];
                    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
                    let request: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
                    let response = if let Some(calls) = request.as_array() {
                        batch_sizes.push(calls.len());
                        let mut results: Vec<_> = calls.iter().rev().map(|call| {
                            let id = call["id"].as_u64().unwrap_or(u64::MAX);
                            let mut hash = hex::encode(sha256(&id.to_be_bytes()));
                            if mode == "uppercase" { hash = hash.to_uppercase(); }
                            serde_json::json!({"id":id,"result":hash,"error":null})
                        }).collect();
                        if mode == "duplicate-id" && !results.is_empty() { results.push(results[0].clone()); }
                        if mode == "missing-id" { results.pop(); }
                        serde_json::Value::Array(results)
                    } else if request["method"] == "getblockchaininfo" {
                        serde_json::json!({"id":0,"error":null,"result":{
                            "initialblockdownload": mode == "ibd", "blocks": if mode == "depth" { height + 99 } else { height + 100 },
                            "headers": if mode == "depth" { height + 99 } else { height + 100 }}})
                    } else {
                        let mut hash = sha256(&height.to_be_bytes());
                        if mode == "reorg" { hash[0] ^= 1; }
                        serde_json::json!({"id":0,"result":hex::encode(hash),"error":null})
                    };
                    let bytes = if mode == "json" { b"{broken".to_vec() }
                        else if mode == "rpc-error" { br#"{"id":0,"error":{"code":-1},"result":null}"#.to_vec() }
                        else { serde_json::to_vec(&response).map_err(|e| e.to_string())? };
                    if mode == "no-length" {
                        write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
                    } else if mode == "status" {
                        write!(stream, "HTTP/1.1 500 Bad\r\nContent-Length: 0\r\n\r\n").map_err(|e| e.to_string())?;
                    } else {
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", bytes.len()).map_err(|e| e.to_string())?;
                        stream.write_all(&bytes).map_err(|e| e.to_string())?;
                    }
                }
            });
            let out = temp.0.join("list.txt");
            let result = export_chain_list(&url, &temp.0.join("cookie"), height, &out);
            stop.store(true, Ordering::Relaxed);
            let batches = thread.join().map_err(|_| "fake RPC thread panicked")??;
            if mode == "success" {
                result?;
                let chain = parse_chain_list(&fs::read(&out)?)?;
                assert_eq!(chain.len() as u64, height + 1);
                assert_eq!(batches, vec![1000, 2]);
                assert!(export_chain_list(&url, &temp.0.join("cookie"), height, &out).is_err());
            } else {
                assert!(result.is_err(), "fake export mode {} succeeded", mode);
                assert!(!out.exists());
            }
            Ok(())
        }

        #[test]
        fn export_rpc_batch_auth_and_rejections() -> TestResult {
            for (bytes, expected) in [(b"".as_slice(), ""), (b"f", "Zg=="), (b"fo", "Zm8="),
                (b"foo", "Zm9v"), (b"foob", "Zm9vYg==")] {
                assert_eq!(base64(bytes), expected);
            }
            for mode in ["success", "ibd", "depth", "reorg", "json", "rpc-error",
                "no-length", "status", "uppercase", "duplicate-id", "missing-id"] {
                fake_export(mode, 1001)?;
            }
            let temp = TempDir::new()?;
            let cookie = temp.0.join("cookie");
            fs::write(&cookie, "__cookie__:url-test\n")?;
            for (index, (url, expected)) in [
                ("https://localhost:8332/", "RPC URL must be http://<host>:<port>/"),
                ("http://localhost:8332/x", "RPC URL must be http://<host>:<port>/"),
                ("http://localhost/", "RPC URL requires a port"),
                ("http://localhost:8332", "RPC URL must be http://<host>:<port>/"),
                ("http://a:8332/x/", "RPC URL must be http://<host>:<port>/"),
                ("http://u@a:8332/", "RPC URL must be http://<host>:<port>/"),
            ].into_iter().enumerate() {
                let error = export_chain_list(url, &cookie, 0, &temp.0.join(format!("url-{}.txt", index)))
                    .err().ok_or("invalid RPC URL accepted")?;
                assert_eq!(error, expected, "{}", url);
            }
            Ok(())
        }

        #[test]
        fn missing_directory_levels_are_ordered_and_exclude_existing_ancestors() -> TestResult {
            let temp = TempDir::new()?;
            let path = temp.0.join("a/b/c");
            assert_eq!(missing_directory_levels(&path)?,
                vec![temp.0.join("a"), temp.0.join("a/b"), path.clone()]);
            fs::create_dir(temp.0.join("a"))?;
            assert_eq!(missing_directory_levels(&path)?, vec![temp.0.join("a/b"), path]);
            assert!(missing_directory_levels(&temp.0)?.is_empty());

            let relative_root = PathBuf::from(temp.0.file_name().ok_or("test directory name")?).with_extension("missing");
            assert!(matches!(fs::symlink_metadata(&relative_root),
                Err(e) if e.kind() == io::ErrorKind::NotFound));
            let relative = relative_root.join("a/b/c");
            assert_eq!(missing_directory_levels(&relative)?,
                vec![relative_root.clone(), relative_root.join("a"), relative_root.join("a/b"), relative]);
            Ok(())
        }

        #[test]
        fn missing_directory_levels_rejects_paths_through_regular_files() -> TestResult {
            let temp = TempDir::new()?;
            fs::write(temp.0.join("f"), b"")?;
            let path = temp.0.join("f/x");
            let error = missing_directory_levels(&path).err().ok_or("path through regular file accepted")?;
            assert!(error.starts_with(&format!("{}: metadata: ", path.display())), "{}", error);
            Ok(())
        }

        #[test]
        fn scan_rejects_empty_output_directory_without_creating_files() -> TestResult {
            let temp = TempDir::new()?;
            let error = scan_blocks_dir(temp.0.join("blocks").to_str().ok_or("test blocks path")?, "",
                temp.0.join("chain-list.txt").to_str().ok_or("test list path")?)
                .err().ok_or("empty output directory accepted")?;
            assert_eq!(error, "output directory path must not be empty");
            assert_eq!(fs::read_dir(&temp.0)?.count(), 0);
            Ok(())
        }

        #[test]
        fn failed_checkpoint_withdrawal_removes_file_and_preserves_original_error() -> TestResult {
            let temp = TempDir::new()?;
            let path = temp.0.join("checkpoint.json");
            fs::write(&path, b"{}")?;
            let error = withdraw_failed_checkpoint(&path, "original publication error".to_string());
            assert!(error.starts_with("original publication error; "), "{}", error);
            assert!(error.contains(&path.display().to_string()) && error.contains(": removed"), "{}", error);
            assert!(matches!(fs::symlink_metadata(&path), Err(e) if e.kind() == io::ErrorKind::NotFound));
            Ok(())
        }

        #[test]
        fn failed_checkpoint_withdrawal_preserves_error_when_file_is_absent() -> TestResult {
            let temp = TempDir::new()?;
            let error = withdraw_failed_checkpoint(&temp.0.join("checkpoint.json"), "original publication error".to_string());
            assert_eq!(error, "original publication error");
            Ok(())
        }

        #[test]
        fn failed_checkpoint_withdrawal_warns_when_path_cannot_be_removed() -> TestResult {
            let temp = TempDir::new()?;
            let path = temp.0.join("checkpoint.json");
            fs::create_dir(&path)?;
            let error = withdraw_failed_checkpoint(&path, "original publication error".to_string());
            assert!(error.starts_with("original publication error; "), "{}", error);
            assert!(error.contains(&path.display().to_string())
                && error.contains("remains in the output directory and must not be used: remove: "), "{}", error);
            assert!(path.is_dir());
            Ok(())
        }

        #[test]
        fn writer_ordering_and_missing_shard_errors() -> TestResult {
            let temp = TempDir::new()?;
            let mut writer = ScanWriter::new(temp.0.join("state.bin"))?;
            writer.record(&[2; 32], &[1])?;
            assert!(writer.record(&[2; 32], &[2]).is_err());
            assert!(writer.record(&[1; 32], &[1]).is_err());
            writer.finish(Some(33))?;
            assert!(read_scan_shard(&temp.0.join("missing.bin"), 33).is_err());
            fs::write(temp.0.join("short.bin"), [0; 32])?;
            assert!(read_scan_shard(&temp.0.join("short.bin"), 33).is_err());
            Ok(())
        }
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
