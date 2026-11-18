use super::*;

pub const BUCKETS: [&str; 9] = [
    "witness_v0_wrong_length", "witness_v1_non32", "witness_v2_v16",
    "mt_gox_malformed", "bare_multisig_outside_policy", "p2pk_nonminimal_push",
    "anyone_can_spend", "hash_puzzle", "everything_else",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub utxo_count: u64,
    pub amount_sats: u64,
    pub distinct_keys: u64,
}
impl Tally {
    pub fn record(&mut self, count: u64, amount: u64, distinct: u64) -> io::Result<()> {
        add(&mut self.utxo_count, count)?;
        add(&mut self.amount_sats, amount)?;
        add(&mut self.distinct_keys, distinct)
    }
    fn json(self) -> String {
        format!("{{\"utxo_count\":{},\"amount_sats\":{},\"distinct_keys\":{}}}", self.utxo_count, self.amount_sats, self.distinct_keys)
    }
}

#[derive(Debug, Default)]
pub struct Details {
    pub p2sh: [Tally; 3],
    pub cross_format: [Tally; 4],
    pub histogram: [Tally; 9],
    pub(crate) top: Vec<Aggregate>,
    pub curve: [[Tally; 2]; 3],
    pub extra_entries: [Option<u64>; 3],
}

// Return pushed bytes and whether the length opcode is minimal for a key.
fn push<'a>(s: &'a [u8], pos: &mut usize) -> Option<(&'a [u8], bool)> {
    let opcode = *s.get(*pos)?;
    *pos += 1;
    let length = match opcode {
        0..=75 => usize::from(opcode),
        76 => { let n = usize::from(*s.get(*pos)?); *pos += 1; n }
        77 => { let n = u16::from_le_bytes(s.get(*pos..*pos + 2)?.try_into().ok()?); *pos += 2; usize::from(n) }
        78 => { let n = u32::from_le_bytes(s.get(*pos..*pos + 4)?.try_into().ok()?); *pos += 4; usize::try_from(n).ok()? }
        _ => return None,
    };
    let end = pos.checked_add(length)?;
    let data = s.get(*pos..end)?;
    *pos = end;
    Some((data, opcode <= 75))
}

fn small_number(op: u8) -> Option<i32> {
    match op { 0 => Some(0), 0x4f => Some(-1), 0x51..=0x60 => Some(i32::from(op - 0x50)), _ => None }
}

fn multisig_template(s: &[u8]) -> bool {
    if s.len() < 3 || s.last() != Some(&0xae) { return false; }
    let (Some(m), Some(n)) = (small_number(s[0]), small_number(s[s.len() - 2])) else { return false; };
    let end = s.len() - 2;
    let mut pos = 1;
    let mut count = 0;
    let mut nonminimal = false;
    while pos < end {
        let Some((key, minimal)) = push(&s[..end], &mut pos) else { return false; };
        if key.len() != 33 && key.len() != 65 { return false; }
        nonminimal |= !minimal;
        count += 1;
    }
    count == n && (!(1..=3).contains(&m) || !(1..=3).contains(&n) || nonminimal)
}

pub fn bucket(s: &[u8]) -> usize {
    if s.len() >= 4 && (2..=40).contains(&s[1]) && s.len() == usize::from(s[1]) + 2 {
        match s[0] {
            0 if s[1] != 20 && s[1] != 32 => return 0,
            0x51 if s[1] != 32 => return 1,
            0x52..=0x60 => return 2,
            _ => (),
        }
    }
    if s == [0x76, 0xa9, 0, 0x88, 0xac] { return 3; }
    if multisig_template(s) { return 4; }
    let mut pos = 0;
    if let Some((key, minimal)) = push(s, &mut pos) {
        if !minimal && (key.len() == 33 || key.len() == 65) && s.get(pos..) == Some(&[0xac][..]) { return 5; }
    }
    // Empty script can be satisfied by a true scriptSig stack item.
    // Recognize constant templates, not general script execution.
    if s.is_empty() { return 6; }
    if s.len() == 1 && (s[0] == 0x4f || (0x51..=0x60).contains(&s[0])) { return 6; }
    if s.first() == Some(&0xa8) || s.first() == Some(&0xa9) {
        let mut pos = 1;
        if let Some((digest, _)) = push(s, &mut pos) {
            let expected = if s[0] == 0xa8 { 32 } else { 20 };
            if digest.len() == expected && s.get(pos..) == Some(&[0x87][..]) { return 7; }
        }
    }
    8
}

pub fn valid_multisig(script: &Script) -> bool {
    let Script::Raw(s) = script else { return false; };
    let mut pos = 1;
    let mut valid = 0;
    while pos < s.len() - 2 {
        let Some((key, _)) = push(s, &mut pos) else { return false; };
        valid += usize::from(curve::pubkey(key));
    }
    valid >= usize::from(s[0] - 0x50)
}

impl Details {
    pub fn observe_table(&mut self, index: usize, entries: u64) -> io::Result<()> {
        if self.extra_entries[index].is_some_and(|old| old != entries) { return Err(invalid("table changed between scans")); }
        self.extra_entries[index] = Some(entries);
        Ok(())
    }

    pub fn record_other(&mut self, script: &Script, amount: u64, out: &mut impl Write) -> io::Result<()> {
        let (hash, prefix, truncated, bucket) = match script {
            Script::Raw(s) => (sha256::digest(s), &s[..s.len().min(80)], s.len() > 80, bucket(s)),
            Script::Oversized { hash, prefix } => (*hash, prefix.as_slice(), true, 8),
            _ => return Err(invalid("unexpected other representation")),
        };
        self.histogram[bucket].record(1, amount, 0)?;
        let mut record = [0; KEY_BYTES];
        record[..32].copy_from_slice(&hash);
        record[32] = prefix.len() as u8;
        record[33] = u8::from(truncated);
        record[34..34 + prefix.len()].copy_from_slice(prefix);
        out.write_all(&record)?;
        out.write_all(&amount.to_le_bytes())
    }

    pub fn finish(&mut self, work: &Path, config: &Config, classes: &[Stats; 8]) -> io::Result<()> {
        let path = aggregate_named(work, "other_raw", KEY_BYTES, config.chunk_records)?;
        let mut reader = BufReader::new(File::open(path)?);
        while let Some(row) = read_aggregate(&mut reader, KEY_BYTES)? {
            self.top.push(row);
            self.top.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
            self.top.truncate(20);
        }
        if config.check_curve {
            let path = aggregate_named(work, "valid_multisig", 32, config.chunk_records)?;
            let mut reader = BufReader::new(File::open(path)?);
            while let Some(row) = read_aggregate(&mut reader, 32)? { self.curve[2][0].record(row.count, row.amount, 1)?; }
            let valid = self.curve[2][0];
            self.curve[2][1] = Tally {
                utxo_count: classes[6].utxo_count - valid.utxo_count,
                amount_sats: classes[6].amount_sats - valid.amount_sats,
                distinct_keys: classes[6].distinct_keys - valid.distinct_keys,
            };
        }
        Ok(())
    }

    pub fn class_json(&self, class: usize, stats: &Stats, check_curve: bool) -> String {
        let mut json = stats_json(stats);
        json.pop();
        if class == 2 {
            for (name, value) in ["exposed_sh20_only", "exposed_pk20_only", "exposed_both"].iter().zip(self.p2sh) {
                json.push_str(&format!(",\"{name}\":{}", value.json()));
            }
        } else if class < 4 {
            json.push_str(&format!(",\"exposed_in_cross_format_diff\":{}", self.cross_format[class].json()));
        }
        if (4..7).contains(&class) {
            json.push_str(",\"curve_validation\":");
            if check_curve {
                json.push_str(&format!("{{\"valid\":{},\"invalid\":{}}}", self.curve[class - 4][0].json(), self.curve[class - 4][1].json()));
            } else { json.push_str("null"); }
        }
        json.push('}');
        json
    }

    pub fn json(&self, enabled: bool) -> String {
        let histogram = BUCKETS.iter().zip(self.histogram).map(|(name, s)|
            format!("\"{name}\":{{\"utxo_count\":{},\"amount_sats\":{}}}", s.utxo_count, s.amount_sats)).collect::<Vec<_>>().join(",");
        let top = self.top.iter().map(|r| format!("{{\"script_hex\":{},\"truncated\":{},\"script_sha256\":{},\"utxo_count\":{},\"amount_sats\":{}}}",
            json_string(&hex(&r.key[34..34 + usize::from(r.key[32])])), r.key[33] != 0,
            json_string(&hex(&r.key[..32])), r.count, r.amount)).collect::<Vec<_>>().join(",");
        format!(",\n  \"check_curve\":{enabled},\n  \"cross_format_diff_table_entries\":{{\"diff20\":{},\"diff32\":{}}},\n  \"other_histogram\":{{{histogram}}},\n  \"other_top_scripts\":[{top}]\n", self.extra_entries[1].unwrap_or(0), self.extra_entries[2].unwrap_or(0))
    }

    pub fn markdown(&self, enabled: bool) -> String {
        let mut out = String::from("\n| Exposure subset | UTXOs | Amount (sats) | Distinct keys |\n| --- | ---: | ---: | ---: |\n");
        for (name, s) in ["p2sh exposed_sh20_only", "p2sh exposed_pk20_only", "p2sh exposed_both"].iter().zip(self.p2sh) {
            out.push_str(&format!("| {name} | {} | {} | {} |\n", s.utxo_count, s.amount_sats, s.distinct_keys));
        }
        for i in [0, 1, 3] {
            let s = self.cross_format[i];
            out.push_str(&format!("| {} exposed_in_cross_format_diff | {} | {} | {} |\n", NAMES[i], s.utxo_count, s.amount_sats, s.distinct_keys));
        }
        out.push_str("\n| Other template | UTXOs | Amount (sats) |\n| --- | ---: | ---: |\n");
        for (name, s) in BUCKETS.iter().zip(self.histogram) { out.push_str(&format!("| {name} | {} | {} |\n", s.utxo_count, s.amount_sats)); }
        out.push_str("\nTop other scripts (full-script counts; hex truncated to 80 bytes):\n\n| Script hex | Truncated | SHA256 | UTXOs | Amount (sats) |\n| --- | --- | --- | ---: | ---: |\n");
        for r in &self.top {
            out.push_str(&format!("| `{}` | {} | `{}` | {} | {} |\n", hex(&r.key[34..34 + usize::from(r.key[32])]), r.key[33] != 0, hex(&r.key[..32]), r.count, r.amount));
        }
        if enabled {
            out.push_str("\n| Curve validation | Result | UTXOs | Amount (sats) | Distinct keys/scripts |\n| --- | --- | ---: | ---: | ---: |\n");
            for i in 0..3 {
                for (label, s) in ["valid", "invalid"].iter().zip(self.curve[i]) {
                    out.push_str(&format!("| {} | {label} | {} | {} | {} |\n", NAMES[i + 4], s.utxo_count, s.amount_sats, s.distinct_keys));
                }
            }
        } else { out.push_str("\nCurve validation: disabled (not measured).\n"); }
        out.push_str("\nDenominators are counted before curve validation.\n");
        out
    }
}
