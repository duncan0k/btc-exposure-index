mod codec;
mod sha256;
mod curve;
mod details;
use details::Details;

use codec::{bytes, compact_size, decompress_amount, decompress_script, invalid, varint, Script};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_CHUNK_RECORDS: usize = 8_000_000;
const MAX_CHUNK_RECORDS: usize = 24_000_000;
const MAX_CHUNK_BYTES: usize = 960_000_000;
const KEY_BYTES: usize = 114;
type Key = [u8; KEY_BYTES];
const FAN_IN: usize = 64;
const MIB: usize = 1024 * 1024;
const MAX_MONEY: u64 = 2_100_000_000_000_000;
const HEIGHT: u64 = 975019;
const BASE_HASH: &str = "0000000000000000000158c9898f947463d71d98c97f1dad1639e25114a1dae6";
const BASIS: &str = "UTXO set as of height 975019 (dumptxoutset)";
const NAMES: [&str; 8] = ["p2pkh", "p2wpkh", "p2sh", "p2wsh", "p2tr", "p2pk", "bare_multisig", "other"];
const TABLES: [&str; 3] = ["pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin"];

pub struct Config {
    pub utxo: PathBuf,
    pub tables: PathBuf,
    pub out: PathBuf,
    pub tmp: PathBuf,
    pub tool_version: String,
    pub limit_coins: Option<u64>,
    pub chunk_records: usize,
    pub check_curve: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub utxo_count: u64,
    pub amount_sats: u64,
    pub distinct_keys: u64,
    pub exposed_utxo_count: u64,
    pub exposed_amount_sats: u64,
    pub exposed_distinct_keys: u64,
}

#[derive(Debug)]
pub struct Header {
    pub version: u16,
    pub network_magic: [u8; 4],
    pub base_hash: String,
    pub coins_count: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CrossProgram {
    pub distinct_keys: u64,
    pub p2pkh_utxo_count: u64,
    pub p2wpkh_utxo_count: u64,
    pub p2pkh_amount_sats: u64,
    pub p2wpkh_amount_sats: u64,
    pub amount_sats: u64,
    pub exposed_distinct_keys: u64,
    pub exposed_utxo_count: u64,
    pub exposed_amount_sats: u64,
}

#[derive(Debug)]
pub struct Report {
    pub header: Header,
    pub classes: [Stats; 8],
    pub totals: Stats,
    pub distinct_scripts_total: u64,
    pub cross_program: CrossProgram,
    pub table_entries: [u64; 3],
    pub complete: bool,
    pub details: Details,
}

fn add(target: &mut u64, value: u64) -> io::Result<()> {
    *target = target.checked_add(value).ok_or_else(|| invalid("counter overflow"))?;
    Ok(())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn key(data: &[u8]) -> Key {
    let mut result = [0; KEY_BYTES];
    result[..data.len()].copy_from_slice(data);
    result
}

fn width(class: usize) -> usize {
    match class { 0..=2 => 20, 5 => 66, _ => 32 }
}

fn p2pk_key(pubkey: &[u8]) -> Key {
    let mut result = [0; KEY_BYTES];
    result[0] = pubkey.len() as u8;
    result[1..1 + pubkey.len()].copy_from_slice(pubkey);
    result
}

fn bare_multisig(s: &[u8]) -> bool {
    if s.len() < 3 || !(0x51..=0x53).contains(&s[0]) || s[s.len() - 1] != 0xae { return false; }
    let n = s[s.len() - 2];
    if !(0x51..=0x53).contains(&n) || s[0] > n { return false; }
    let end = s.len() - 2;
    let mut pos = 1;
    let mut count = 0;
    while pos < end {
        let length = s[pos] as usize;
        if length != 33 && length != 65 { return false; }
        pos += 1;
        if pos + length > end { return false; }
        pos += length;
        count += 1;
    }
    count == usize::from(n - 0x50)
}

fn classify(script: &Script) -> (usize, Key) {
    let s = match script {
        Script::UncompressedP2pk { marker, x } => {
            let mut result = [0; KEY_BYTES];
            result[1] = *marker;
            result[2..34].copy_from_slice(x);
            return (5, result);
        }
        Script::Oversized { hash, .. } => return (7, key(hash)),
        Script::Raw(s) => s.as_slice(),
    };
    if s.len() == 25 && s[..3] == [0x76, 0xa9, 0x14] && s[23..] == [0x88, 0xac] {
        (0, key(&s[3..23]))
    } else if s.len() == 22 && s[..2] == [0, 0x14] {
        (1, key(&s[2..]))
    } else if s.len() == 23 && s[..2] == [0xa9, 0x14] && s[22] == 0x87 {
        (2, key(&s[2..22]))
    } else if s.len() == 34 && s[..2] == [0, 0x20] {
        (3, key(&s[2..]))
    } else if s.len() == 34 && s[..2] == [0x51, 0x20] {
        (4, key(&s[2..]))
    } else if (s.len() == 35 && s[0] == 33 && s[34] == 0xac)
        || (s.len() == 67 && s[0] == 65 && s[66] == 0xac) {
        (5, p2pk_key(&s[1..s.len() - 1]))
    } else if bare_multisig(s) {
        (6, key(&sha256::digest(s)))
    } else { (7, key(&sha256::digest(s))) }
}

fn read_header(reader: &mut impl Read) -> io::Result<Header> {
    if bytes::<5>(reader)? != *b"utxo\xff" { return Err(invalid("invalid snapshot magic")); }
    let version = u16::from_le_bytes(bytes(reader)?);
    if version != 2 { return Err(invalid("snapshot version must be 2")); }
    let network_magic = bytes(reader)?;
    if network_magic != [0xf9, 0xbe, 0xb4, 0xd9] { return Err(invalid("snapshot must be mainnet")); }
    let mut hash = bytes::<32>(reader)?;
    hash.reverse();
    let base_hash = hex(&hash);
    if base_hash != BASE_HASH { return Err(invalid("snapshot base hash does not match height 975019")); }
    Ok(Header { version, network_magic, base_hash, coins_count: u64::from_le_bytes(bytes(reader)?) })
}

fn parse(config: &Config, work: &Path, start: Instant, details: &mut Details) -> io::Result<(Header, [Stats; 8], bool)> {
    let mut reader = BufReader::with_capacity(MIB, File::open(&config.utxo)?);
    let header = read_header(&mut reader)?;
    let target = config.limit_coins.unwrap_or(header.coins_count).min(header.coins_count);
    let mut spills = Vec::new();
    for name in &NAMES {
        spills.push(BufWriter::with_capacity(MIB, File::create(work.join(format!("{name}.spill")))?));
    }
    let mut other = BufWriter::with_capacity(MIB, File::create(work.join("other_raw.spill"))?);
    let mut valid_multisig = BufWriter::with_capacity(MIB, File::create(work.join("valid_multisig.spill"))?);
    let mut classes = [Stats::default(); 8];
    let mut parsed = 0;
    let mut total_amount = 0;
    while parsed < target {
        bytes::<32>(&mut reader)?;
        let coins = compact_size(&mut reader)?;
        if coins == 0 || coins > header.coins_count - parsed { return Err(invalid("invalid txid group count")); }
        let mut previous_vout = None;
        for _ in 0..coins {
            if parsed == target { break; }
            let vout = compact_size(&mut reader)?;
            if vout >= u64::from(u32::MAX) || previous_vout.is_some_and(|previous| previous >= vout) {
                return Err(invalid("invalid or unordered vout"));
            }
            previous_vout = Some(vout);
            let code = varint(&mut reader)?;
            if code >> 1 > HEIGHT { return Err(invalid("coin height exceeds snapshot height")); }
            let amount = decompress_amount(varint(&mut reader)?)?;
            add(&mut total_amount, amount)?;
            if total_amount > MAX_MONEY { return Err(invalid("snapshot amount exceeds maximum supply")); }
            let script = decompress_script(&mut reader)?;
            let (class, key) = classify(&script);
            if class == 7 { details.record_other(&script, amount, &mut other)?; }
            if config.check_curve && class == 6 && details::valid_multisig(&script) {
                valid_multisig.write_all(&key[..32])?;
                valid_multisig.write_all(&amount.to_le_bytes())?;
            }
            add(&mut classes[class].utxo_count, 1)?;
            add(&mut classes[class].amount_sats, amount)?;
            spills[class].write_all(&key[..width(class)])?;
            spills[class].write_all(&amount.to_le_bytes())?;
            if (4..7).contains(&class) {
                add(&mut classes[class].exposed_utxo_count, 1)?;
                add(&mut classes[class].exposed_amount_sats, amount)?;
            }
            parsed += 1;
            if parsed % 10_000_000 == 0 {
                eprintln!("parse: {parsed} coins, {:.1}s elapsed", start.elapsed().as_secs_f64());
            }
        }
    }
    let complete = parsed == header.coins_count;
    if complete && !reader.fill_buf()?.is_empty() { return Err(invalid("trailing snapshot bytes")); }
    for spill in &mut spills { spill.flush()?; }
    other.flush()?;
    valid_multisig.flush()?;
    if complete && total_amount < 1_900_000_000_000_000 {
        eprintln!("sanity warning: {total_amount} sats is below the expected approximately 19.9 million BTC");
    }
    Ok((header, classes, complete))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Record { key: Key, amount: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Aggregate { key: Key, count: u64, amount: u64 }

fn read_key(reader: &mut impl BufRead, width: usize) -> io::Result<Option<Key>> {
    if reader.fill_buf()?.is_empty() { return Ok(None); }
    let mut key = [0; KEY_BYTES];
    reader.read_exact(&mut key[..width])?;
    Ok(Some(key))
}

fn read_aggregate(reader: &mut impl BufRead, width: usize) -> io::Result<Option<Aggregate>> {
    let Some(key) = read_key(reader, width)? else { return Ok(None); };
    let count = u64::from_le_bytes(bytes(reader)?);
    let amount = u64::from_le_bytes(bytes(reader)?);
    if count == 0 { return Err(invalid("zero-count aggregate")); }
    Ok(Some(Aggregate { key, count, amount }))
}

fn write_aggregate(writer: &mut impl Write, width: usize, row: Aggregate) -> io::Result<()> {
    writer.write_all(&row.key[..width])?;
    writer.write_all(&row.count.to_le_bytes())?;
    writer.write_all(&row.amount.to_le_bytes())
}

fn accumulate(writer: &mut impl Write, width: usize, pending: &mut Option<Aggregate>, row: Aggregate) -> io::Result<()> {
    if let Some(previous) = pending {
        if previous.key == row.key {
            add(&mut previous.count, row.count)?;
            add(&mut previous.amount, row.amount)?;
            return Ok(());
        }
        write_aggregate(writer, width, *previous)?;
    }
    *pending = Some(row);
    Ok(())
}

fn merge_runs(paths: &[PathBuf], output: &Path, width: usize) -> io::Result<()> {
    let mut readers = paths.iter().map(|p| File::open(p).map(|f| BufReader::with_capacity(64 * 1024, f)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (index, reader) in readers.iter_mut().enumerate() {
        if let Some(row) = read_aggregate(reader, width)? { heap.push(Reverse((row, index))); }
    }
    let mut writer = BufWriter::with_capacity(MIB, File::create(output)?);
    let mut pending = None;
    while let Some(Reverse((row, index))) = heap.pop() {
        accumulate(&mut writer, width, &mut pending, row)?;
        if let Some(next) = read_aggregate(&mut readers[index], width)? { heap.push(Reverse((next, index))); }
    }
    if let Some(row) = pending { write_aggregate(&mut writer, width, row)?; }
    writer.flush()
}

fn aggregate(work: &Path, class: usize, chunk_records: usize) -> io::Result<PathBuf> {
    aggregate_named(work, NAMES[class], width(class), chunk_records)
}

fn aggregate_named(work: &Path, name: &str, width: usize, chunk_records: usize) -> io::Result<PathBuf> {
    let chunk_records = chunk_records.min(MAX_CHUNK_BYTES / std::mem::size_of::<Record>());
    let spill = work.join(format!("{name}.spill"));
    let mut reader = BufReader::with_capacity(MIB, File::open(&spill)?);
    let available = reader.get_ref().metadata()?.len() / (width as u64 + 8);
    let capacity = available.min(chunk_records as u64) as usize;
    let mut rows = Vec::with_capacity(capacity);
    let mut runs = Vec::new();
    loop {
        rows.clear();
        while rows.len() < chunk_records {
            let Some(key) = read_key(&mut reader, width)? else { break; };
            rows.push(Record { key, amount: u64::from_le_bytes(bytes(&mut reader)?) });
        }
        if rows.is_empty() { break; }
        rows.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let path = work.join(format!("{name}.run-{}", runs.len()));
        let mut writer = BufWriter::with_capacity(MIB, File::create(&path)?);
        let mut pending = None;
        for row in &rows {
            accumulate(&mut writer, width, &mut pending, Aggregate { key: row.key, count: 1, amount: row.amount })?;
        }
        if let Some(row) = pending { write_aggregate(&mut writer, width, row)?; }
        writer.flush()?;
        runs.push(path);
    }
    drop(rows);
    drop(reader);
    fs::remove_file(spill)?;
    let mut pass = 0;
    while runs.len() > FAN_IN {
        let mut merged = Vec::new();
        for (index, batch) in runs.chunks(FAN_IN).enumerate() {
            let path = work.join(format!("{name}.merge-{pass}-{index}"));
            merge_runs(batch, &path, width)?;
            for old in batch { fs::remove_file(old)?; }
            merged.push(path);
        }
        runs = merged;
        pass += 1;
    }
    let output = work.join(format!("{name}.agg"));
    merge_runs(&runs, &output, width)?;
    for path in runs { fs::remove_file(path)?; }
    Ok(output)
}

struct TableCursor {
    reader: BufReader<File>,
    width: usize,
    current: Option<Key>,
    previous: Option<Key>,
    entries: u64,
}

impl TableCursor {
    fn open(path: &Path, width: usize) -> io::Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() % width as u64 != 0 { return Err(invalid("table has a partial record")); }
        let mut cursor = Self { reader: BufReader::with_capacity(4 * MIB, file), width, current: None, previous: None, entries: 0 };
        cursor.advance()?;
        Ok(cursor)
    }

    fn advance(&mut self) -> io::Result<()> {
        self.current = read_key(&mut self.reader, self.width)?;
        if let Some(key) = self.current {
            if self.previous.is_some_and(|previous| previous >= key) {
                return Err(invalid("table must be strictly sorted and deduplicated"));
            }
            self.previous = Some(key);
            add(&mut self.entries, 1)?;
        }
        Ok(())
    }

    fn contains(&mut self, key: Key) -> io::Result<bool> {
        while self.current.is_some_and(|current| current < key) { self.advance()?; }
        Ok(self.current == Some(key))
    }

    fn finish(mut self) -> io::Result<u64> {
        while self.current.is_some() { self.advance()?; }
        Ok(self.entries)
    }
}

fn join(path: &Path, tables: &Path, class: usize, stats: &mut Stats, details: &mut Details) -> io::Result<u64> {
    let width = width(class);
    let index = match class { 0 | 1 => 0, 2 => 1, _ => 2 };
    let mut reader = BufReader::with_capacity(MIB, File::open(path)?);
    let mut table = TableCursor::open(&tables.join(TABLES[index]), width)?;
    let extra_name = match class {
        2 => TABLES[0], 3 => "cross_format_diff_32.bin", _ => "cross_format_diff_20.bin",
    };
    let mut extra = TableCursor::open(&tables.join(extra_name), width)?;
    let mut count = 0;
    let mut amount = 0;
    while let Some(row) = read_aggregate(&mut reader, width)? {
        add(&mut stats.distinct_keys, 1)?;
        add(&mut count, row.count)?;
        add(&mut amount, row.amount)?;
        let primary = table.contains(row.key)?;
        let secondary = extra.contains(row.key)?;
        if primary || (class == 2 && secondary) {
            add(&mut stats.exposed_distinct_keys, 1)?;
            add(&mut stats.exposed_utxo_count, row.count)?;
            add(&mut stats.exposed_amount_sats, row.amount)?;
            if class == 2 {
                let bucket = match (primary, secondary) { (true, true) => 2, (true, false) => 0, _ => 1 };
                details.p2sh[bucket].record(row.count, row.amount, 1)?;
            } else if secondary {
                details.cross_format[class].record(row.count, row.amount, 1)?;
            }
        }
    }
    if (count, amount) != (stats.utxo_count, stats.amount_sats) { return Err(invalid("aggregate does not match parse totals")); }
    let entries = extra.finish()?;
    details.observe_table(if class == 2 { 0 } else if class == 3 { 2 } else { 1 }, entries)?;
    table.finish()
}

fn cross_program(left: &Path, right: &Path, table: &Path) -> io::Result<(CrossProgram, u64)> {
    let mut left = BufReader::with_capacity(MIB, File::open(left)?);
    let mut right = BufReader::with_capacity(MIB, File::open(right)?);
    let mut table = TableCursor::open(table, 20)?;
    let mut a = read_aggregate(&mut left, 20)?;
    let mut b = read_aggregate(&mut right, 20)?;
    let mut result = CrossProgram::default();
    while let (Some(x), Some(y)) = (a, b) {
        if x.key == y.key {
            add(&mut result.distinct_keys, 1)?;
            add(&mut result.p2pkh_utxo_count, x.count)?;
            add(&mut result.p2wpkh_utxo_count, y.count)?;
            add(&mut result.p2pkh_amount_sats, x.amount)?;
            add(&mut result.p2wpkh_amount_sats, y.amount)?;
            add(&mut result.amount_sats, x.amount)?;
            add(&mut result.amount_sats, y.amount)?;
            if table.contains(x.key)? {
                add(&mut result.exposed_distinct_keys, 1)?;
                add(&mut result.exposed_utxo_count, x.count)?;
                add(&mut result.exposed_utxo_count, y.count)?;
                add(&mut result.exposed_amount_sats, x.amount)?;
                add(&mut result.exposed_amount_sats, y.amount)?;
            }
        }
        if x.key <= y.key { a = read_aggregate(&mut left, 20)?; }
        if y.key <= x.key { b = read_aggregate(&mut right, 20)?; }
    }
    Ok((result, table.finish()?))
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            c if c < ' ' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
    output
}

fn stats_json(s: &Stats) -> String {
    format!("{{\"utxo_count\":{},\"amount_sats\":{},\"distinct_keys\":{},\"exposed_utxo_count\":{},\"exposed_amount_sats\":{},\"exposed_distinct_keys\":{}}}",
        s.utxo_count, s.amount_sats, s.distinct_keys, s.exposed_utxo_count, s.exposed_amount_sats, s.exposed_distinct_keys)
}

fn write_reports(config: &Config, report: &Report) -> io::Result<()> {
    fs::create_dir_all(&config.out)?;
    let h = &report.header;
    let c = &report.cross_program;
    let mut json = format!("{{\n  \"basis\":{},\n  \"tool_version\":{},\n  \"complete\":{},\n  \"limit_coins\":{},\n  \"snapshot\":{{\"magic_hex\":\"7574786fff\",\"version\":{},\"network_magic\":{},\"base_hash\":{},\"coins_count\":{}}},\n  \"parsed_coin_count\":{},\n  \"total_amount_sats\":{},\n  \"count_matches_header\":{},\n  \"amount_near_19_9_million_btc\":{},\n  \"table_entries\":{{\"pk20\":{},\"sh20\":{},\"sh32\":{}}},\n  \"classes\":{{\n",
        json_string(BASIS), json_string(&config.tool_version), report.complete,
        config.limit_coins.map(|n| n.to_string()).unwrap_or_else(|| "null".into()),
        h.version, json_string(&hex(&h.network_magic)), json_string(&h.base_hash), h.coins_count,
        report.totals.utxo_count, report.totals.amount_sats, report.totals.utxo_count == h.coins_count,
        report.complete && (1_900_000_000_000_000..=2_100_000_000_000_000).contains(&report.totals.amount_sats),
        report.table_entries[0], report.table_entries[1], report.table_entries[2]);
    for (i, name) in NAMES.iter().enumerate() {
        json.push_str(&format!("    {}:{}{}\n", json_string(name), report.details.class_json(i, &report.classes[i], config.check_curve), if i == 7 { "" } else { "," }));
    }
    json.push_str(&format!("  }},\n  \"totals\":{},\n  \"distinct_scripts_total\":{},\n  \"distinct_keys_scope\":\"Totals sum distinct (class, key) pairs over all classes\",\n  \"cross_program\":{{\"distinct_keys\":{},\"p2pkh_utxo_count\":{},\"p2wpkh_utxo_count\":{},\"p2pkh_amount_sats\":{},\"p2wpkh_amount_sats\":{},\"amount_sats\":{},\"exposed_distinct_keys\":{},\"exposed_utxo_count\":{},\"exposed_amount_sats\":{}}}\n}}\n",
        stats_json(&report.totals), report.distinct_scripts_total, c.distinct_keys, c.p2pkh_utxo_count, c.p2wpkh_utxo_count,
        c.p2pkh_amount_sats, c.p2wpkh_amount_sats, c.amount_sats, c.exposed_distinct_keys, c.exposed_utxo_count, c.exposed_amount_sats));
    let mut markdown = format!("# UTXO census\n\n{BASIS}\n\nStatus: {}. Parsed {} of {} coins; total {} sats.\n\n| Class | UTXOs | Amount (sats) | Distinct keys | Exposed UTXOs | Exposed amount (sats) | Exposed distinct keys |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n",
        if report.complete { "complete" } else { "PARTIAL SMOKE TEST; not a full UTXO census" }, report.totals.utxo_count, h.coins_count, report.totals.amount_sats);
    for i in 0..=8 {
        let (name, s) = if i == 8 { ("total", &report.totals) } else { (NAMES[i], &report.classes[i]) };
        markdown.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} |\n", name, s.utxo_count, s.amount_sats,
            s.distinct_keys, s.exposed_utxo_count, s.exposed_amount_sats,
            s.exposed_distinct_keys));
    }
    markdown.push_str(&format!("\nDenominators are counted before curve validation.\n\ndistinct_scripts_total: {}. Distinct-key totals sum (class, key) pairs over all classes. Structural exposure does not imply curve validation.\n\nCross-program: {} shared hashes; {} P2PKH UTXOs ({} sats), {} P2WPKH UTXOs ({} sats), {} sats combined; {} shared hashes in pk20 ({} UTXOs, {} sats).\n",
        report.distinct_scripts_total, c.distinct_keys, c.p2pkh_utxo_count, c.p2pkh_amount_sats, c.p2wpkh_utxo_count, c.p2wpkh_amount_sats,
        c.amount_sats, c.exposed_distinct_keys, c.exposed_utxo_count, c.exposed_amount_sats));
    let end = json.rfind('}').expect("report object");
    json.insert_str(end, &report.details.json(config.check_curve));
    markdown.push_str(&report.details.markdown(config.check_curve));
    fs::write(config.out.join("stats.json"), json)?;
    fs::write(config.out.join("summary.md"), markdown)
}

pub fn run(config: &Config) -> io::Result<Report> {
    if config.chunk_records == 0 || config.chunk_records > MAX_CHUNK_RECORDS {
        return Err(invalid("chunk_records must be in 1..=24000000"));
    }
    fs::create_dir_all(&config.tmp)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos();
    let work = config.tmp.join(format!("utxo-census-{}-{stamp}", std::process::id()));
    fs::create_dir(&work)?;
    eprintln!("temporary workspace: {}", work.display());
    let start = Instant::now();
    eprintln!("phase 1: parse, {:.1}s elapsed", start.elapsed().as_secs_f64());
    let mut details = Details::default();
    let (header, mut classes, complete) = parse(config, &work, start, &mut details)?;
    eprintln!("phase 2: aggregate, {:.1}s elapsed", start.elapsed().as_secs_f64());
    let mut aggregates = Vec::new();
    for class in 0..8 { aggregates.push(aggregate(&work, class, config.chunk_records)?); }
    eprintln!("phase 3: join, {:.1}s elapsed", start.elapsed().as_secs_f64());
    let mut table_entries = [0; 3];
    for class in 0..4 {
        let table = match class { 0 | 1 => 0, 2 => 1, _ => 2 };
        let entries = join(&aggregates[class], &config.tables, class, &mut classes[class], &mut details)?;
        if class == 1 && entries != table_entries[0] { return Err(invalid("pk20 changed between scans")); }
        table_entries[table] = entries;
    }
    for class in 4..8 {
        let mut reader = BufReader::with_capacity(MIB, File::open(&aggregates[class])?);
        let mut count = 0;
        let mut amount = 0;
        while let Some(row) = read_aggregate(&mut reader, width(class))? {
            add(&mut classes[class].distinct_keys, 1)?;
            if config.check_curve && (class == 4 || class == 5) {
                let valid = if class == 4 { curve::lift_x(&row.key[..32]) }
                    else if row.key[0] == 0 { true }
                    else { curve::pubkey(&row.key[1..1 + usize::from(row.key[0])]) };
                details.curve[class - 4][usize::from(!valid)].record(row.count, row.amount, 1)?;
            }
            add(&mut count, row.count)?;
            add(&mut amount, row.amount)?;
        }
        if (count, amount) != (classes[class].utxo_count, classes[class].amount_sats) {
            return Err(invalid("aggregate does not match parse totals"));
        }
        if class < 7 { classes[class].exposed_distinct_keys = classes[class].distinct_keys; }
    }
    details.finish(&work, config, &classes)?;
    if details.extra_entries[0] != Some(table_entries[0]) { return Err(invalid("pk20 changed between scans")); }
    eprintln!("phase 4: cross-program, {:.1}s elapsed", start.elapsed().as_secs_f64());
    let (cross_program, entries) = cross_program(&aggregates[0], &aggregates[1], &config.tables.join(TABLES[0]))?;
    if entries != table_entries[0] { return Err(invalid("pk20 changed between scans")); }
    let mut totals = Stats::default();
    for s in &classes {
        add(&mut totals.utxo_count, s.utxo_count)?;
        add(&mut totals.amount_sats, s.amount_sats)?;
        add(&mut totals.distinct_keys, s.distinct_keys)?;
        add(&mut totals.exposed_utxo_count, s.exposed_utxo_count)?;
        add(&mut totals.exposed_amount_sats, s.exposed_amount_sats)?;
        add(&mut totals.exposed_distinct_keys, s.exposed_distinct_keys)?;
    }
    let report = Report { header, classes, totals, distinct_scripts_total: totals.distinct_keys, cross_program, table_entries, complete, details };
    write_reports(config, &report)?;
    eprintln!("done: {} coins, {} sats, {:.1}s elapsed; aggregates retained in {}", report.totals.utxo_count, report.totals.amount_sats, start.elapsed().as_secs_f64(), work.display());
    Ok(report)
}

#[cfg(test)]
mod tests;
