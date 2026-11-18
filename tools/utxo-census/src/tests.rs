use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut result = vec![(n & 127) as u8];
    while n > 127 {
        n = (n >> 7) - 1;
        result.push((n & 127) as u8 | 128);
    }
    result.reverse();
    result
}

fn encode_compact(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 253 { out.push(n as u8); }
    else if n <= u16::MAX.into() { out.push(253); out.extend_from_slice(&(n as u16).to_le_bytes()); }
    else if n <= u32::MAX.into() { out.push(254); out.extend_from_slice(&(n as u32).to_le_bytes()); }
    else { out.push(255); out.extend_from_slice(&n.to_le_bytes()); }
    out
}

fn compress_amount(mut n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut e = 0;
    while n % 10 == 0 && e < 9 { n /= 10; e += 1; }
    if e < 9 {
        let d = n % 10;
        1 + ((n / 10) * 9 + d - 1) * 10 + e
    } else { 1 + (n - 1) * 10 + 9 }
}

#[test]
fn varint_vectors() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0]), (1, &[1]), (127, &[0x7f]), (128, &[0x80, 0]),
        (255, &[0x80, 0x7f]), (256, &[0x81, 0]), (16383, &[0xfe, 0x7f]),
        (16384, &[0xff, 0]), (16511, &[0xff, 0x7f]), (16512, &[0x80, 0x80, 0]),
        (u64::MAX, &[0x80, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0x7f]),
    ];
    for &(n, encoded) in cases {
        assert_eq!(varint(&mut &encoded[..]).unwrap(), n);
        assert_eq!(encode_varint(n), encoded);
    }
    assert!(varint(&mut &[][..]).is_err());
    assert!(varint(&mut &[0x80][..]).is_err());
    assert!(varint(&mut &[0xff; 11][..]).is_err());
}

#[test]
fn compact_size_vectors() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0]), (252, &[252]), (253, &[253, 253, 0]),
        (65535, &[253, 255, 255]), (65536, &[254, 0, 0, 1, 0]),
        (4294967295, &[254, 255, 255, 255, 255]),
        (4294967296, &[255, 0, 0, 0, 0, 1, 0, 0, 0]),
        (u64::MAX, &[255; 9]),
    ];
    for &(n, encoded) in cases {
        assert_eq!(compact_size(&mut &encoded[..]).unwrap(), n);
        assert_eq!(encode_compact(n), encoded);
    }
    for encoded in [&[253, 252, 0][..], &[254, 255, 255, 0, 0], &[255, 1, 0, 0, 0, 0, 0, 0, 0], &[253, 1]] {
        assert!(compact_size(&mut &encoded[..]).is_err());
    }
}

#[test]
fn amount_vectors_and_core_roundtrips() {
    for (compressed, amount) in [(0, 0), (1, 1), (2, 10), (3, 100), (9, 100_000_000),
        (10, 1_000_000_000), (11, 2), (21, 3), (1_111_111_101, 123_456_789), (21_000_000, MAX_MONEY)] {
        assert_eq!(decompress_amount(compressed).unwrap(), amount);
        assert_eq!(compress_amount(amount), compressed);
    }
    for amount in [1, 2, 3, 10, 123456789, 100000000, 2100000000000000] {
        assert_eq!(decompress_amount(compress_amount(amount)).unwrap(), amount);
    }
    assert!(decompress_amount(u64::MAX - 6).is_err());
}

fn raw_script(class: usize, byte: u8) -> Vec<u8> {
    match class {
        0 => [vec![0x76, 0xa9, 20], vec![byte; 20], vec![0x88, 0xac]].concat(),
        1 => [vec![0, 20], vec![byte; 20]].concat(),
        2 => [vec![0xa9, 20], vec![byte; 20], vec![0x87]].concat(),
        3 => [vec![0, 32], vec![byte; 32]].concat(),
        4 => [vec![0x51, 32], vec![byte; 32]].concat(),
        5 => [vec![33, 2], vec![byte; 32], vec![0xac]].concat(),
        6 => [vec![0x51, 33, 2], vec![byte; 32], vec![0x51, 0xae]].concat(),
        _ => vec![0x6a, byte],
    }
}

#[test]
fn script_decompression_all_tags() {
    for tag in 0..=5 {
        let length = if tag < 2 { 20 } else { 32 };
        let mut encoded = vec![tag];
        encoded.extend(vec![42; length]);
        let script = decompress_script(&mut &encoded[..]).unwrap();
        match tag {
            0 => assert_eq!(script, Script::Raw(raw_script(0, 42))),
            1 => assert_eq!(script, Script::Raw(raw_script(2, 42))),
            2 | 3 => {
                let mut expected = raw_script(5, 42);
                expected[1] = tag;
                assert_eq!(script, Script::Raw(expected));
            }
            _ => assert_eq!(script, Script::UncompressedP2pk { marker: tag, x: [42; 32] }),
        }
        encoded.pop();
        assert!(decompress_script(&mut &encoded[..]).is_err());
    }
    for script in [vec![], raw_script(1, 12), raw_script(3, 45)] {
        let encoded = [encode_varint(script.len() as u64 + 6), script.clone()].concat();
        assert_eq!(decompress_script(&mut &encoded[..]).unwrap(), Script::Raw(script));
    }
    let oversized = [encode_varint(10007), vec![0; 10001]].concat();
    assert_eq!(decompress_script(&mut &oversized[..]).unwrap(), Script::Oversized { hash: sha256::digest(&vec![0; 10001]), prefix: [0; 80] });
    assert!(decompress_script(&mut &oversized[..oversized.len() - 1]).is_err());
}

#[test]
fn every_class_and_multisig_boundaries() {
    for class in 0..8 {
        let (actual, hash) = classify(&Script::Raw(raw_script(class, 42)));
        assert_eq!(actual, class);
        let script = raw_script(class, 42);
        let expected = match class {
            0..=4 => key(&vec![42; width(class)]),
            5 => p2pk_key(&script[1..34]),
            _ => key(&sha256::digest(&script)),
        };
        assert_eq!(hash, expected);
    }
    assert_eq!(classify(&Script::UncompressedP2pk { marker: 4, x: [0; 32] }).0, 5);
    let uncompressed = [vec![65, 4], vec![0; 64], vec![0xac]].concat();
    assert_eq!(classify(&Script::Raw(uncompressed)).0, 5);
    for n in 1..=3u8 {
        for m in 1..=n {
            let mut script = vec![0x50 + m];
            for _ in 0..n { script.extend([vec![65, 4], vec![0; 64]].concat()); }
            script.extend([0x50 + n, 0xae]);
            assert_eq!(classify(&Script::Raw(script)).0, 6);
        }
    }
    let mut bad_count = raw_script(6, 1);
    let n_pos = bad_count.len() - 2;
    bad_count[n_pos] = 0x52;
    let mut bad_threshold = raw_script(6, 1);
    bad_threshold[0] = 0x52;
    for script in [vec![], vec![0x6a, 1, 1], [vec![0x52, 32], vec![1; 32]].concat(),
        bad_count, bad_threshold, vec![0x51, 33, 2, 0x51, 0xae]] {
        assert_eq!(classify(&Script::Raw(script)).0, 7);
    }
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("utxo-census-test-{}-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), SERIAL.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).expect("remove test workspace"); }
}

fn header(count: u64) -> Vec<u8> {
    let mut result = b"utxo\xff".to_vec();
    result.extend(2u16.to_le_bytes());
    result.extend([0xf9, 0xbe, 0xb4, 0xd9]);
    let mut hash = (0..32).map(|i| u8::from_str_radix(&BASE_HASH[i * 2..i * 2 + 2], 16).unwrap()).collect::<Vec<_>>();
    hash.reverse();
    result.extend(hash);
    result.extend(count.to_le_bytes());
    result
}

fn fixture(root: &Path) -> Config {
    let config = Config {
        utxo: root.join("snapshot.dat"), tables: root.join("tables"), out: root.join("out"), tmp: root.join("tmp"),
        tool_version: "test\"\\\n\t\u{3bb}".into(), limit_coins: None, chunk_records: 3, check_curve: false,
    };
    fs::create_dir(&config.tables).unwrap();
    fs::write(config.tables.join(TABLES[0]), [vec![1; 20], vec![4; 20], vec![9; 20]].concat()).unwrap();
    fs::write(config.tables.join(TABLES[1]), [vec![5; 20], vec![9; 20]].concat()).unwrap();
    fs::write(config.tables.join(TABLES[2]), [vec![8; 32], vec![9; 32]].concat()).unwrap();
    fs::write(config.tables.join("cross_format_diff_20.bin"), [vec![1; 20], vec![3; 20]].concat()).unwrap();
    fs::write(config.tables.join("cross_format_diff_32.bin"), [vec![7; 32], vec![8; 32]].concat()).unwrap();
    let mut coins = vec![(0, 1, 20), (0, 3, 10), (0, 2, 40), (0, 1, 30), (1, 1, 50),
        (1, 1, 60), (1, 4, 70), (2, 5, 80), (2, 6, 90), (3, 7, 100),
        (3, 8, 110), (4, 2, 120), (5, 3, 130), (6, 4, 140), (7, 5, 150)];
    for (class, byte) in [(4, 2), (5, 3), (6, 4), (7, 5)] {
        coins.extend([(class, byte, 1), (class, byte, 1), (class, byte, 1), (class, byte + 1, 1)]);
    }
    coins.extend([(2, 1, 11), (2, 9, 12), (7, 0, 13)]);
    let mut snapshot = header(coins.len() as u64);
    for (txid, group) in coins.chunks(7).enumerate() {
        snapshot.extend([txid as u8; 32]);
        snapshot.extend(encode_compact(group.len() as u64));
        for (vout, &(class, byte, amount)) in group.iter().enumerate() {
            snapshot.extend(encode_compact(vout as u64));
            snapshot.extend(encode_varint((HEIGHT << 1) | (txid as u64 & 1)));
            snapshot.extend(encode_varint(compress_amount(amount)));
            if class == 0 || class == 2 {
                snapshot.push(if class == 0 { 0 } else { 1 });
                snapshot.extend([byte; 20]);
            } else if class == 5 {
                snapshot.push(if byte == 3 { 4 } else { 5 });
                snapshot.extend([3; 32]);
            } else {
                let script = if class == 7 && byte == 0 { vec![0x76, 0xa9, 0, 0x88, 0xac] } else { raw_script(class, byte) };
                snapshot.extend(encode_varint(script.len() as u64 + 6));
                snapshot.extend(script);
            }
        }
    }
    fs::write(&config.utxo, snapshot).unwrap();
    config
}

fn stats(count: u64, amount: u64, distinct: u64, exposed_count: u64, exposed_amount: u64, exposed_distinct: u64) -> Stats {
    Stats { utxo_count: count, amount_sats: amount, distinct_keys: distinct,
        exposed_utxo_count: exposed_count, exposed_amount_sats: exposed_amount, exposed_distinct_keys: exposed_distinct }
}

#[test]
fn end_to_end_all_numbers_and_reports() {
    let temp = Temp::new();
    let config = fixture(&temp.0);
    let report = run(&config).unwrap();
    assert_eq!(report.header.version, 2);
    assert_eq!(report.header.network_magic, [0xf9, 0xbe, 0xb4, 0xd9]);
    assert_eq!(report.header.base_hash, BASE_HASH);
    assert_eq!(report.header.coins_count, 34);
    assert!(report.complete);
    assert_eq!(report.table_entries, [3, 2, 2]);
    assert_eq!(report.classes, [stats(4, 100, 3, 2, 50, 1), stats(3, 180, 2, 3, 180, 2),
        stats(4, 193, 4, 3, 103, 3), stats(2, 210, 2, 1, 110, 1),
        stats(5, 124, 2, 5, 124, 2), stats(5, 134, 2, 5, 134, 2),
        stats(5, 144, 2, 5, 144, 2), stats(6, 167, 3, 0, 0, 0)]);
    assert_eq!(report.totals, stats(34, 1252, 20, 24, 845, 13));
    assert_eq!(report.distinct_scripts_total, 20);
    use details::Tally;
    assert_eq!(report.details.p2sh, [
        Tally { utxo_count: 1, amount_sats: 80, distinct_keys: 1 },
        Tally { utxo_count: 1, amount_sats: 11, distinct_keys: 1 },
        Tally { utxo_count: 1, amount_sats: 12, distinct_keys: 1 },
    ]);
    for (class, count, amount) in [(0, 2, 50), (1, 2, 110), (3, 1, 110)] {
        assert_eq!(report.details.cross_format[class], Tally { utxo_count: count, amount_sats: amount, distinct_keys: 1 });
    }
    assert_eq!(report.details.histogram[3], Tally { utxo_count: 1, amount_sats: 13, distinct_keys: 0 });
    assert_eq!(report.details.histogram[8], Tally { utxo_count: 5, amount_sats: 154, distinct_keys: 0 });
    assert_eq!(report.details.extra_entries, [Some(3), Some(2), Some(2)]);
    assert_eq!(report.details.top.len(), 3);
    assert_eq!((report.details.top[0].count, report.details.top[0].amount), (4, 153));
    assert_eq!(report.details.curve, [[Tally::default(); 2]; 3]);
    assert_eq!(report.cross_program, CrossProgram { distinct_keys: 1, p2pkh_utxo_count: 2,
        p2wpkh_utxo_count: 2, p2pkh_amount_sats: 50, p2wpkh_amount_sats: 110,
        amount_sats: 160, exposed_distinct_keys: 1, exposed_utxo_count: 4, exposed_amount_sats: 160 });
    let json = fs::read_to_string(config.out.join("stats.json")).unwrap();
    assert!(json.contains(&format!("\"tool_version\":{}", json_string(&config.tool_version))));
    assert!(json.contains(&format!("\"basis\":{}", json_string(BASIS))));
    assert!(json.contains("\"parsed_coin_count\":34"));
    assert!(json.contains("\"total_amount_sats\":1252"));
    assert!(json.contains("\"count_matches_header\":true"));
    assert!(json.contains("\"amount_near_19_9_million_btc\":false"));
    assert!(json.contains("\"table_entries\":{\"pk20\":3,\"sh20\":2,\"sh32\":2}"));
    assert!(json.contains(&format!("\"totals\":{}", stats_json(&report.totals))));
    assert!(json.contains("\"cross_program\":{\"distinct_keys\":1,\"p2pkh_utxo_count\":2,\"p2wpkh_utxo_count\":2,\"p2pkh_amount_sats\":50,\"p2wpkh_amount_sats\":110,\"amount_sats\":160,\"exposed_distinct_keys\":1,\"exposed_utxo_count\":4,\"exposed_amount_sats\":160}"));
    for (i, name) in NAMES.iter().enumerate() {
        assert!(json.contains(&format!("\"{name}\":{}", report.details.class_json(i, &report.classes[i], false))));
    }
    assert!(json.contains("\"distinct_scripts_total\":20"));
    assert!(json.contains("\"check_curve\":false"));
    assert!(json.contains("\"curve_validation\":null"));
    assert!(json.contains("\"cross_format_diff_table_entries\":{\"diff20\":2,\"diff32\":2}"));
    assert!(json.contains("\"mt_gox_malformed\":{\"utxo_count\":1,\"amount_sats\":13}"));
    assert!(json.contains("\"script_hex\":\"76a90088ac\""));
    let markdown = fs::read_to_string(config.out.join("summary.md")).unwrap();
    assert!(markdown.contains("| total | 34 | 1252 | 20 | 24 | 845 | 13 |"));
    assert!(markdown.contains("distinct_scripts_total: 20."));
    assert!(markdown.contains("| p2sh exposed_pk20_only | 1 | 11 | 1 |"));
    assert!(markdown.contains("| p2sh exposed_both | 1 | 12 | 1 |"));
    assert!(markdown.contains("| p2wpkh exposed_in_cross_format_diff | 2 | 110 | 1 |"));
    assert!(markdown.contains("| mt_gox_malformed | 1 | 13 |"));
    for (name, s) in NAMES.iter().zip(report.classes) {
        assert!(markdown.contains(&format!("| {name} | {} | {} | {} | {} | {} | {} |",
            s.utxo_count, s.amount_sats, s.distinct_keys, s.exposed_utxo_count,
            s.exposed_amount_sats, s.exposed_distinct_keys)));
    }
    assert!(markdown.contains("Denominators are counted before curve validation."));
    assert!(!markdown.contains("ever-funded"));
    assert_eq!(json_string("\"\\\n\r\t\0\u{3bb}"), "\"\\\"\\\\\\u000a\\u000d\\u0009\\u0000\u{3bb}\"");
}

#[test]
fn smoke_limit_mid_group_and_empty_inputs() {
    let temp = Temp::new();
    let mut config = fixture(&temp.0);
    config.limit_coins = Some(4);
    let report = run(&config).unwrap();
    assert!(!report.complete);
    assert_eq!(report.totals, stats(4, 100, 3, 2, 50, 1));
    assert_eq!(report.cross_program, CrossProgram::default());
    assert!(fs::read_to_string(config.out.join("summary.md")).unwrap().contains("PARTIAL SMOKE TEST"));
    config.limit_coins = Some(0);
    assert_eq!(run(&config).unwrap().totals, Stats::default());
    config.limit_coins = None;
    fs::write(&config.utxo, header(0)).unwrap();
    for table in TABLES { fs::write(config.tables.join(table), []).unwrap(); }
    let report = run(&config).unwrap();
    assert!(report.complete);
    assert_eq!(report.totals, Stats::default());
    assert_eq!(report.table_entries, [0; 3]);
}

#[test]
fn reject_invalid_tables_including_unmatched_tail() {
    for data in [vec![1; 21], [vec![1; 20], vec![9; 20], vec![8; 20]].concat(),
        [vec![1; 20], vec![9; 20], vec![9; 20]].concat()] {
        let temp = Temp::new();
        let config = fixture(&temp.0);
        fs::write(config.tables.join(TABLES[0]), data).unwrap();
        assert!(run(&config).is_err());
        assert!(!config.out.join("stats.json").exists());
    }
}

#[test]
fn snapshot_header_truncation_and_trailing_data() {
    for offset in [0, 5, 7, 11] {
        let mut data = header(0);
        data[offset] ^= 1;
        assert!(read_header(&mut &data[..]).is_err());
    }
    let temp = Temp::new();
    let config = fixture(&temp.0);
    let original = fs::read(&config.utxo).unwrap();
    for data in [original[..original.len() - 1].to_vec(), [original, vec![0]].concat()] {
        fs::write(&config.utxo, data).unwrap();
        assert!(run(&config).is_err());
    }
    let mut bad_group = header(1);
    bad_group.extend([0; 32]);
    bad_group.push(0);
    fs::write(&config.utxo, bad_group).unwrap();
    assert!(run(&config).is_err());
}

#[test]
fn bounded_fan_in_and_partial_spills() {
    let temp = Temp::new();
    let spill = temp.0.join("p2pkh.spill");
    let mut data = Vec::new();
    for i in (0..195u8).rev() {
        data.extend([i; 20]);
        data.extend(u64::from(i).to_le_bytes());
    }
    fs::write(&spill, data).unwrap();
    let output = aggregate(&temp.0, 0, 3).unwrap();
    let mut reader = BufReader::new(File::open(output).unwrap());
    for i in 0..195u8 {
        assert_eq!(read_aggregate(&mut reader, 20).unwrap(), Some(Aggregate {
            key: key(&[i; 20]), count: 1, amount: u64::from(i),
        }));
    }
    assert!(read_aggregate(&mut reader, 20).unwrap().is_none());
    fs::write(&spill, [0; 27]).unwrap();
    assert!(aggregate(&temp.0, 0, 3).is_err());
}

#[test]
fn cross_program_unexposed_intersection() {
    let temp = Temp::new();
    let config = fixture(&temp.0);
    fs::write(config.tables.join(TABLES[0]), vec![4; 20]).unwrap();
    let report = run(&config).unwrap();
    assert_eq!(report.cross_program.distinct_keys, 1);
    assert_eq!(report.cross_program.amount_sats, 160);
    assert_eq!(report.cross_program.exposed_distinct_keys, 0);
    assert_eq!(report.cross_program.exposed_utxo_count, 0);
    assert_eq!(report.cross_program.exposed_amount_sats, 0);
}

#[test]
fn p2pk_keys_preserve_bytes_lengths_and_parity() {
    let mut encoded_keys = Vec::new();
    for tag in 2..=5 {
        let encoded = [vec![tag], vec![42; 32]].concat();
        encoded_keys.push(classify(&decompress_script(&mut &encoded[..]).unwrap()).1);
    }
    let compressed = raw_script(5, 42);
    assert_eq!(classify(&Script::Raw(compressed)).1, encoded_keys[0]);
    let mut uncompressed = [vec![65, 4], vec![42; 32], vec![0; 32], vec![0xac]].concat();
    encoded_keys.push(classify(&Script::Raw(uncompressed.clone())).1);
    uncompressed[65] = 1;
    encoded_keys.push(classify(&Script::Raw(uncompressed.clone())).1);
    assert_eq!(encoded_keys[4], p2pk_key(&[vec![4], vec![42; 32], vec![0; 32]].concat()));
    for i in 0..encoded_keys.len() {
        for j in i + 1..encoded_keys.len() { assert_ne!(encoded_keys[i], encoded_keys[j]); }
    }
    let temp = Temp::new();
    let mut spill = Vec::new();
    for key in encoded_keys.iter().chain(encoded_keys.iter()).rev() {
        spill.extend_from_slice(&key[..width(5)]);
        spill.extend_from_slice(&1u64.to_le_bytes());
    }
    fs::write(temp.0.join("p2pk.spill"), spill).unwrap();
    let output = aggregate(&temp.0, 5, 3).unwrap();
    let mut reader = BufReader::new(File::open(output).unwrap());
    encoded_keys.sort_unstable();
    for key in encoded_keys {
        assert_eq!(read_aggregate(&mut reader, width(5)).unwrap(), Some(Aggregate { key, count: 2, amount: 2 }));
    }
    assert!(read_aggregate(&mut reader, width(5)).unwrap().is_none());
}

#[test]
fn sha256_vectors_and_stream_boundaries() {
    assert_eq!(hex(&sha256::digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    for (length, expected) in [
        (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
        (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
        (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
        (65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"),
        (10001, "0cab99a058600ffaad1292d0c53c0548ebaf88dd1d01030345705f018a813909"),
    ] {
        let data = vec![0x61; length];
        assert_eq!(hex(&sha256::digest(&data)), expected);
        let mut input = [data.clone(), vec![0xff]].concat();
        let mut reader = &input[..];
        assert_eq!(hex(&sha256::digest_reader(&mut reader, length as u64).unwrap()), expected);
        assert_eq!(reader, &[0xff]);
        input.truncate(length - 1);
        assert!(sha256::digest_reader(&mut &input[..], length as u64).is_err());
        if length > 10_000 {
            let encoded = [encode_varint(length as u64 + 6), data.clone()].concat();
            let decoded = decompress_script(&mut &encoded[..]).unwrap();
            assert_eq!(classify(&decoded), (7, key(&sha256::digest(&data))));
            let mut different = data;
            different[length - 1] ^= 1;
            assert_ne!(classify(&decoded).1, key(&sha256::digest(&different)));
        }
    }
}


#[test]
fn other_templates_and_nonminimal_pushes() {
    let p2a = [0x51, 2, 0x4e, 0x73];
    assert_eq!(details::bucket(&p2a), 1);
    assert_eq!(details::bucket(&[0, 2, 1, 2]), 0);
    for version in 0x52..=0x60 { assert_eq!(details::bucket(&[version, 2, 1, 2]), 2); }
    assert_eq!(details::bucket(&[0x76, 0xa9, 0, 0x88, 0xac]), 3);
    for opcode in [76, 77, 78] {
        let length = match opcode { 76 => vec![33], 77 => vec![33, 0], _ => vec![33, 0, 0, 0] };
        let push = [vec![opcode], length, vec![2; 33]].concat();
        let p2pk = [push.clone(), vec![0xac]].concat();
        assert_eq!(classify(&Script::Raw(p2pk.clone())).0, 7);
        assert_eq!(details::bucket(&p2pk), 5);
        let multi = [vec![0x51], push, vec![0x51, 0xae]].concat();
        assert_eq!(classify(&Script::Raw(multi.clone())).0, 7);
        assert_eq!(details::bucket(&multi), 4);
    }
    let multi = [vec![0x54], [vec![33], vec![2; 33]].concat().repeat(4), vec![0x54, 0xae]].concat();
    assert_eq!(details::bucket(&multi), 4);
    assert_eq!(details::bucket(&[0x51]), 6);
    assert_eq!(details::bucket(&[]), 6);
    for (op, length) in [(0xa8, 32), (0xa9, 20)] {
        assert_eq!(details::bucket(&[vec![op, length], vec![1; usize::from(length)], vec![0x87]].concat()), 7);
    }
    for script in [vec![0x6a], vec![0x51, 2, 1], vec![76, 255, 1], vec![0xa8, 0x87]] {
        assert_eq!(details::bucket(&script), 8);
    }
}

#[test]
fn exact_top_twenty_and_oversized_prefixes() {
    let temp = Temp::new();
    let config = fixture(&temp.0);
    let mut details = details::Details::default();
    let mut spill = Vec::new();
    for i in 0..25u8 {
        // Identical displayed prefixes must not combine different full scripts.
        let mut script = vec![0x6a; 10001];
        script[10000] = i;
        let encoded = [encode_varint(10007), script].concat();
        let decoded = decompress_script(&mut &encoded[..]).unwrap();
        for _ in 0..=i { details.record_other(&decoded, 2, &mut spill).unwrap(); }
    }
    fs::write(temp.0.join("other_raw.spill"), spill).unwrap();
    details.finish(&temp.0, &config, &[Stats::default(); 8]).unwrap();
    assert_eq!(details.top.len(), 20);
    assert_eq!(details.histogram[8].utxo_count, 325);
    for (index, row) in details.top.iter().enumerate() {
        assert_eq!(row.count, 25 - index as u64);
        assert_eq!(row.amount, 2 * row.count);
        assert_eq!(&row.key[32..34], &[80, 1]);
        assert_eq!(&row.key[34..], &[0x6a; 80]);
    }
}

#[test]
fn curve_enabled_preserves_denominators_and_partitions() {
    let temp = Temp::new();
    let mut config = fixture(&temp.0);
    let baseline = run(&config).unwrap();
    config.check_curve = true;
    let checked = run(&config).unwrap();
    assert_eq!(baseline.classes, checked.classes);
    assert_eq!(baseline.totals, checked.totals);
    for i in 0..3 {
        let [valid, invalid] = checked.details.curve[i];
        let s = checked.classes[i + 4];
        assert_eq!(valid.utxo_count + invalid.utxo_count, s.utxo_count);
        assert_eq!(valid.amount_sats + invalid.amount_sats, s.amount_sats);
        assert_eq!(valid.distinct_keys + invalid.distinct_keys, s.distinct_keys);
    }
    assert_eq!(checked.details.curve[0], [
        details::Tally { utxo_count: 4, amount_sats: 123, distinct_keys: 1 },
        details::Tally { utxo_count: 1, amount_sats: 1, distinct_keys: 1 },
    ]);
    assert_eq!(checked.details.curve[2], [details::Tally::default(),
        details::Tally { utxo_count: 5, amount_sats: 144, distinct_keys: 2 }]);
    assert_eq!(checked.details.curve[1][0].utxo_count, 5); // Snapshot tags 4/5.
    assert_eq!(checked.details.curve[1][1].utxo_count, 0);
    let json = fs::read_to_string(config.out.join("stats.json")).unwrap();
    assert!(json.contains("\"check_curve\":true"));
    assert!(json.contains("\"curve_validation\":{\"valid\":"));
}

#[test]
fn multisig_curve_threshold() {
    let x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let x = (0..64).step_by(2).map(|i| u8::from_str_radix(&x[i..i + 2], 16).unwrap()).collect::<Vec<_>>();
    let mut script = [vec![0x51, 33, 2], x, vec![33, 2], vec![0; 32], vec![0x52, 0xae]].concat();
    assert!(bare_multisig(&script));
    assert!(details::valid_multisig(&Script::Raw(script.clone())));
    script[0] = 0x52;
    assert!(!details::valid_multisig(&Script::Raw(script)));
}

#[test]
fn reject_diff_tables_and_p2sh_secondary_tail() {
    for table in ["cross_format_diff_20.bin", "cross_format_diff_32.bin"] {
        for malformed in [false, true] {
            let temp = Temp::new();
            let config = fixture(&temp.0);
            let width = if table.contains("20") { 20 } else { 32 };
            let data = if malformed { vec![0; width + 1] } else { [vec![1; width], vec![255; width], vec![254; width]].concat() };
            fs::write(config.tables.join(table), data).unwrap();
            assert!(run(&config).is_err());
        }
    }
    let temp = Temp::new();
    let config = fixture(&temp.0);
    let agg = temp.0.join("p2sh.agg");
    fs::write(&agg, []).unwrap();
    fs::write(config.tables.join(TABLES[0]), [vec![255; 20], vec![254; 20]].concat()).unwrap();
    assert!(join(&agg, &config.tables, 2, &mut Stats::default(), &mut details::Details::default()).is_err());
}


#[test]
fn p2sh_union_counts_aggregates_once() {
    let temp = Temp::new();
    let config = fixture(&temp.0);
    let path = temp.0.join("p2sh.agg");
    let mut data = Vec::new();
    for byte in [1, 5, 6, 9] {
        write_aggregate(&mut data, 20, Aggregate { key: key(&[byte; 20]), count: 3, amount: 42 }).unwrap();
    }
    fs::write(&path, data).unwrap();
    let mut stats = Stats { utxo_count: 12, amount_sats: 168, ..Stats::default() };
    let mut details = details::Details::default();
    assert_eq!(join(&path, &config.tables, 2, &mut stats, &mut details).unwrap(), 2);
    assert_eq!(stats.exposed_utxo_count, 9);
    assert_eq!(stats.exposed_amount_sats, 126);
    assert_eq!(stats.exposed_distinct_keys, 3);
    assert_eq!(details.p2sh, [details::Tally { utxo_count: 3, amount_sats: 42, distinct_keys: 1 }; 3]);
}
