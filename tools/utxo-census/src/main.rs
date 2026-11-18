use std::{env, path::PathBuf, process};
use utxo_census::{run, Config, DEFAULT_CHUNK_RECORDS};

const USAGE: &str = "utxo-census --utxo <file> --tables <dir> --out <dir> --tmp <dir> [--tool-version <str>] [--limit-coins N] [--check-curve]";

fn arguments() -> Result<Option<Config>, String> {
    let mut args = env::args_os().skip(1);
    let mut values = std::collections::BTreeMap::new();
    let mut check_curve = false;
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" { return Ok(None); }
        if flag == "--check-curve" {
            if check_curve { return Err("duplicate option --check-curve".into()); }
            check_curve = true;
            continue;
        }
        let flag = flag.into_string().map_err(|_| "invalid option encoding")?;
        if !["--utxo", "--tables", "--out", "--tmp", "--tool-version", "--limit-coins"].contains(&flag.as_str()) {
            return Err(format!("unknown option {flag}"));
        }
        let value = args.next().ok_or_else(|| format!("missing value for {flag}"))?;
        if values.insert(flag.clone(), value).is_some() { return Err(format!("duplicate option {flag}")); }
    }
    let mut path = |name: &str| values.remove(name).map(PathBuf::from).ok_or_else(|| format!("missing {name}"));
    let utxo = path("--utxo")?;
    let tables = path("--tables")?;
    let out = path("--out")?;
    let tmp = path("--tmp")?;
    let tool_version = values.remove("--tool-version").map(|s| s.into_string().map_err(|_| "invalid tool version encoding"))
        .transpose()?.unwrap_or_else(|| "unknown".to_owned());
    let limit_coins = values.remove("--limit-coins").map(|s| {
        s.to_str().ok_or("invalid limit encoding")?.parse::<u64>().map_err(|_| "invalid --limit-coins")
    }).transpose()?;
    Ok(Some(Config { utxo, tables, out, tmp, tool_version, limit_coins, chunk_records: DEFAULT_CHUNK_RECORDS, check_curve }))
}

fn main() {
    match arguments() {
        Ok(None) => println!("{USAGE}"),
        Ok(Some(config)) => if let Err(error) = run(&config) {
            eprintln!("utxo-census: {error}");
            process::exit(1);
        },
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            process::exit(2);
        }
    }
}
