#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "Usage: $0 <old-binary> <new-binary> <bitcoin-bin-dir> <work-dir> <old-stage1-binary>" >&2
    exit 1
fi
old=$1
new=$2
bitcoin=$3
work=$4
old_stage1=$5
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p -- "$work"
# Use absolute paths to keep bitcoind's datadir and all temporary files in the working directory.
work=$(cd -- "$work" && pwd)
for name in node-b node-c scan-b scan-c old-c new-c new-b old-stage1-c bad-list depth-list.txt; do
    if [[ -e "$work/$name" ]]; then
        echo "FAIL work directory contains $name" >&2
        exit 1
    fi
done
mkdir -- "$work/node-b" "$work/node-c"
"$bitcoin/bitcoind" --version >"$work/bitcoin-version.txt"
"$bitcoin/bitcoin-cli" --version >"$work/cli-version.txt"
if ! python3 -I - "$work/bitcoin-version.txt" "$work/cli-version.txt" <<'PY'
import pathlib, re, sys
sys.exit(not all(re.search(r"\bv28\.1(?:\.0)?(?:\s|$)", pathlib.Path(p).read_text()) for p in sys.argv[1:]))
PY
then
    echo "FAIL Bitcoin Core 28.1 required"
    exit 1
fi
read -r port_b port_c < <(python3 -I - <<'PY'
import socket
with socket.socket() as b, socket.socket() as c:
    b.bind(("127.0.0.1", 0))
    c.bind(("127.0.0.1", 0))
    print(b.getsockname()[1], c.getsockname()[1])
PY
)
b_pid=
c_pid=
b() { "$bitcoin/bitcoin-cli" -regtest -datadir="$work/node-b" -rpcport="$port_b" "$@"; }
c() { "$bitcoin/bitcoin-cli" -regtest -datadir="$work/node-c" -rpcport="$port_c" "$@"; }
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n "$b_pid" ]]; then
        b stop >"$work/b-stop.log" 2>&1 || true
        wait "$b_pid" || result=1
    fi
    if [[ -n "$c_pid" ]]; then
        c stop >"$work/c-stop.log" 2>&1 || true
        wait "$c_pid" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
"$bitcoin/bitcoind" -regtest -datadir="$work/node-b" -blocksxor=0 -fallbackfee=0.0001 \
    -rpcport="$port_b" -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -listen=0 -discover=0 -dnsseed=0 \
    -connect=0 -printtoconsole=0 >"$work/b-node.log" 2>&1 &
b_pid=$!
"$bitcoin/bitcoind" -regtest -datadir="$work/node-c" -blocksxor=0 \
    -rpcport="$port_c" -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -listen=0 -discover=0 -dnsseed=0 \
    -connect=0 -printtoconsole=0 >"$work/c-node.log" 2>&1 &
c_pid=$!
b -rpcwait getblockchaininfo >"$work/b-info.json"
c -rpcwait getblockchaininfo >"$work/c-info.json"
b -named createwallet wallet_name=regtest descriptors=true >"$work/wallet.json"
mine_addr=$(b getnewaddress "" bech32)
b generatetoaddress 101 "$mine_addr" >"$work/mined-initial.json"

# Two fixed private keys and their public keys, used only for this regtest wallet.
python3 -I - "$work/descriptor-inputs.json" <<'PY'
import hashlib, json, pathlib, sys
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def wif(n):
    payload = b"\xef" + n.to_bytes(32, "big") + b"\x01"
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = alphabet[rem] + encoded
    return encoded
a, b = wif(1), wif(2)
nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
pathlib.Path(sys.argv[1]).write_text(json.dumps([
    f"wsh(multi(2,{a},{b}))", f"sh(multi(2,{a},{b}))", f"tr({nums},pk({a}))"
]))
PY

# Python drives the RPC flow; all JSON is processed in isolated mode.
python3 -I - "$bitcoin/bitcoin-cli" "$work" "$port_b" "$mine_addr" <<'PY'
import json, pathlib, subprocess, sys
cli, root, port, mining = sys.argv[1:]
root = pathlib.Path(root)
base = [cli, "-regtest", f"-datadir={root / 'node-b'}", f"-rpcport={port}"]
def rpc(method, *args):
    args = [json.dumps(a, separators=(",", ":")) if not isinstance(a, str) else a for a in args]
    value = subprocess.check_output(base + [method] + args, text=True).strip()
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
def mine():
    rpc("generatetoaddress", 1, mining)
destination = rpc("getnewaddress", "", "bech32")
def fund_and_spend(address, tap_script=False):
    txid = rpc("sendtoaddress", address, 1)
    mine()
    tx = rpc("decoderawtransaction", rpc("gettransaction", txid)["hex"])
    output = next(o for o in tx["vout"] if o["scriptPubKey"].get("address") == address)
    raw = rpc("createrawtransaction", [{"txid": txid, "vout": output["n"]}], {destination: 0.9999})
    signed = rpc("signrawtransactionwithwallet", raw)
    if not signed["complete"]:
        raise RuntimeError(f"incomplete signature: {signed}")
    decoded = rpc("decoderawtransaction", signed["hex"])
    if tap_script:
        witness = decoded["vin"][0].get("txinwitness", [])
        if len(witness) < 3 or len(bytes.fromhex(witness[-1])) < 33:
            raise RuntimeError("taproot descriptor did not use script path")
    rpc("sendrawtransaction", signed["hex"], 0)
    mine()
for kind in ("legacy", "p2sh-segwit", "bech32", "bech32m"):
    fund_and_spend(rpc("getnewaddress", "", kind))
for desc in json.loads((root / "descriptor-inputs.json").read_text()):
    info = rpc("getdescriptorinfo", desc)
    imported = rpc("importdescriptors", [{"desc": desc + "#" + info["checksum"], "timestamp": "now"}])
    if not imported[0]["success"]:
        raise RuntimeError(f"descriptor import failed: {imported}")
    address = rpc("deriveaddresses", info["descriptor"])[0]
    fund_and_spend(address, desc.startswith("tr("))
# The stale branch contains one transaction; after invalidation, it reenters the mempool and confirms again on the new branch.
rpc("sendtoaddress", destination, 0.01)
stale = rpc("generatetoaddress", 1, mining)[0]
if rpc("getblock", stale)["nTx"] < 2:
    raise RuntimeError("stale block is missing its transaction")
rpc("invalidateblock", stale)
fork_mining = rpc("getnewaddress", "", "bech32")
rpc("generatetoaddress", 2, fork_mining)
rpc("generatetoaddress", 110, mining)
tip = rpc("getblockcount")
(root / "heights.json").write_text(json.dumps({"tip": tip, "height": tip - 100}))
PY
read -r tip height < <(python3 -I - "$work/heights.json" <<'PY'
import json, pathlib, sys
info = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
print(info["tip"], info["height"])
PY
)
"$new" --export-chain-list "http://127.0.0.1:$port_b/" "$work/node-b/regtest/.cookie" \
    "$height" "$work/list.txt" >"$work/export.log" 2>&1

set +e
"$new" --export-chain-list "http://127.0.0.1:$port_b/" "$work/node-b/regtest/.cookie" \
    "$((tip - 99))" "$work/depth-list.txt" >"$work/depth.log" 2>&1
depth_status=$?
set -e

python3 -I - "$bitcoin/bitcoin-cli" "$work" "$port_b" "$port_c" "$height" <<'PY'
import json, pathlib, subprocess, sys
cli, root, port_b, port_c, height = sys.argv[1:]
root = pathlib.Path(root)
def rpc(node, port, method, *args):
    data = subprocess.check_output(
        [cli, "-regtest", f"-datadir={root / node}", f"-rpcport={port}", method, *map(str, args)], text=True
    ).strip()
    if not data:
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return data
for h in range(1, int(height) + 1):
    block_hash = rpc("node-b", port_b, "getblockhash", h)
    raw = rpc("node-b", port_b, "getblock", block_hash, 0)
    if rpc("node-c", port_c, "submitblock", raw) is not None:
        raise RuntimeError(f"node C rejected height {h}")
if rpc("node-c", port_c, "getbestblockhash") != rpc("node-b", port_b, "getblockhash", height):
    raise RuntimeError("node C tip differs")
PY
b stop >"$work/b-stop.log"
wait "$b_pid"
b_pid=
c stop >"$work/c-stop.log"
wait "$c_pid"
c_pid=

# The original scanner recognizes only f9beb4d9; replace only regtest record magic in scan copies, preserving block bytes.
python3 -I - "$work" <<'PY'
import pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
for node, target in (("node-b", "scan-b"), ("node-c", "scan-c")):
    dst = root / target
    dst.mkdir()
    for source in sorted((root / node / "regtest/blocks").glob("blk*.dat")):
        data = bytearray(source.read_bytes())
        pos = 0
        while pos + 8 <= len(data):
            if data[pos:pos + 4] == bytes.fromhex("fabfb5da"):
                size = struct.unpack_from("<I", data, pos + 4)[0]
                if size < 80 or size > len(data) - pos - 8:
                    break
                data[pos:pos + 4] = bytes.fromhex("f9beb4d9")
                pos += 8 + size
            else:
                pos += 1
        (dst / source.name).write_bytes(data)
lines = (root / "list.txt").read_text().splitlines()
h, block_hash = lines[-1].split()
lines[-1] = h + " " + ("1" if block_hash[0] == "0" else "0") + block_hash[1:]
(root / "wrong-list.txt").write_text("\n".join(lines) + "\n")
PY
"$old" --scan-blocks "$work/scan-c" "$work/old-c" >"$work/old-c.log" 2>&1
"$new" --scan-blocks "$work/scan-c" "$work/new-c" "$work/list.txt" >"$work/new-c.log" 2>&1
"$new" --scan-blocks "$work/scan-b" "$work/new-b" "$work/list.txt" >"$work/new-b.log" 2>&1
if ! BTC_INDEXER_STOP_AFTER_STAGE1=1 "$old_stage1" --scan-blocks "$work/scan-c" "$work/old-stage1-c" >"$work/old-stage1-c.log" 2>&1; then
    echo "FAIL old stage-1 node C scan"
    exit 1
fi
failed=0
echo "Node C state oracle:"
python3 -I "$script_dir/state-oracle.py" "$work/old-stage1-c/shards" "$work/new-c" || failed=1
echo "Node B state oracle (node C main-chain shards):"
python3 -I "$script_dir/state-oracle.py" "$work/old-stage1-c/shards" "$work/new-b" || failed=1
set +e
"$new" --scan-blocks "$work/scan-b" "$work/bad-list" "$work/wrong-list.txt" >"$work/bad-list.log" 2>&1
bad_status=$?
set -e

if ! python3 -I - "$work" "$bad_status" "$depth_status" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
failed = False
def check(ok, label):
    global failed
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    failed |= not ok
tables = (
    "pubkey_hash_index.bin", "script_hash_index_20.bin", "script_hash_index_32.bin",
    "cross_format_diff_20.bin", "cross_format_diff_32.bin",
)
for name in tables:
    check((root / "old-c" / name).read_bytes() == (root / "new-c" / name).read_bytes(), f"a {name}")
old = json.loads((root / "old-c/stats.json").read_bytes())
new = json.loads((root / "new-c/stats.json").read_bytes())
new.pop("scan_height", None)
new.pop("scan_block_hash", None)
serialize = lambda value: json.dumps(value, sort_keys=True, indent=2).encode("utf-8")
check(serialize(old) == serialize(new), "a stats.json")
def snapshot(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
check(snapshot(root / "new-b") == snapshot(root / "new-c"), "b every new output byte-identical")
match = re.search(r"Skipped (\d+) records", (root / "new-b.log").read_text())
check(match is not None and int(match[1]) >= 1, "c stale records skipped")
check(sys.argv[2] == "1" and re.search(r"^ERROR:", (root / "bad-list.log").read_text(), re.M) is not None,
      "d wrong chain hash rejected")
check(sys.argv[3] == "1" and re.search(r"^ERROR:", (root / "depth.log").read_text(), re.M) is not None,
      "e tip-minus-99 export rejected")
sys.exit(int(failed))
PY
then
    failed=1
fi
exit "$failed"

