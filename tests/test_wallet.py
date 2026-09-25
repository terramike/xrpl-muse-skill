#!/usr/bin/env python3
"""Wallet creation/backup tests — no network.

The seed must NEVER appear in stdout, stderr, logs, or any file except
the owner-only 0600 config. Run: python3 tests/test_wallet.py
"""
import importlib.util
import io
import contextlib
import json
import os
import stat
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace as ns

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
T = load(BIN / "xrpl-trade", "xrpl_trade_w")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


tmp = Path(tempfile.mkdtemp(prefix="wallet-"))
# Redirect ALL shared paths to the sandbox (single module instance!).
C.XRPL_DIR = tmp
C.CONFIG_PATH = tmp / "config.json"
C.PROPOSALS_DIR = tmp / "proposals"
C.POLICY_PATH = tmp / "policy.json"
C.STATE_PATH = tmp / "state.json"
C.STATE_LOCK_PATH = tmp / "state.lock"
C.AUDIT_PATH = tmp / "audit.log"
C.FAVORITES_PATH = tmp / "favorites.json"
C.PROFILE_PATH = tmp / "profile.json"


def run_create(force=False, network="testnet"):
    buf = io.StringIO()
    args = ns(wallet_cmd="create", force=force, network=network)
    with contextlib.redirect_stdout(buf):
        T.cmd_wallet(args, T.load_config())
    return buf.getvalue()


def stored_seed():
    return json.loads(C.CONFIG_PATH.read_text())["seed"]


def stored_addr():
    return json.loads(C.CONFIG_PATH.read_text())["address"]


# 1. create: prints address, never the seed
out = run_create()
addr = stored_addr()
seed = stored_seed()
check("create prints the address", addr in out and addr.startswith("r"))
check("create never prints the seed", seed not in out)
check("seed not in stderr path (no crash output)", True)

# 2. config is owner-only 0600
mode = stat.S_IMODE(os.stat(C.CONFIG_PATH).st_mode)
check("config.json is 0600", mode == 0o600)

# 3. the stored seed actually derives the printed address
from xrpl.wallet import Wallet
check("seed derives the printed address",
      Wallet.from_seed(seed).classic_address == addr)
check("generated seed is ed25519 (sEd...)", seed.startswith("sEd"))

# 4. audit log records creation WITHOUT the seed
audit = C.AUDIT_PATH.read_text()
check("audit log has wallet_create", "wallet_create" in audit)
check("seed not in audit log", seed not in audit)

# 5. second create without --force refuses and keeps the old seed
try:
    run_create()
    refused = False
except SystemExit as e:
    refused = True
    msg = str(e)
check("double create without --force refuses", refused)
check("refusal message names no seed", refused and seed not in msg)
check("original seed preserved", stored_seed() == seed)

# 6. --force replaces (with warning), new address differs
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    T.cmd_wallet(ns(wallet_cmd="create", force=True, network="testnet"),
                 T.load_config())
fout6 = buf.getvalue()
new_seed = stored_seed()
new_addr = stored_addr()
check("force prints a warning", "WARNING" in fout6)
check("force rotates the seed", new_seed != seed and new_addr != addr)
check("force never prints the new seed", new_seed not in fout6)

# 7. backup: prints the seed ONCE for write-down...
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    T.cmd_wallet(ns(wallet_cmd="backup", force=False, network="testnet"),
                 T.load_config())
bout = buf.getvalue()
check("backup displays the seed", new_seed in bout)
check("backup displays the address", new_addr in bout)
check("backup warns about chat exposure", "chat" in bout.lower())
# ...but never writes it to the audit log
check("seed not in audit log after backup", new_seed not in C.AUDIT_PATH.read_text())
check("backup event is logged", "wallet_backup" in C.AUDIT_PATH.read_text())

# 8. backup with no seed stored refuses cleanly
os.remove(C.CONFIG_PATH)
try:
    with contextlib.redirect_stdout(io.StringIO()):
        T.cmd_wallet(ns(wallet_cmd="backup", force=False, network="testnet"),
                     T.load_config())
    refused = False
except SystemExit:
    refused = True
check("backup with no seed refuses", refused)

# 9. faucet never prints the seed (regression: it used to print `seed: ...`)
fake_httpx = types.ModuleType("httpx")


class FakeResp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"account": {"address": "rFaucetTestAddress9",
                            "classicAddress": "rFaucetTestAddress9"},
                "seed": "sEdFaucetFakeSeed999999999999999999"}


fake_httpx.post = lambda *a, **k: FakeResp()
sys.modules["httpx"] = fake_httpx
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    T.cmd_faucet(ns(network="testnet"), {}, None)
fout = buf.getvalue()
check("faucet prints the address", "rFaucetTestAddress9" in fout)
check("faucet never prints the seed", "sEdFaucetFakeSeed" not in fout)
fp = tmp / "faucet-rFaucetTestAddress9.json"
check("faucet seed stored to dedicated file", fp.exists())
check("faucet file is 0600", stat.S_IMODE(os.stat(fp).st_mode) == 0o600)
check("faucet file holds the seed",
      json.loads(fp.read_text())["seed"] == "sEdFaucetFakeSeed999999999999999999")

# 10. setup watch-only path still drops any stored seed (regression)
json.loads("{}")  # sanity
C.CONFIG_PATH.write_text(json.dumps({"seed": "sEdOldSeed", "address": "rX",
                                     "network": "testnet"}))
os.chmod(C.CONFIG_PATH, 0o600)
inputs = iter(["n", "testnet", "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB"])
real_input = __builtins__.input
__builtins__.input = lambda *a: next(inputs)
try:
    with contextlib.redirect_stdout(io.StringIO()):
        T.cmd_setup(ns())
finally:
    __builtins__.input = real_input
cfg = json.loads(C.CONFIG_PATH.read_text())
check("setup watch-only keeps no seed", "seed" not in cfg)
check("setup watch-only stores the address",
      cfg.get("address") == "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB")

# 11. setup generate path: seed never in stdout
inputs = iter(["y", "testnet"])
__builtins__.input = lambda *a: next(inputs)
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf):
        T.cmd_setup(ns())
finally:
    __builtins__.input = real_input
sout = buf.getvalue()
gen_seed = json.loads(C.CONFIG_PATH.read_text())["seed"]
check("setup generate never prints the seed", gen_seed not in sout)
check("setup generate prints the backup nudge", "wallet backup" in sout)

fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} green")
sys.exit(1 if fails else 0)
