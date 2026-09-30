#!/usr/bin/env python3
"""Read-only default mode tests — no network.

Run: python3 tests/test_readonly.py

Covers: fresh installs default to read-only, grandfathered installs keep
prior behavior, corrupt config fails closed, the live/read-only ceremony
flips the flag (wrong phrase refuses), no CLI/env bypass exists, and
xrpl-sign --approve refuses while read-only (audit-logged).
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

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
T = load(BIN / "xrpl-trade", "xrpl_trade_readonly")
S = load(BIN / "xrpl-sign", "xrpl_sign_readonly")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def fresh_state():
    """Point the shared C module at an empty temp dir. Returns the dir."""
    tmp = Path(tempfile.mkdtemp(prefix="xrpl-ro-test-"))
    C.XRPL_DIR = tmp
    C.CONFIG_PATH = tmp / "config.json"
    C.PROPOSALS_DIR = tmp / "proposals"
    C.AUDIT_PATH = tmp / "audit.log"
    return tmp


def write_cfg(d):
    C.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    C.CONFIG_PATH.write_text(json.dumps(d))
    os.chmod(C.CONFIG_PATH, 0o600)


def run_cmd(fn, *a):
    """Run a cmd_* function, capturing (stdout, systemexit_code)."""
    buf = io.StringIO()
    code = "no-exit"
    with redirect_stdout(buf):
        try:
            fn(*a)
        except SystemExit as e:
            code = e.code
    return buf.getvalue(), code


# ---------- is_read_only defaults ----------

fresh_state()
check("fresh install (no config): read-only", C.is_read_only() is True)

fresh_state()
write_cfg({"address": "rABC", "network": "mainnet"})
check("grandfathered config (no key): signing stays enabled",
      C.is_read_only() is False)

fresh_state()
write_cfg({"read_only": True})
check("explicit read_only=true: read-only", C.is_read_only() is True)

fresh_state()
write_cfg({"read_only": False})
check("explicit read_only=false: live", C.is_read_only() is False)

fresh_state()
write_cfg({"read_only": 1})
check("truthy non-bool coerced", C.is_read_only() is True)

fresh_state()
C.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
C.CONFIG_PATH.write_text("{not json")
check("corrupt config: fail closed (read-only)", C.is_read_only() is True)

# ---------- set_read_only ----------

fresh_state()
write_cfg({"address": "rABC", "network": "mainnet", "seed": "sXXX"})
C.set_read_only(True)
cfg = json.loads(C.CONFIG_PATH.read_text())
check("set_read_only preserves other keys",
      cfg.get("address") == "rABC" and cfg.get("seed") == "sXXX"
      and cfg.get("read_only") is True)
check("config stays 0600", oct(C.CONFIG_PATH.stat().st_mode & 0o777) == "0o600")
C.set_read_only(False)
check("set_read_only flips back",
      json.loads(C.CONFIG_PATH.read_text())["read_only"] is False)

fresh_state()
C.set_read_only(True)  # no config file at all
check("set_read_only creates config when missing",
      json.loads(C.CONFIG_PATH.read_text())["read_only"] is True)

# ---------- default_read_only_for_new_config ----------

fresh_state()
cfg = {"address": "rABC"}
C.default_read_only_for_new_config(cfg)
check("brand-new config file: stamped read-only", cfg.get("read_only") is True)

fresh_state()
write_cfg({"address": "rABC"})
cfg = json.loads(C.CONFIG_PATH.read_text())
C.default_read_only_for_new_config(cfg)
check("existing config: key stays absent (grandfathered)",
      "read_only" not in cfg)

# ---------- ceremony commands ----------

fresh_state()  # read-only (no config)
out, code = run_cmd(T.cmd_live, Namespace(confirm="please"))
check("live with wrong phrase: refused",
      "did not match" in out and C.is_read_only() is True)

out, code = run_cmd(T.cmd_live, Namespace(confirm="go live"))
check("live with 'go live': enabled",
      "Live. Signing is now enabled." in out and C.is_read_only() is False)

out, code = run_cmd(T.cmd_live, Namespace(confirm=None))
check("live when already live: no-op message",
      "already enabled" in out and C.is_read_only() is False)

out, code = run_cmd(T.cmd_read_only, Namespace())
check("read-only command locks down",
      "Read-only mode ON" in out and C.is_read_only() is True)

out, code = run_cmd(T.cmd_read_only, Namespace())
check("read-only when already read-only: no-op message",
      "Already in read-only mode." in out)

# live then read-only round-trip preserves the rest of the config
fresh_state()
write_cfg({"address": "rABC", "network": "testnet"})
run_cmd(T.cmd_live, Namespace(confirm="go live"))
run_cmd(T.cmd_read_only, Namespace())
cfg = json.loads(C.CONFIG_PATH.read_text())
check("ceremony round-trip preserves other keys",
      cfg.get("address") == "rABC" and cfg.get("read_only") is True)

# ---------- no bypass ----------

for name, path in [("xrpl-trade", BIN / "xrpl-trade"),
                   ("xrpl-sign", BIN / "xrpl-sign"),
                   ("xrpl_common", BIN / "xrpl_common.py")]:
    src = Path(path).read_text()
    check(f"{name}: no XRPL_READ_ONLY env bypass", "XRPL_READ_ONLY" not in src)
    check(f"{name}: no --no-read-only flag", "--no-read-only" not in src)

sign_src = (BIN / "xrpl-sign").read_text()
check("xrpl-sign: no --read-only CLI flag",
      '"--read-only"' not in sign_src and "'--read-only'" not in sign_src)

# ---------- xrpl-sign --approve gate ----------

fresh_state()
write_cfg({"read_only": True})
out, code = run_cmd(S.cmd_sign, Namespace(hash="bogus", approve=True))
check("sign --approve in read-only: refused",
      code == 1 and "READ-ONLY MODE" in out)
check("sign --approve in read-only: nothing signed",
      "Nothing was signed or submitted." in out)
audit_lines = C.AUDIT_PATH.read_text().strip().splitlines() if C.AUDIT_PATH.exists() else []
check("refusal is audit-logged",
      any("read_only_refused" in ln for ln in audit_lines))

fresh_state()
write_cfg({"read_only": False})
out, code = run_cmd(S.cmd_sign, Namespace(hash="bogus", approve=True))
check("sign --approve when live: no read-only refusal",
      "READ-ONLY MODE" not in out)

# ---------- summary ----------
fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} passed")
if fails:
    print("FAILURES:", fails)
    sys.exit(1)
