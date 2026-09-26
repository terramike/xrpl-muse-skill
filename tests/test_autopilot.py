#!/usr/bin/env python3
"""Autopilot (at-your-own-risk local signing) tests — no network.

The autopilot seed must NEVER appear in stdout, stderr, the audit log, or
any file except the owner-only 0600 autopilot.json. Run:
python3 tests/test_autopilot.py
"""
import importlib.util
import io
import contextlib
import getpass
import builtins
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace as ns
from unittest import mock

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    # Register the shared helper under the name both CLIs import, so the
    # test and the CLIs use ONE module instance.
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
S = load(BIN / "xrpl-sign", "xrpl_sign_autopilot")
T = load(BIN / "xrpl-trade", "xrpl_trade_autopilot")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


tmp = Path(tempfile.mkdtemp(prefix="autopilot-"))
# Redirect ALL shared paths to the sandbox (single module instance!).
C.XRPL_DIR = tmp
C.CONFIG_PATH = tmp / "config.json"
C.PROPOSALS_DIR = tmp / "proposals"
C.POLICY_PATH = tmp / "policy.json"
C.STATE_PATH = tmp / "state.json"
C.STATE_LOCK_PATH = tmp / "state.lock"
C.AUDIT_PATH = tmp / "audit.log"
C.AUTOPILOT_PATH = tmp / "autopilot.json"

from xrpl.wallet import Wallet

w = Wallet.create()
SEED = w.seed
ADDR = w.classic_address
OTHER = Wallet.create()
CFG = {"address": ADDR, "network": "mainnet"}


class FakeResp:
    def __init__(self, ok, result):
        self._ok = ok
        self.result = result

    def is_successful(self):
        return self._ok


class FakeClient:
    """No network. account_data carries no RegularKey (master path)."""
    def request(self, req):
        return FakeResp(True, {"account_data": {}})


def run_enable(seed, ack="ENABLE AUTOPILOT", address=None, cfg=None):
    buf = io.StringIO()
    args = ns(autopilot_cmd="enable", address=address)
    with mock.patch.object(T, "get_client", return_value=FakeClient()), \
         mock.patch.object(builtins, "input", return_value=ack), \
         mock.patch.object(getpass, "getpass", return_value=seed), \
         contextlib.redirect_stdout(buf):
        try:
            T.cmd_autopilot(args, cfg if cfg is not None else CFG)
            return "ok", buf.getvalue()
        except SystemExit as e:
            return f"exit:{e.code}", buf.getvalue()


def run_simple(cmd, confirm=None):
    buf = io.StringIO()
    args = ns(autopilot_cmd=cmd, address=None)
    cm = mock.patch.object(builtins, "input", return_value=confirm) \
        if confirm is not None else contextlib.nullcontext()
    with cm, contextlib.redirect_stdout(buf):
        try:
            T.cmd_autopilot(args, CFG)
            return "ok", buf.getvalue()
        except SystemExit as e:
            return f"exit:{e.code}", buf.getvalue()


def cleanup():
    try:
        C.AUTOPILOT_PATH.unlink()
    except OSError:
        pass


# 1. status: disabled by default
cleanup()
rc, out = run_simple("status")
check("status says disabled when no file", rc == "ok" and "disabled" in out)
check("status leaks nothing (no seed anywhere)", SEED not in out)

# 2. enable: wrong acknowledgment -> refused, no file
cleanup()
rc, out = run_enable(SEED, ack="yes please")
check("enable without exact acknowledgment refuses",
      rc.startswith("exit:") and not C.AUTOPILOT_PATH.exists())

# 3. enable: garbage seed -> refused
cleanup()
rc, out = run_enable("not-a-seed-at-all")
check("enable refuses a garbage seed",
      rc.startswith("exit:") and not C.AUTOPILOT_PATH.exists())

# 4. enable: seed for a DIFFERENT address -> refused
cleanup()
rc, out = run_enable(OTHER.seed)
check("enable refuses a seed that does not control the account",
      rc.startswith("exit:") and not C.AUTOPILOT_PATH.exists())

# 5. enable: happy path
cleanup()
rc, out = run_enable(SEED)
check("enable succeeds with acknowledgment + matching seed", rc == "ok")
check("autopilot.json created", C.AUTOPILOT_PATH.exists())
mode = stat.S_IMODE(os.stat(C.AUTOPILOT_PATH).st_mode)
check("autopilot.json is owner-only 0600", mode == 0o600)
check("enable never prints the seed", SEED not in out)
stored = json.loads(C.AUTOPILOT_PATH.read_text())
check("stored account matches", stored.get("account") == ADDR)
check("stored enabled flag", stored.get("enabled") is True)
check("stored network", stored.get("network") == "mainnet")
check("risk acknowledgment recorded", stored.get("risk_acknowledged") is True)
audit_text = C.AUDIT_PATH.read_text() if C.AUDIT_PATH.exists() else ""
check("audit logs the enable event", "autopilot_enable" in audit_text)
check("audit never contains the seed", SEED not in audit_text)

# 6. helpers: gating
check("autopilot_enabled_for true for the account",
      C.autopilot_enabled_for(ADDR) is True)
check("autopilot_enabled_for false for another account",
      C.autopilot_enabled_for(OTHER.classic_address) is False)
check("read_autopilot_seed returns the seed for the account",
      C.read_autopilot_seed(ADDR) == SEED)
check("read_autopilot_seed None for another account",
      C.read_autopilot_seed(OTHER.classic_address) is None)

# 7. enable twice -> refused (no silent overwrite)
rc, out = run_enable(SEED)
check("second enable refuses while already enabled",
      rc.startswith("exit:"))
check("file unchanged by refused enable",
      json.loads(C.AUTOPILOT_PATH.read_text())["seed"] == SEED)

# 8. status when enabled: shows account, never the seed
rc, out = run_simple("status")
check("status shows enabled + account",
      rc == "ok" and "ENABLED" in out and ADDR in out)
check("status never shows the seed", SEED not in out)

# 9. signer load_seed: autopilot kind works, fail-closed otherwise
check("signer load_seed(autopilot) returns the seed",
      S.load_seed(("autopilot", ADDR)) == SEED)
try:
    S.load_seed(("autopilot", OTHER.classic_address))
    check("signer load_seed(autopilot) refuses another account", False)
except SystemExit:
    check("signer load_seed(autopilot) refuses another account", True)

# 10. loose file permissions -> fail closed
os.chmod(C.AUTOPILOT_PATH, 0o644)
check("read_autopilot_seed None on 0644 file",
      C.read_autopilot_seed(ADDR) is None)
check("autopilot_enabled_for still true (state, not seed)",
      C.autopilot_enabled_for(ADDR) is True)
os.chmod(C.AUTOPILOT_PATH, 0o600)
check("read_autopilot_seed recovers on 0600",
      C.read_autopilot_seed(ADDR) == SEED)

# 11. corrupt file -> treated as disabled (fail closed)
C.AUTOPILOT_PATH.write_text("{not json")
check("corrupt autopilot.json reads as no state",
      C.autopilot_state() is None)
check("corrupt autopilot.json is not enabled",
      C.autopilot_enabled_for(ADDR) is False)
check("corrupt autopilot.json yields no seed",
      C.read_autopilot_seed(ADDR) is None)
cleanup()

# 12. disable: wrong confirmation keeps the file
run_enable(SEED)
rc, out = run_simple("disable", confirm="rWRONG")
check("disable with wrong address keeps the seed",
      rc.startswith("exit:") and C.AUTOPILOT_PATH.exists())
check("still enabled after refused disable",
      C.autopilot_enabled_for(ADDR) is True)

# 13. disable: right confirmation removes everything
rc, out = run_simple("disable", confirm=ADDR)
check("disable with the address succeeds", rc == "ok")
check("autopilot.json removed", not C.AUTOPILOT_PATH.exists())
check("disabled after removal", C.autopilot_enabled_for(ADDR) is False)
check("no seed after removal", C.read_autopilot_seed(ADDR) is None)
check("disable never prints the seed", SEED not in out)
audit_text = C.AUDIT_PATH.read_text()
check("audit logs the disable event", "autopilot_disable" in audit_text)
check("audit still never contains the seed", SEED not in audit_text)
try:
    S.load_seed(("autopilot", ADDR))
    check("signer refuses autopilot seed after disable", False)
except SystemExit:
    check("signer refuses autopilot seed after disable", True)

# 14. disable when already disabled: harmless no-op
rc, out = run_simple("disable", confirm=ADDR)
check("disable when disabled is a no-op", rc == "ok")

# 15. RegularKey path: seed deriving to the on-ledger RegularKey is accepted
rk_wallet = Wallet.create()
rk_client = FakeClient()


class RKClient:
    def request(self, req):
        return FakeResp(True, {"account_data":
                               {"RegularKey": rk_wallet.classic_address}})


ok, kind = T.autopilot_seed_controls_account(rk_wallet.seed, ADDR, RKClient())
check("seed deriving to RegularKey accepted", ok and kind == "regular")
ok, kind = T.autopilot_seed_controls_account(rk_wallet.seed, ADDR, FakeClient())
check("RegularKey seed without ledger RegularKey refused", not ok)
ok, kind = T.autopilot_seed_controls_account(SEED, ADDR, FakeClient())
check("master seed accepted without ledger call", ok and kind == "master")
ok, kind = T.autopilot_seed_controls_account("garbage", ADDR, FakeClient())
check("garbage seed rejected by verifier", not ok)

# 16. backup_ceremony: exact confirmation required, seed displayed once
buf = io.StringIO()
with mock.patch.object(builtins, "input",
                       return_value="I HAVE WRITTEN IT DOWN"), \
     contextlib.redirect_stdout(buf):
    confirmed = T.backup_ceremony(SEED, ADDR)
out = buf.getvalue()
check("backup ceremony confirms on exact phrase", confirmed is True)
check("backup ceremony displays the seed once", SEED in out)
check("backup ceremony warns about chat/logs", "BURNED" in out)

buf = io.StringIO()
with mock.patch.object(builtins, "input", return_value="yeah sure"), \
     contextlib.redirect_stdout(buf):
    confirmed = T.backup_ceremony(SEED, ADDR)
check("backup ceremony rejects wrong confirmation", confirmed is False)


def run_enable_inputs(inputs, cfg, getpass_ret="should-not-be-called"):
    """Enable with a scripted input() sequence; getpass fails loudly."""
    buf = io.StringIO()
    args = ns(autopilot_cmd="enable", address=None)
    def _getpass(prompt=""):
        raise AssertionError("getpass must not be called on this path")
    it = iter(inputs)
    with mock.patch.object(T, "get_client", return_value=FakeClient()), \
         mock.patch.object(builtins, "input", side_effect=lambda *a: next(it)), \
         mock.patch.object(getpass, "getpass", side_effect=_getpass), \
         contextlib.redirect_stdout(buf):
        try:
            T.cmd_autopilot(args, cfg)
            return "ok", buf.getvalue()
        except SystemExit as e:
            return f"exit:{e.code}", buf.getvalue()
        except StopIteration:
            return "exit:ran-out-of-inputs", buf.getvalue()


CFG_WITH_SEED = {"address": ADDR, "network": "testnet", "seed": SEED}

# 17. adopt: local seed adopted directly, no paste
cleanup()
rc, out = run_enable_inputs(["ENABLE AUTOPILOT", "y", "n"], dict(CFG_WITH_SEED))
st = C.autopilot_state()
check("adopt path enables without pasting", rc == "ok" and st is not None)
check("adopt path stores the local seed",
      st and st.get("seed") == SEED and st.get("account") == ADDR)
check("adopt path records backed_up=False when never backed up",
      st and st.get("seed_backed_up") is False)
check("adopt path never displays the seed", SEED not in out)

# 18. adopt declined -> falls through to generate/paste; abort cleanly
cleanup()
rc, out = run_enable_inputs(
    ["ENABLE AUTOPILOT", "n", "g", "not yet"], dict(CFG_WITH_SEED))
check("declined adopt + declined backup stores nothing",
      rc.startswith("exit:") and not C.AUTOPILOT_PATH.exists())

# 19. generate: fresh wallet, backup ceremony, backed_up=True
cleanup()
rc, out = run_enable_inputs(
    ["ENABLE AUTOPILOT", "g", "I HAVE WRITTEN IT DOWN"],
    {"network": "testnet"})
st = C.autopilot_state()
check("generate path enables", rc == "ok" and st is not None)
check("generate path records backed_up=True",
      st and st.get("seed_backed_up") is True)
check("generate path stores a fresh seed (not the fixture)",
      st and st.get("seed") and st.get("seed") != SEED)
check("generate path seed derives its account",
      st and Wallet.from_seed(st["seed"]).classic_address == st["account"])
check("generate path displays the seed for backup",
      st and st["seed"] in out)

# 20. generate without backup confirmation stores nothing
cleanup()
rc, out = run_enable_inputs(
    ["ENABLE AUTOPILOT", "g", "not yet"], {"network": "testnet"})
check("generate without backup confirmation stores nothing",
      rc.startswith("exit:") and not C.AUTOPILOT_PATH.exists())

fails = [n for n, ok_ in PASS if not ok_]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} passed")
sys.exit(1 if fails else 0)
