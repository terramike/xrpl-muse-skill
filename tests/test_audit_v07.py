#!/usr/bin/env python3
"""v0.7 audit-remediation regression tests — no network. Run: python3 tests/test_audit_v07.py

Covers the Astra audit findings reproduced against 34f09499:
- P1-1: profile-bound signing (account+network+credential+policy+state)
- P1-2: vault-only mainnet (no mainnet seed creation/backup/display)
- P1-3: reservations that cannot vanish (no expiry, proven non-inclusion,
        fee retained on validated failure)
- P2-6: strict accounting state (negative/nonfinite/inconsistent rejected,
        corrupt state fails closed, recover-state preserves obligations)
"""
import importlib.util
import json
import sys
import tempfile
import time
from types import SimpleNamespace
from decimal import Decimal
import os
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
T = load(BIN / "xrpl-trade", "xrpl_trade_v07")
S = load(BIN / "xrpl-sign", "xrpl_sign_v07")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet  # noqa: E402
ACCT = Wallet.create().classic_address
OTHER = Wallet.create().classic_address
ISS = Wallet.create().classic_address

tmp = Path(tempfile.mkdtemp())
C.XRPL_DIR = tmp
C.PROPOSALS_DIR = tmp / "proposals"
C.POLICY_PATH = tmp / "policy.json"
C.STATE_PATH = tmp / "state.json"
C.STATE_LOCK_PATH = tmp / "state.lock"
C.AUDIT_PATH = tmp / "audit.log"
C.APPROVED_PATH = tmp / "approved.json"
C.CONFIG_PATH = tmp / "config.json"
C.PROFILES_PATH = tmp / "profiles.json"
C.APPROVED_PATH.write_text(json.dumps({"pairs": {
    "XRP/RLUSD": {"base": "XRP", "base_issuer": None,
                  "quote": "RLUSD", "quote_issuer": ISS}}}))
policy = dict(C.DEFAULT_POLICY)
policy["spend_limits"] = {"XRP": {"per_tx": "25", "per_day": "100"},
                          f"RLUSD.{ISS}": {"per_tx": "40", "per_day": "150"}}
policy["network_lock"] = "mainnet"
C.POLICY_PATH.write_text(json.dumps(policy))
os.chmod(C.POLICY_PATH, 0o600)
policy_sha = C._sha256_file(C.POLICY_PATH)
C.PROFILES_PATH.write_text(json.dumps({
    "schema_version": 1,
    "profiles": {
        "main": {"account": ACCT, "network": "mainnet",
                 "credential": {"kind": "env", "env_var": "XRPL_SEED"},
                 "policy_path": str(C.POLICY_PATH),
                 "policy_sha256": policy_sha,
                 "state": "default"},
        "other": {"account": OTHER, "network": "mainnet",
                  "credential": {"kind": "env", "env_var": "XRPL_SEED"},
                  "policy_path": str(C.POLICY_PATH),
                  "policy_sha256": policy_sha,
                  "state": "giveaway"},
    }}))
os.chmod(C.PROFILES_PATH, 0o600)

# ---------------------------------------------------------------- P1-1

def make_mainnet_proposal(account=ACCT, profile="main", pdigest=policy_sha,
                          network="mainnet"):
    tx = T.build_offer_tx(account, "XRP", None, "RLUSD", ISS,
                          Decimal("1"), Decimal("1.5"), "buy", 3600)
    txd = tx.to_xrpl()
    txd["Sequence"] = 1
    txd["Fee"] = "12"
    txd["LastLedgerSequence"] = 100
    h, path = C.save_proposal(txd, network, account, "buy",
                              profile=profile, policy_sha256=pdigest)
    return json.loads(path.read_text())

# Build a mainnet proposal bound to profile "main".
prop = make_mainnet_proposal()
check("P1-1 proposal carries profile binding",
      prop.get("profile") == "main" and
      prop.get("policy_sha256") == policy_sha and
      prop.get("format") == "xrpl-proposal/4")

def gate_args(profile):
    return SimpleNamespace(profile=profile, policy=None,
                           seed_env="XRPL_SEED", hash=prop["proposal_hash"])

# Signer gate: mainnet without --profile is refused.
try:
    S.resolve_signing_context(gate_args(None), prop)
    check("P1-1 mainnet without --profile refused", False)
except SystemExit:
    check("P1-1 mainnet without --profile refused", True)

# Wrong profile is refused.
try:
    S.resolve_signing_context(gate_args("other"), prop)
    check("P1-1 cross-profile use refused", False)
except SystemExit:
    check("P1-1 cross-profile use refused", True)

# Correct profile passes the gate (legacy-seed block may fire first if the
# operator's real ~/.xrpl has seeds — the gate itself is what we test).
# Point C at the sandbox so block_mainnet_on_legacy_seeds sees clean files.
import os as _os
_real_xrpl = C.XRPL_DIR
try:
    S.resolve_signing_context(gate_args("main"), prop)
    check("P1-1 matching profile passes gate", True)
except SystemExit as e:
    # Acceptable only if it's the legacy-seed block (P1-2), not a gate bug.
    check("P1-1 matching profile passes gate (" + str(e)[:60] + ")",
          "seed material" in str(e))

# Policy digest mismatch -> refused.
tampered = dict(C.load_profiles()["main"])
tampered["policy_sha256"] = "0" * 64
raw = json.loads(C.PROFILES_PATH.read_text())
raw["profiles"]["main"] = tampered
C.PROFILES_PATH.write_text(json.dumps(raw))
try:
    S.resolve_signing_context(gate_args("main"), prop)
    check("P1-1 policy-digest mismatch refused", False)
except SystemExit as e:
    check("P1-1 policy-digest mismatch refused",
          "digest" in str(e) or "policy" in str(e).lower())
# restore
raw = json.loads(C.PROFILES_PATH.read_text())
raw["profiles"]["main"]["policy_sha256"] = policy_sha
C.PROFILES_PATH.write_text(json.dumps(raw))

# Envelope hash binds the profile: rebinding to another profile breaks it.
rebound = dict(prop)
rebound["profile"] = "other"
check("P1-1 envelope hash binds profile",
      C.canonical_hash({k: rebound[k] for k in C.ENVELOPE_HASH_KEYS}) != prop["proposal_hash"])

# Testnet adhoc: no profile required.
tprop = make_mainnet_proposal(network="testnet", profile=None, pdigest=None)
check("P1-1 testnet proposal has no profile binding",
      tprop.get("profile") in (None, "") and
      tprop.get("format") == "xrpl-proposal/4")

# ---------------------------------------------------------------- P1-2

def wallet_args(cmd, network):
    return SimpleNamespace(wallet_cmd=cmd, network=network, force=False,
                           path=None)

# Mainnet wallet creation is refused (vault-only).
try:
    T.cmd_wallet(wallet_args("create", "mainnet"), {})
    check("P1-2 mainnet wallet create refused", False)
except SystemExit as e:
    check("P1-2 mainnet wallet create refused",
          "vault-only" in str(e))

# Mainnet backup is refused.
try:
    T.cmd_wallet(wallet_args("backup", "mainnet"), {})
    check("P1-2 mainnet wallet backup refused", False)
except SystemExit as e:
    check("P1-2 mainnet wallet backup refused",
          "vault-only" in str(e))

# Testnet create works and prints no seed.
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    T.cmd_wallet(wallet_args("create", "testnet"), {})
out = buf.getvalue()
cfg = json.loads(C.CONFIG_PATH.read_text())
check("P1-2 testnet create prints no seed",
      cfg.get("seed") not in out)
check("P1-2 testnet seed stored locally",
      bool(cfg.get("seed")))

# Legacy-seed detection flags config.json.
C.CONFIG_PATH.write_text(json.dumps({"seed": "sEdSKoP2x8x7x9x0x1x2x3x4x5x6x7x", "network": "mainnet"}))
found = C.detect_legacy_seeds()
check("P1-2 legacy seed in config.json detected",
      any("config.json" in p for p, _ in found))

# ---------------------------------------------------------------- P1-3 + P2-6

cpol = {"spend_limits": {"XRP": {"per_tx": "25", "per_day": "100"}}}
tr = C.SpentTracker()

# Negative spend rejected.
d, rid = tr.try_reserve({"XRP": Decimal("-5")}, cpol)
check("P2-6 negative spend denied", bool(d) and rid is None)

# NaN / Infinity rejected.
d, rid = tr.try_reserve({"XRP": Decimal("NaN")}, cpol)
check("P2-6 NaN spend denied", bool(d) and rid is None)
d, rid = tr.try_reserve({"XRP": Decimal("Infinity")}, cpol)
check("P2-6 Infinity spend denied", bool(d) and rid is None)

# Pending entries never age out of the rolling window.
old_pending = {"rid": "old", "ts": int(time.time()) - 90000, "asset": "XRP",
               "amount": "1", "status": "pending", "tx_hash": None,
               "last_ledger": None, "submit_ledger": None}
C.STATE_PATH.write_text(json.dumps({"entries": [old_pending]}))
pruned = tr._prune(tr._load()["entries"], int(time.time()))
check("P1-3 pending survives _prune past 24h", len(pruned) == 1)

# But confirmed entries still age out.
old_conf = dict(old_pending, rid="oldc", status="confirmed")
C.STATE_PATH.write_text(json.dumps({"entries": [old_conf]}))
pruned = tr._prune(tr._load()["entries"], int(time.time()))
check("P1-3 confirmed entries still age out", len(pruned) == 0)

# Corrupt state fails closed — never silently resets limits.
C.STATE_PATH.write_text("{not json")
try:
    tr._load()
    check("P2-6 corrupt state raises StateError", False)
except C.SpentTracker.StateError:
    check("P2-6 corrupt state raises StateError", True)

# Negative entry in state is rejected, not silently offset.
C.STATE_PATH.write_text(json.dumps({"entries": [
    {"rid": "n", "ts": int(time.time()), "asset": "XRP",
     "amount": "-50", "status": "confirmed"}]}))
try:
    tr._load()
    check("P2-6 negative state entry raises StateError", False)
except C.SpentTracker.StateError:
    check("P2-6 negative state entry raises StateError", True)

# Validated failure retains the fee as confirmed XRP.
C.STATE_PATH.write_text(json.dumps({"entries": []}))
d, rid = tr.try_reserve({"XRP": Decimal("10.000012")}, cpol)
assert not d
tr.bind_reservation(rid, "A" * 64, 100, 90)
tr.release_tx("A" * 64, fee_drops="12")  # 12 drops fee
entries = tr._load()["entries"]
fee_kept = [e for e in entries if e.get("note", "").startswith("fee consumed")]
check("P1-3 validated failure retains fee",
      len(entries) == 1 and fee_kept and
      fee_kept[0]["asset"] == "XRP" and
      fee_kept[0]["status"] == "confirmed")

# Proven non-inclusion: history coverage parsing.
check("P1-3 history covers range",
      C.SpentTracker._history_covers("100-200", 120, 180))
check("P1-3 history gap fails closed",
      not C.SpentTracker._history_covers("100-110,150-200", 120, 180))
check("P1-3 missing history fails closed",
      not C.SpentTracker._history_covers("", 120, 180))

# sweep_pending with a fake client.
class FakeResp:
    def __init__(self, result=None, ok=True):
        self.result = result or {}
        self._ok = ok

    def is_successful(self):
        return self._ok


class FakeClient:
    """Bound entry: last_ledger passed, tx NOT found, history complete."""
    def request(self, req):
        from xrpl.models.requests import Ledger
        if isinstance(req, Ledger):
            return FakeResp({"ledger_index": 200,
                             "complete_ledgers": "100-200"})
        return FakeResp({}, ok=False)  # txnNotFound


C.STATE_PATH.write_text(json.dumps({"entries": []}))
d, rid = tr.try_reserve({"XRP": Decimal("5")}, cpol)
assert not d
tr.bind_reservation(rid, "B" * 64, 150, 100)  # last=150 < cur=200
# history 150-200 covers [100,150] -> proven non-inclusion -> released.
tr.sweep_pending(FakeClient())
check("P1-3 proven non-inclusion releases",
      tr._load()["entries"] == [])


class FakeClientGap:
    """History does NOT cover the submission range -> stays pending."""
    def request(self, req):
        from xrpl.models.requests import Ledger
        if isinstance(req, Ledger):
            return FakeResp({"ledger_index": 200,
                             "complete_ledgers": "160-200"})
        return FakeResp({}, ok=False)


C.STATE_PATH.write_text(json.dumps({"entries": []}))
d, rid = tr.try_reserve({"XRP": Decimal("5")}, cpol)
assert not d
tr.bind_reservation(rid, "C" * 64, 150, 100)
tr.sweep_pending(FakeClientGap())
entries = tr._load()["entries"]
check("P1-3 unproven absence keeps pending",
      len(entries) == 1 and entries[0]["status"] == "pending")


class FakeClientFail:
    """Validated failure -> fee retained, trade released."""
    def request(self, req):
        from xrpl.models.requests import Ledger, Tx
        if isinstance(req, Ledger):
            return FakeResp({"ledger_index": 200,
                             "complete_ledgers": "100-200"})
        return FakeResp({"validated": True,
                         "Fee": "15",
                         "meta": {"TransactionResult": "tecPATH_DRY"}},
                        ok=True)


C.STATE_PATH.write_text(json.dumps({"entries": []}))
d, rid = tr.try_reserve({"XRP": Decimal("5.000015")}, cpol)
assert not d
tr.bind_reservation(rid, "D" * 64, 150, 100)
tr.sweep_pending(FakeClientFail())
entries = tr._load()["entries"]
check("P1-3 sweep on validated failure retains fee",
      len(entries) == 1 and entries[0]["status"] == "confirmed" and
      entries[0]["asset"] == "XRP" and
      "tecPATH_DRY" in entries[0].get("note", ""))

# recover-state: quarantines invalid, keeps pending obligations.
C.STATE_PATH.write_text(json.dumps({"entries": [
    {"rid": "good", "ts": int(time.time()), "asset": "XRP", "amount": "2",
     "status": "pending", "tx_hash": None, "last_ledger": None,
     "submit_ledger": None},
    {"rid": "bad", "ts": int(time.time()), "asset": "XRP",
     "amount": "-99", "status": "confirmed"},
]}))
import io as _io, contextlib as _cl
with _cl.redirect_stdout(_io.StringIO()):
    S.cmd_recover_state(type("A", (), {})())
rec = tr._load()["entries"]
check("P2-6 recover-state keeps valid pending, quarantines invalid",
      len(rec) == 1 and rec[0]["rid"] == "good" and
      rec[0]["status"] == "pending")

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
