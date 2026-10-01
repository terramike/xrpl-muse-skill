#!/usr/bin/env python3
"""v0.14.1 regression tests: spend-state recovery (audit finding #1).

The spend tracker must NEVER silently reset limits. A corrupt state file
fails closed; `xrpl-sign recover-state` rebuilds accounting from the
audit log (latest outcome per tx_hash wins); when nothing trustworthy
can be rebuilt, signing stays BLOCKED until the operator reconciles
manually and attests — and the attestation itself is audit-logged.

No network. Run: python3 -m unittest tests.test_recovery
"""
import io
import json
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from decimal import Decimal
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))

import importlib.util


def _load(path, name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


C = _load(BIN / "xrpl_common.py", "xrpl_common")
S = _load(BIN / "xrpl-sign", "xrpl_sign_recovery")

NOW = int(time.time())


def audit_entry(tx_hash, result, spends, ts=NOW, note=""):
    e = {"ts": ts, "action": "buy", "proposal_hash": "p" * 64,
         "tx_hash": tx_hash, "network": "testnet", "account": "rX",
         "result": result, "note": note}
    if spends:
        e["spends"] = {k: str(v) for k, v in spends.items()}
    return e


class Args:
    def __init__(self, attest=None):
        self.attest = attest


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = (C.STATE_PATH, C.STATE_LOCK_PATH, C.AUDIT_PATH)
        C.STATE_PATH = self.tmp / "spend_state.json"
        C.STATE_LOCK_PATH = self.tmp / "spend_state.lock"
        C.AUDIT_PATH = self.tmp / "audit.log"

    def tearDown(self):
        C.STATE_PATH, C.STATE_LOCK_PATH, C.AUDIT_PATH = self._orig

    def write_audit(self, entries):
        C.AUDIT_PATH.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n")

    def write_state(self, obj):
        C.STATE_PATH.write_text(json.dumps(obj))

    # --- reconstruction rules ---

    def test_latest_outcome_per_tx_wins(self):
        th = "A" * 64
        self.write_audit([
            audit_entry(th, "signed", {"XRP": "10"}, ts=NOW - 100),
            audit_entry(th, "applied", {"XRP": "10"}, ts=NOW - 50),
        ])
        entries, n = S._reconstruct_entries_from_audit_log(NOW)
        self.assertEqual(n, 1)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "confirmed")
        self.assertEqual(entries[0]["amount"], "10")

    def test_signed_and_submit_error_stay_pending(self):
        self.write_audit([
            audit_entry("B" * 64, "signed", {"XRP": "5"}),
            audit_entry("C" * 64, "submit_error", {"XRP": "3"}),
        ])
        entries, _ = S._reconstruct_entries_from_audit_log(NOW)
        by_hash = {e["tx_hash"]: e for e in entries}
        self.assertEqual(by_hash["B" * 64]["status"], "pending")
        self.assertEqual(by_hash["C" * 64]["status"], "pending")
        self.assertEqual(by_hash["B" * 64]["amount"], "5")

    def test_old_format_failed_entry_skipped(self):
        # pre-v0.14.1 failed entries recorded full trade amounts with no
        # fee-retained marker: the fee is unknowable, the trade was
        # released — counting either would be wrong.
        self.write_audit([
            audit_entry("D" * 64, "failed:tecPATH_DRY",
                        {"XRP": "10"}, note=""),
        ])
        entries, n = S._reconstruct_entries_from_audit_log(NOW)
        self.assertEqual(n, 1)
        self.assertEqual(entries, [])

    def test_fee_retained_failed_entry_confirmed(self):
        # current failed entries are fee-only: the live path keeps the
        # consumed fee as a confirmed XRP spend, recovery must match.
        self.write_audit([
            audit_entry("E" * 64, "failed:tecPATH_DRY", {"XRP": "0.00001"},
                        note="fee-retained: attempted spends {'XRP': '10'} "
                             "released, consumed fee 0.00001 XRP kept"),
        ])
        entries, _ = S._reconstruct_entries_from_audit_log(NOW)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "confirmed")
        self.assertEqual(entries[0]["amount"], "0.00001")
        self.assertEqual(entries[0]["asset"], "XRP")

    def test_applied_ages_out_of_window(self):
        self.write_audit([
            audit_entry("F" * 64, "applied", {"XRP": "10"},
                        ts=NOW - C.ROLLING_WINDOW - 1),
        ])
        entries, _ = S._reconstruct_entries_from_audit_log(NOW)
        self.assertEqual(entries, [])

    def test_malformed_audit_lines_skipped_not_fatal(self):
        self.write_audit([])
        with open(C.AUDIT_PATH, "a") as f:
            f.write("not json\n")
            f.write(json.dumps(audit_entry("G" * 64, "applied",
                                           {"XRP": "7"})) + "\n")
        entries, _ = S._reconstruct_entries_from_audit_log(NOW)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["amount"], "7")

    # --- blocking and attestation ---

    def test_missing_audit_log_blocks_signing(self):
        self.write_state({"entries": [{"rid": "x"}]})  # garbage shape
        C.STATE_PATH.write_text("{corrupt")
        with redirect_stdout(io.StringIO()):
            S.cmd_recover_state(Args())
        st = json.loads(C.STATE_PATH.read_text())
        self.assertTrue(st.get("blocked"))
        tr = C.SpentTracker()
        with self.assertRaises(C.SpentTracker.StateError) as ctx:
            tr.check({"XRP": Decimal("1")}, self._policy())
        self.assertIn("BLOCKED", str(ctx.exception))

    def test_blocked_state_reported_not_reset(self):
        self.write_state({"entries": [], "blocked": True,
                          "blocked_reason": "audit log unreadable"})
        tr = C.SpentTracker()
        with self.assertRaises(C.SpentTracker.StateError) as ctx:
            tr.try_reserve({"XRP": Decimal("1")}, self._policy())
        msg = str(ctx.exception)
        self.assertIn("BLOCKED", msg)
        self.assertIn("recover-state", msg)

    def test_attestation_clears_block_and_is_audited(self):
        self.write_state({"entries": [], "blocked": True,
                          "blocked_reason": "audit log unreadable"})
        with redirect_stdout(io.StringIO()):
            S.cmd_recover_state(
                Args(attest="reviewed ledgers 1-100, 0 spends found"))
        st = json.loads(C.STATE_PATH.read_text())
        self.assertFalse(st.get("blocked"))
        self.assertEqual(st.get("entries"), [])
        audit_lines = C.AUDIT_PATH.read_text().strip().splitlines()
        att = [json.loads(l) for l in audit_lines
               if json.loads(l).get("action") == "recover_state"
               and json.loads(l).get("result") == "attested"]
        self.assertEqual(len(att), 1)
        self.assertIn("reviewed ledgers 1-100", att[0]["note"])

    def test_attest_on_healthy_state_changes_nothing(self):
        self.write_state({"entries": []})
        with redirect_stdout(io.StringIO()) as buf:
            S.cmd_recover_state(Args(attest="oops"))
        self.assertIn("nothing to attest", buf.getvalue())
        self.assertEqual(json.loads(C.STATE_PATH.read_text())["entries"],
                         [])

    # --- quarantine ---

    def test_invalid_status_becomes_pending_hold(self):
        # an entry with an unrecognized status must keep counting toward
        # limits (pending hold), never vanish from accounting.
        self.write_state({"entries": [
            {"rid": "weird", "ts": NOW, "asset": "XRP", "amount": "4",
             "status": "mystery", "tx_hash": None, "last_ledger": None,
             "submit_ledger": None}]})
        with redirect_stdout(io.StringIO()):
            S.cmd_recover_state(Args())
        st = json.loads(C.STATE_PATH.read_text())
        self.assertEqual(len(st["entries"]), 1)
        hold = st["entries"][0]
        self.assertEqual(hold["status"], "pending")
        self.assertEqual(hold["amount"], "4")
        self.assertTrue(hold.get("quarantined"))
        # and it counts: a 4 XRP hold blocks a 7 XRP reservation
        # against a 10 XRP cap
        tr = C.SpentTracker()
        denied, _ = tr.try_reserve({"XRP": Decimal("7")}, self._policy(10))
        self.assertTrue(denied)

    def test_corrupt_amount_rebuilds_from_audit_log(self):
        self.write_state({"entries": [
            {"rid": "bad", "ts": NOW, "asset": "XRP",
             "amount": "not-a-number", "status": "confirmed"}]})
        self.write_audit([
            audit_entry("H" * 64, "applied", {"XRP": "2"}),
        ])
        with redirect_stdout(io.StringIO()):
            S.cmd_recover_state(Args())
        st = json.loads(C.STATE_PATH.read_text())
        self.assertFalse(st.get("blocked"))
        self.assertEqual(len(st["entries"]), 1)
        self.assertEqual(st["entries"][0]["amount"], "2")
        self.assertEqual(st["entries"][0]["status"], "confirmed")

    def test_full_recovery_roundtrip(self):
        # end to end: corrupt state + audit log -> reconstructed state
        # that enforces limits
        self.write_state({"entries": "garbage"})
        self.write_audit([
            audit_entry("I" * 64, "applied", {"XRP": "10"}),
            audit_entry("J" * 64, "signed", {"XRP": "5"}),
        ])
        with redirect_stdout(io.StringIO()):
            S.cmd_recover_state(Args())
        tr = C.SpentTracker()
        # 10 confirmed + 5 pending = 15 of a 20 cap: 6 more is denied
        denied, _ = tr.try_reserve({"XRP": Decimal("6")}, self._policy(20))
        self.assertTrue(denied)
        denied, _ = tr.try_reserve({"XRP": Decimal("4")}, self._policy(20))
        self.assertFalse(denied)

    @staticmethod
    def _policy(cap="1000000"):
        return {"spend_limits": {"XRP": {"per_tx": cap, "per_day": cap}},
                "allowed_tx_types": ["Payment"]}


if __name__ == "__main__":
    unittest.main()
