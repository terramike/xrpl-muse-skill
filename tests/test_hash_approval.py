#!/usr/bin/env python3
"""v0.14.1 regression tests: exact full proposal hash approval (audit finding #4).

--approve requires EXACTLY 64 hex characters matching the verified
proposal envelope. Prefixes are inspection-only and can never select a
signing target. Inspection glob metacharacters are escaped and treated
literally. The CLI hash comparison is case-insensitive against the
verified envelope hash. The ceremony and giveaway commands display the
COMPLETE hash. require_full_hash_for_approve refuses with a re-runnable
command carrying the complete hash. load_proposal_exact refuses
prefixes before touching the filesystem.

No network. Run: python3 -m unittest tests.test_hash_approval
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))


def _load(path, name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


C = _load(BIN / "xrpl_common.py", "xrpl_common_hash")

FULL = "a" * 64
FULL_UPPER = "A" * 64


class HashApprovalTest(unittest.TestCase):
    def test_exact_64_hex_accepted(self):
        self.assertTrue(C.is_full_proposal_hash(FULL))
        self.assertTrue(C.is_full_proposal_hash(FULL_UPPER))
        self.assertTrue(C.is_full_proposal_hash("9f" * 32))

    def test_prefix_rejected(self):
        self.assertFalse(C.is_full_proposal_hash("a" * 16))
        self.assertFalse(C.is_full_proposal_hash("a" * 63))
        self.assertFalse(C.is_full_proposal_hash(""))

    def test_non_hex_rejected(self):
        self.assertFalse(C.is_full_proposal_hash("z" * 64))
        self.assertFalse(C.is_full_proposal_hash("a" * 63 + " "))
        self.assertFalse(C.is_full_proposal_hash(None))
        self.assertFalse(C.is_full_proposal_hash(123))

    def test_require_full_hash_matches_case_insensitive(self):
        prop = {"proposal_hash": FULL}
        self.assertIsNone(C.require_full_hash_for_approve(FULL, prop))
        self.assertIsNone(C.require_full_hash_for_approve(FULL_UPPER, prop))

    def test_require_full_hash_refuses_prefix_with_rerunnable(self):
        prop = {"proposal_hash": FULL}
        with self.assertRaises(SystemExit) as ctx:
            C.require_full_hash_for_approve("a" * 16, prop)
        msg = str(ctx.exception)
        self.assertIn("FULL 64-character", msg)
        self.assertIn(FULL, msg)  # re-runnable command carries the hash

    def test_require_full_hash_refuses_mismatch(self):
        prop = {"proposal_hash": FULL}
        with self.assertRaises(SystemExit) as ctx:
            C.require_full_hash_for_approve("b" * 64, prop)
        msg = str(ctx.exception)
        self.assertIn("does not match", msg)
        self.assertIn(FULL, msg)

    def test_load_proposal_exact_refuses_prefix(self):
        with self.assertRaises(SystemExit) as ctx:
            C.load_proposal_exact("a" * 16)
        self.assertIn("COMPLETE 64-character", str(ctx.exception))

    def test_load_proposal_exact_loads_by_hash(self):
        with tempfile.TemporaryDirectory() as d:
            orig = C.PROPOSALS_DIR
            C.PROPOSALS_DIR = Path(d)
            try:
                (Path(d) / f"{FULL}.json").write_text(
                    json.dumps({"proposal_hash": FULL}))
                prop, path = C.load_proposal_exact(FULL_UPPER)
                self.assertEqual(prop["proposal_hash"], FULL)
                self.assertTrue(str(path).endswith(".json"))
            finally:
                C.PROPOSALS_DIR = orig

    def test_load_proposal_exact_missing_hash(self):
        with tempfile.TemporaryDirectory() as d:
            orig = C.PROPOSALS_DIR
            C.PROPOSALS_DIR = Path(d)
            try:
                with self.assertRaises(SystemExit) as ctx:
                    C.load_proposal_exact(FULL)
                self.assertIn("No proposal with hash", str(ctx.exception))
            finally:
                C.PROPOSALS_DIR = orig

    def test_inspection_glob_chars_are_literal(self):
        # '*' must not act as a wildcard: looking up the literal prefix
        # "ab*cd" must find ONLY the file literally named ab*cd…, never
        # the abZZcd… file (which a wildcard would also match, making the
        # lookup ambiguous).
        with tempfile.TemporaryDirectory() as d:
            orig = C.PROPOSALS_DIR
            C.PROPOSALS_DIR = Path(d)
            try:
                (Path(d) / ("ab*cd" + "x" * 59 + ".json")).write_text(
                    json.dumps({"name": "literal"}))
                (Path(d) / ("abZZcd" + "x" * 59 + ".json")).write_text(
                    json.dumps({"name": "wildcard-bait"}))
                prop, _ = C.load_proposal("ab*cd")
                self.assertEqual(prop["name"], "literal")
            finally:
                C.PROPOSALS_DIR = orig

    def test_inspection_prefix_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            orig = C.PROPOSALS_DIR
            C.PROPOSALS_DIR = Path(d)
            try:
                (Path(d) / f"{FULL}.json").write_text(
                    json.dumps({"proposal_hash": FULL}))
                prop, _ = C.load_proposal(FULL[:12])
                self.assertEqual(prop["proposal_hash"], FULL)
            finally:
                C.PROPOSALS_DIR = orig

    def test_giveaway_sign_command_uses_complete_hash(self):
        cmd = C.giveaway_sign_command(FULL)
        self.assertIn(FULL, cmd)
        self.assertIn("--approve", cmd)
        # a prefix must never appear as the approval hash
        self.assertNotIn(FULL[:16] + " ", cmd.replace(FULL, ""))


if __name__ == "__main__":
    unittest.main()
