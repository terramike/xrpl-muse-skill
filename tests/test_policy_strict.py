#!/usr/bin/env python3
"""v0.14.1 regression tests: strict policy validation (audit finding #3).

load_policy must reject hostile or malformed policy files BEFORE they
are used: unknown keys, wrong types (the string "false" is truthy — a
classic bypass), non-finite limits, bad addresses/tags, invalid ranges,
unsupported transaction types, and invalid NFT fields. spend_limits is
REQUIRED. The giveaway variant's two extra keys must be JSON booleans.
validate_policy returns the valid policy unchanged. provisional_spend_check
validates the RAW policy before limit math and fails closed on corrupt
spend state.

No network. Run: python3 -m unittest tests.test_policy_strict
"""
import copy
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


C = _load(BIN / "xrpl_common.py", "xrpl_common")
T = _load(BIN / "xrpl-trade", "xrpl_trade_policy")


def valid_policy():
    p = copy.deepcopy(C.DEFAULT_POLICY)
    p.pop("giveaway", None)
    p.pop("allow_any_payment_destination", None)
    return p


class PolicyStrictTest(unittest.TestCase):
    def test_valid_policy_returns_unchanged(self):
        p = valid_policy()
        self.assertIs(C.validate_policy(p), p)

    def test_unknown_key_rejected(self):
        p = valid_policy()
        p["evil_backdoor"] = True
        with self.assertRaises(C.PolicyError) as ctx:
            C.validate_policy(p)
        self.assertIn("unknown policy key", str(ctx.exception))

    def test_missing_spend_limits_rejected(self):
        p = valid_policy()
        del p["spend_limits"]
        with self.assertRaises(C.PolicyError) as ctx:
            C.validate_policy(p)
        self.assertIn("spend_limits", str(ctx.exception))

    def test_truthy_string_false_rejected(self):
        # the string "false" is truthy — accepting it would enable the
        # buy side / allowlist bypass the operator thought was off.
        p = valid_policy()
        p["giveaway"] = "false"
        with self.assertRaises(C.PolicyError) as ctx:
            C.validate_policy(p)
        self.assertIn("JSON boolean", str(ctx.exception))

    def test_giveaway_keys_accept_booleans(self):
        p = valid_policy()
        p["giveaway"] = True
        p["allow_any_payment_destination"] = False
        self.assertIs(C.validate_policy(p), p)

    def test_nonfinite_limit_rejected(self):
        for bad in ("NaN", "Infinity", "-Infinity"):
            p = valid_policy()
            p["spend_limits"]["XRP"]["per_tx"] = bad
            with self.assertRaises(C.PolicyError, msg=bad):
                C.validate_policy(p)

    def test_float_limit_rejected(self):
        p = valid_policy()
        p["spend_limits"]["XRP"]["per_tx"] = 25.5
        with self.assertRaises(C.PolicyError):
            C.validate_policy(p)

    def test_bool_limit_rejected(self):
        p = valid_policy()
        p["max_fee_drops"] = True
        with self.assertRaises(C.PolicyError):
            C.validate_policy(p)

    def test_bad_allowlist_address_rejected(self):
        p = valid_policy()
        p["destination_allowlist"] = [{"address": "not-an-address"}]
        with self.assertRaises(C.PolicyError):
            C.validate_policy(p)

    def test_bad_destination_tag_rejected(self):
        p = valid_policy()
        p["destination_allowlist"] = [{
            "address": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
            "destination_tag": "seven"}]
        with self.assertRaises(C.PolicyError):
            C.validate_policy(p)

    def test_unsupported_tx_type_rejected(self):
        p = valid_policy()
        p["allowed_tx_types"] = ["Payment", "EvilType"]
        with self.assertRaises(C.PolicyError):
            C.validate_policy(p)

    def test_invalid_nft_mint_flag_rejected(self):
        # bit 16 is not a real NFTokenMint flag; only 1, 2, 4, 8 allowed
        p = valid_policy()
        p["nft"]["allowed_mint_flags"] = [16]
        with self.assertRaises(C.PolicyError) as ctx:
            C.validate_policy(p)
        self.assertIn("(1,2,4,8)", str(ctx.exception))

    def test_valid_nft_mint_flags_accepted(self):
        p = valid_policy()
        p["nft"]["allowed_mint_flags"] = [1, 2, 4, 8]
        self.assertIs(C.validate_policy(p), p)

    def test_non_dict_rejected(self):
        with self.assertRaises(C.PolicyError):
            C.validate_policy(["not", "a", "dict"])

    def test_load_policy_reports_schema_violation(self):
        p = valid_policy()
        p["mystery_key"] = 1
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "policy.json"
            fp.write_text(json.dumps(p))
            with self.assertRaises(SystemExit) as ctx:
                C.load_policy(fp)
            self.assertIn("policy schema violation", str(ctx.exception))

    def test_provisional_spend_check_validates_raw_policy(self):
        # a hostile raw policy must be refused before limit math runs:
        # best-effort here means a clean note, never a proposal built
        # on schema-violating limits (the signer hard-refuses later).
        from decimal import Decimal
        from io import StringIO
        from contextlib import redirect_stdout
        bad = valid_policy()
        bad["spend_limits"]["XRP"]["per_tx"] = "NaN"
        with tempfile.TemporaryDirectory() as d:
            orig_p, orig_s = C.POLICY_PATH, C.STATE_PATH
            C.POLICY_PATH = Path(d) / "policy.json"
            C.STATE_PATH = Path(d) / "spend_state.json"
            try:
                C.POLICY_PATH.write_text(json.dumps(bad))
                buf = StringIO()
                with redirect_stdout(buf):
                    T.provisional_spend_check({"XRP": Decimal("1")})
                self.assertIn("fails schema validation", buf.getvalue())
            finally:
                C.POLICY_PATH, C.STATE_PATH = orig_p, orig_s

    def test_provisional_spend_check_fails_closed_on_corrupt_state(self):
        from decimal import Decimal
        with tempfile.TemporaryDirectory() as d:
            orig_p, orig_s = C.POLICY_PATH, C.STATE_PATH
            C.POLICY_PATH = Path(d) / "policy.json"
            C.STATE_PATH = Path(d) / "spend_state.json"
            try:
                C.POLICY_PATH.write_text(json.dumps(valid_policy()))
                C.STATE_PATH.write_text("{corrupt")
                with self.assertRaises(SystemExit) as ctx:
                    T.provisional_spend_check({"XRP": Decimal("1")})
                self.assertIn("spend state", str(ctx.exception))
            finally:
                C.POLICY_PATH, C.STATE_PATH = orig_p, orig_s


if __name__ == "__main__":
    unittest.main()
