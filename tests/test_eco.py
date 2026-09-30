#!/usr/bin/env python3
"""Ecosystem connector tests — no network (all HTTP mocked).

Covers: validator-list decode + ripple-time, amendments grouping,
XRPL Meta second-opinion lines, OnTheDEX error-envelope handling,
and fail-open behavior everywhere.
Run: python3 -m unittest tests.test_eco
"""
import base64
import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


eco = load(BIN / "xrpl_eco.py", "xrpl_eco")


def fake_vl(sequence=85, n_validators=35, expires_in_days=200):
    blob = {
        "sequence": sequence,
        "expiration": int(time.time() - eco.RIPPLE_EPOCH
                           + expires_in_days * 86400),
        "validators": [{"validation_public_key": f"KEY{i:02d}",
                        "manifest": f"M{i:02d}"}
                       for i in range(n_validators)],
    }
    return {"public_key": "PUB", "manifest": "MAN", "version": 1,
            "signature": "SIG",
            "blob": base64.b64encode(json.dumps(blob).encode()).decode()}


FEATURES = {
    "id-enabled": {"name": "FixA", "enabled": True, "supported": True},
    "id-voting": {"name": "FixB", "enabled": False, "supported": True},
    "id-blocked": {"name": "FixC", "enabled": True, "supported": False},
}


class TestCurrencyHex(unittest.TestCase):
    def test_three_char_passthrough(self):
        self.assertEqual(eco.currency_to_hex("XRP"), "XRP")
        self.assertEqual(eco.currency_to_hex("USD"), "USD")

    def test_five_char_goes_hex(self):
        h = eco.currency_to_hex("RLUSD")
        self.assertEqual(len(h), 40)
        self.assertTrue(h.startswith("524C555344"))  # "RLUSD" in hex

    def test_long_name_hex(self):
        h = eco.currency_to_hex("FUZZY")
        self.assertEqual(len(h), 40)
        self.assertEqual(h, h.upper())
        self.assertTrue(h.startswith("46555A5A59"))  # "FUZZY" in hex


class TestValidators(unittest.TestCase):
    def test_decode_and_format(self):
        with mock.patch.object(eco, "_http_get_json",
                               return_value=fake_vl()), \
             mock.patch.object(eco, "_write_seen", lambda d: None), \
             mock.patch.object(eco, "_read_seen", return_value={}):
            lines = eco.format_validators()
        text = "\n".join(lines)
        self.assertIn("35 validators", text)
        self.assertIn("sequence 85", text)
        self.assertIn("expires in 200d", text)

    def test_expiry_warning(self):
        with mock.patch.object(eco, "_http_get_json",
                               return_value=fake_vl(expires_in_days=10)), \
             mock.patch.object(eco, "_write_seen", lambda d: None), \
             mock.patch.object(eco, "_read_seen", return_value={}):
            text = "\n".join(eco.format_validators())
        self.assertIn("EXPIRES SOON", text)

    def test_membership_change_noted(self):
        seen = {"xrplf": {"sequence": 84, "count": 35},
                "ripple": {"sequence": 84, "count": 35}}
        with mock.patch.object(eco, "_http_get_json",
                               return_value=fake_vl(sequence=85)), \
             mock.patch.object(eco, "_write_seen", lambda d: None), \
             mock.patch.object(eco, "_read_seen", return_value=seen):
            text = "\n".join(eco.format_validators())
        self.assertIn("membership changed", text)

    def test_fail_open(self):
        with mock.patch.object(eco, "_http_get_json",
                               side_effect=RuntimeError("down")):
            text = "\n".join(eco.format_validators())
        self.assertIn("unreachable", text)


class TestAmendments(unittest.TestCase):
    def _mock(self, majorities):
        def post(url, payload):
            if payload.get("method") == "feature":
                return {"result": {"features": FEATURES,
                                   "ledger_index": 999}}
            return {"result": {"info": {"amendments":
                                        {"majorities": majorities}}}}
        return post

    def test_grouping(self):
        maj = [{"amendment": "id-voting", "count": 30,
                "since_ledger": 100}]
        with mock.patch.object(eco, "_http_post_json",
                               side_effect=self._mock(maj)):
            text = "\n".join(eco.format_amendments())
        self.assertIn("in voting (1)", text)
        self.assertIn("FixB", text)
        self.assertIn("enabled: 2 of 3", text)
        self.assertIn("majority countdown", text)
        self.assertIn("30/35", text)

    def test_blocked_alert(self):
        with mock.patch.object(eco, "_http_post_json",
                               side_effect=self._mock([])):
            text = "\n".join(eco.format_amendments())
        self.assertIn("AMENDMENT-BLOCKED RISK", text)
        self.assertIn("FixC", text)

    def test_fail_open(self):
        with mock.patch.object(eco, "_http_post_json",
                               side_effect=RuntimeError("down")):
            text = "\n".join(eco.format_amendments())
        self.assertIn("unavailable", text)


class TestXrplMeta(unittest.TestCase):
    REC = {"currency": "RLUSD",
           "issuer": "rIssuer",
           "meta": {"token": {"name": "Ripple USD", "trust_level": 5},
                    "issuer": {"name": "Ripple", "kyc": True,
                               "domain": "ripple.com"}},
           "metrics": {"holders": 1000, "trustlines": 2000,
                       "price": "1.0"}}

    def test_lines(self):
        with mock.patch.object(eco, "xrplmeta_lookup",
                               return_value=self.REC):
            lines = eco.format_xrplmeta_lines("RLUSD", "rIssuer")
        text = "\n".join(lines)
        self.assertIn("xrplmeta.org", text)
        self.assertIn("Ripple", text)
        self.assertIn("KYC'd", text)
        self.assertIn("trust_level: 5/5 (publisher opinion", text)
        self.assertIn("holders: 1,000", text)

    def test_unavailable_returns_empty(self):
        with mock.patch.object(eco, "xrplmeta_lookup", return_value=None):
            self.assertEqual(eco.format_xrplmeta_lines("X", "rY"), [])


class TestOnTheDex(unittest.TestCase):
    def test_error_envelope_returns_none(self):
        with mock.patch.object(eco, "_http_get_json",
                               return_value={"error": "ERROR_MAINTENANCE",
                                             "message": "down"}):
            self.assertIsNone(eco.onthedex_get("/ticker"))

    def test_exception_returns_none(self):
        with mock.patch.object(eco, "_http_get_json",
                               side_effect=RuntimeError("down")):
            self.assertIsNone(eco.onthedex_get("/ticker"))
            self.assertIsNone(eco.format_onthedex_note())

    def test_live_note(self):
        with mock.patch.object(eco, "onthedex_get",
                               return_value={"A": 1, "B": 2}):
            note = eco.format_onthedex_note()
        self.assertIn("OnTheDEX cross-check: live", note)


if __name__ == "__main__":
    unittest.main()
