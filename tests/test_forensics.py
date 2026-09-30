#!/usr/bin/env python3
"""Forensic light-mode tests — no network (RPC layer mocked).

Covers: counterparty extraction per tx type, funding-of logic, trace
chain assembly + depth cap + fail-open, links assembly (shared
counterparty/issuer/control overlap) + window cap, the "owner"-never-
appears language rule, and the 1h file cache.
Run: python3 -m unittest tests.test_forensics
"""
import importlib.util
import re
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
fx = load(BIN / "xrpl_forensics.py", "xrpl_forensics")


def addr(ch):
    return "r" + ch * 25


A, B, C = addr("A"), addr("B"), addr("C")
FUNDER1, FUNDER2 = addr("F"), addr("G")
ISSUER = addr("I")
REGKEY = addr("R")


def pay_tx(sender, dest, drops="25000000", ledger=100, h="H" * 16):
    return {"Account": sender, "Destination": dest,
            "TransactionType": "Payment", "Amount": drops,
            "ledger_index": ledger, "hash": h,
            "meta": {"delivered_amount": drops}}


def tx_page(txs):
    return {"transactions": [{"tx": t, "validated": True} for t in txs]}


class ExtractTest(unittest.TestCase):
    def test_payment_out(self):
        cps, offers, dex = fx.extract_counterparties(pay_tx(A, B), A)
        self.assertEqual(cps, {B})
        self.assertFalse(dex)

    def test_payment_in(self):
        cps, _, _ = fx.extract_counterparties(pay_tx(B, A), A)
        self.assertEqual(cps, {B})

    def test_payment_unrelated(self):
        cps, _, _ = fx.extract_counterparties(pay_tx(B, C), A)
        self.assertEqual(cps, set())

    def test_trustset_out(self):
        tx = {"Account": A, "TransactionType": "TrustSet",
              "LimitAmount": {"currency": "USD", "issuer": ISSUER,
                              "value": "100"}}
        cps, _, _ = fx.extract_counterparties(tx, A)
        self.assertEqual(cps, {ISSUER})

    def test_trustset_in(self):
        tx = {"Account": B, "TransactionType": "TrustSet",
              "LimitAmount": {"currency": "USD", "issuer": A, "value": "5"}}
        cps, _, _ = fx.extract_counterparties(tx, A)
        self.assertEqual(cps, {B})

    def test_escrow_create(self):
        tx = {"Account": A, "Destination": B, "TransactionType":
              "EscrowCreate"}
        cps, _, _ = fx.extract_counterparties(tx, A)
        self.assertEqual(cps, {B})

    def test_escrow_finish(self):
        tx = {"Account": A, "Owner": B, "TransactionType": "EscrowFinish"}
        cps, _, _ = fx.extract_counterparties(tx, A)
        self.assertEqual(cps, {B})

    def test_nft_offer_indexes_collected(self):
        tx = {"Account": A, "TransactionType": "NFTokenAcceptOffer",
              "NFTokenSellOffer": "IDX1"}
        cps, offers, _ = fx.extract_counterparties(tx, A)
        self.assertEqual(offers, ["IDX1"])
        self.assertEqual(cps, set())

    def test_offer_create_is_dex_only(self):
        tx = {"Account": A, "TransactionType": "OfferCreate"}
        cps, offers, dex = fx.extract_counterparties(tx, A)
        self.assertTrue(dex)
        self.assertEqual(cps, set())

    def test_accountset_nothing(self):
        tx = {"Account": A, "TransactionType": "AccountSet"}
        cps, offers, dex = fx.extract_counterparties(tx, A)
        self.assertEqual((cps, offers, dex), (set(), [], False))


class FundingOfTest(unittest.TestCase):
    def test_inbound_payment(self):
        self.assertEqual(fx.funding_of(pay_tx(FUNDER1, A), A), FUNDER1)

    def test_outbound_payment_not_funding(self):
        self.assertIsNone(fx.funding_of(pay_tx(A, FUNDER1), A))

    def test_non_payment_birth(self):
        tx = {"Account": A, "TransactionType": "OfferCreate",
              "ledger_index": 1, "hash": "H"}
        self.assertIsNone(fx.funding_of(tx, A))

    def test_self_send_not_funding(self):
        self.assertIsNone(fx.funding_of(pay_tx(A, A), A))


def make_rpc(first_map, info_map=None, objs_map=None):
    """Fake _rpc: first_map[account] -> birth tx; info/objs per account."""
    info_map = info_map or {}
    objs_map = objs_map or {}

    def fake(method, params):
        if method == "account_tx":
            acct = params["account"]
            tx = first_map.get(acct)
            if params.get("forward"):
                return tx_page([tx] if tx else [])
            return tx_page([])
        if method == "account_info":
            return {"account_data": info_map.get(params["account"], {})}
        if method == "account_objects":
            return {"account_objects": objs_map.get(params["account"], [])}
        if method == "ledger":
            return {"ledger": {"close_time": 800000000}}
        if method == "account_lines":
            return {"lines": []}
        if method == "ledger_entry":
            return {"node": {"LedgerEntryType": "NFTokenOffer",
                             "Account": FUNDER1}}
        raise AssertionError(f"unexpected {method}")
    return fake


class TraceTest(unittest.TestCase):
    def setUp(self):
        # A <- FUNDER1 <- FUNDER2 <- (birth is OfferCreate: chain ends)
        self.first = {
            A: pay_tx(FUNDER1, A, ledger=100),
            FUNDER1: pay_tx(FUNDER2, FUNDER1, ledger=50),
            FUNDER2: {"Account": FUNDER2, "TransactionType": "OfferCreate",
                      "ledger_index": 10, "hash": "H" * 16},
        }

    def test_two_hop_chain(self):
        with mock.patch.object(fx, "_rpc", make_rpc(self.first)):
            lines = fx.format_trace(A, depth=2, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("Hop 0", text)
        self.assertIn("Hop 1", text)
        self.assertIn("Hop 2", text)
        self.assertIn(FUNDER1, text)
        self.assertIn(FUNDER2, text)
        self.assertIn("LINK:", text)
        self.assertIn("not an inbound Payment, chain ends here", text)

    def test_depth_capped_at_three(self):
        with mock.patch.object(fx, "_rpc", make_rpc(self.first)):
            lines = fx.format_trace(A, depth=99, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("≤16 RPC calls", text)  # (3+1 hops) * 4
        self.assertNotIn("Hop 4", text)

    def test_no_history(self):
        with mock.patch.object(fx, "_rpc", make_rpc({})):
            lines = fx.format_trace(A, use_cache=False)
        self.assertIn("no on-ledger history",
                      "\n".join(lines))

    def test_invalid_address(self):
        lines = fx.format_trace("not-an-address", use_cache=False)
        self.assertIn("not a valid XRPL classic address",
                      "\n".join(lines))

    def test_rpc_down_fails_open(self):
        def boom(method, params):
            raise RuntimeError("down")
        with mock.patch.object(fx, "_rpc", boom):
            lines = fx.format_trace(A, use_cache=False)  # must not raise
        self.assertIn("unavailable", "\n".join(lines))

    def test_owner_never_appears(self):
        with mock.patch.object(fx, "_rpc", make_rpc(self.first)):
            lines = fx.format_trace(A, depth=2, use_cache=False)
        for ln in lines:
            # standalone "owner"/"owners" banned; "ownership" in a
            # disclaimer ("not ownership") is the discipline working
            self.assertIsNone(re.search(r"\bowners?\b", ln.lower()))


class LinksTest(unittest.TestCase):
    def setUp(self):
        # A and B both paid C; both trust ISSUER; both share REGKEY.
        self.first = {}
        self.a_txs = [pay_tx(A, C, ledger=200), pay_tx(A, B, ledger=199)]
        self.b_txs = [pay_tx(C, B, ledger=201), pay_tx(B, A, ledger=198)]

        def fake(method, params):
            if method == "account_tx":
                acct = params["account"]
                if acct == A:
                    return tx_page(self.a_txs)
                if acct == B:
                    return tx_page(self.b_txs)
                return tx_page([])
            if method == "account_info":
                return {"account_data": {"Account": params["account"],
                                         "RegularKey": REGKEY}}
            if method == "account_objects":
                return {"account_objects": []}
            if method == "account_lines":
                return {"lines": [{"account": ISSUER}]}
            raise AssertionError(method)
        self.fake = fake

    def test_shared_counterparty_and_issuer_and_regkey(self):
        with mock.patch.object(fx, "_rpc", self.fake):
            lines = fx.format_links(A, B, window=200, use_cache=False)
        text = "\n".join(lines)
        self.assertIn(f"LINK: {C} — A: 1 txs, B: 1 txs", text)
        self.assertIn(f"LINK: {ISSUER}", text)
        self.assertIn(f"LINK: same RegularKey {REGKEY}", text)
        self.assertIn("exchange hot wallet", text)  # caveat present

    def test_window_capped(self):
        with mock.patch.object(fx, "_rpc", self.fake):
            lines = fx.format_links(A, B, window=9999, use_cache=False)
        self.assertIn("window: 500 most recent", "\n".join(lines))

    def test_same_address_rejected(self):
        lines = fx.format_links(A, A, use_cache=False)
        self.assertIn("two different addresses", "\n".join(lines))

    def test_bad_address_rejected(self):
        lines = fx.format_links(A, "nope", use_cache=False)
        self.assertIn("must be valid XRPL classic addresses",
                      "\n".join(lines))

    def test_owner_never_appears(self):
        with mock.patch.object(fx, "_rpc", self.fake):
            lines = fx.format_links(A, B, use_cache=False)
        for ln in lines:
            # standalone "owner"/"owners" banned; "ownership" in a
            # disclaimer ("not ownership") is the discipline working
            self.assertIsNone(re.search(r"\bowners?\b", ln.lower()))

    def test_rpc_down_fails_open(self):
        def boom(method, params):
            raise RuntimeError("down")
        with mock.patch.object(fx, "_rpc", boom):
            lines = fx.format_links(A, B, use_cache=False)
        self.assertIn("partial", "\n".join(lines))


class CacheTest(unittest.TestCase):
    def test_roundtrip_and_expiry(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fx._cache_put("m", {"a": 1}, {"ok": True}, cache_dir=d)
            self.assertEqual(fx._cache_get("m", {"a": 1}, cache_dir=d),
                             {"ok": True})
            # expire it by backdating
            p = next(Path(d).glob("*.json"))
            rec = {"ts": time.time() - 7200, "data": {"ok": True}}
            p.write_text(__import__("json").dumps(rec))
            self.assertIsNone(fx._cache_get("m", {"a": 1}, cache_dir=d))

    def test_different_params_different_keys(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fx._cache_put("m", {"a": 1}, {"v": 1}, cache_dir=d)
            self.assertIsNone(fx._cache_get("m", {"a": 2}, cache_dir=d))


if __name__ == "__main__":
    unittest.main()
