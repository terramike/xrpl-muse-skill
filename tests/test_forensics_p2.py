#!/usr/bin/env python3
"""Forensic Phase 2 tests — no network (RPC layer mocked).

Covers: amount parsing, DEX-fill extraction, tx value flows, flow
ranking + labels, nft-trail chain assembly + fallback, token-trail
issuer profile/holders/movers, links token section, the labels
registry merge, and the "owner"-never-appears language rule.
Run: python3 -m unittest tests.test_forensics_p2
"""
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from decimal import Decimal
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


A, B, C, D = addr("A"), addr("B"), addr("C"), addr("D")
ISSUER = addr("E")  # 'I' is not valid base58; use E for the issuer
ZERO = "rrrrrrrrrrrrrrrrrrrrrhoLvTp"

TOKEN_ID = ("00010000" + "00" * 20 + "00000001" + "00000005").upper()


def pay_tx(sender, dest, amount="25000000", ledger=100, h="H" * 16):
    return {"Account": sender, "Destination": dest,
            "TransactionType": "Payment", "Amount": amount,
            "ledger_index": ledger, "hash": h,
            "meta": {"delivered_amount": amount,
                     "TransactionResult": "tesSUCCESS"}}


def iou_tx(sender, dest, ccy, issuer, value, ledger=100):
    amt = {"currency": ccy, "issuer": issuer, "value": value}
    return {"Account": sender, "Destination": dest,
            "TransactionType": "Payment", "Amount": amt,
            "ledger_index": ledger, "hash": "H" * 16,
            "meta": {"delivered_amount": amt,
                     "TransactionResult": "tesSUCCESS"}}


def offer_fill_tx(me, cp, gets_consumed, pays_consumed, partial=True):
    """My OfferCreate whose meta shows counterparty cp's offer filled."""
    node = {"LedgerEntryType": "Offer",
            "FinalFields": {"Account": cp,
                            "TakerGets": {"currency": "USD", "issuer": ISSUER,
                                          "value": "90"},
                            "TakerPays": "9000000"}}
    wrap = {"ModifiedNode": node} if partial else {"DeletedNode": node}
    if partial:
        node["PreviousFields"] = {
            "TakerGets": {"currency": "USD", "issuer": ISSUER,
                          "value": str(90 + gets_consumed)},
            "TakerPays": str(9000000 + pays_consumed)}
        # consumed = prev - final
        node["PreviousFields"]["TakerGets"]["value"] = \
            str(90 + gets_consumed)
        node["PreviousFields"]["TakerPays"] = str(9000000 + pays_consumed)
    return {"Account": me, "TransactionType": "OfferCreate",
            "ledger_index": 100, "hash": "H" * 16,
            "meta": {"TransactionResult": "tesSUCCESS",
                     "AffectedNodes": [wrap,
                                       {"ModifiedNode":
                                        {"LedgerEntryType": "Offer",
                                         "FinalFields": {"Account": me}}}]}}


def tx_page(txs):
    """Live response shape: `meta` is a SIBLING of `tx`, not inside it."""
    pages = []
    for t in txs:
        t = dict(t)
        meta = t.pop("meta", None)
        entry = {"tx": t, "validated": True}
        if isinstance(meta, dict):
            entry["meta"] = meta
        pages.append(entry)
    return {"transactions": pages}


# ---------------------------------------------------------------- amounts

class AmountTest(unittest.TestCase):
    def test_xrp_drops(self):
        self.assertEqual(fx._parse_amount("25000000"),
                         ("XRP", Decimal("25")))

    def test_iou(self):
        k, d = fx._parse_amount({"currency": "USD", "issuer": ISSUER,
                                 "value": "12.5"})
        self.assertEqual(k, f"USD.{ISSUER}")
        self.assertEqual(d, Decimal("12.5"))

    def test_garbage(self):
        self.assertEqual(fx._parse_amount(None), (None, None))
        self.assertEqual(fx._parse_amount({"currency": "USD"}),
                         (None, None))

    def test_amt_sub(self):
        k, d = fx._amt_sub("30000000", "25000000")
        self.assertEqual((k, d), ("XRP", Decimal("5")))

    def test_amt_sub_mismatched(self):
        self.assertEqual(fx._amt_sub("1", {"currency": "USD",
                                           "issuer": ISSUER,
                                           "value": "1"}), (None, None))

    def test_normalize_entry_merges_sibling_meta(self):
        tx = {"Account": A, "TransactionType": "Payment"}
        entry = {"tx": tx, "meta": {"delivered_amount": "1000000"},
                 "validated": True}
        norm = fx._normalize_entry(entry)
        self.assertEqual(norm["meta"]["delivered_amount"], "1000000")
        self.assertNotIn("meta", tx)  # response untouched

    def test_normalize_entry_bare_tx(self):
        tx = {"Account": A, "TransactionType": "Payment"}
        self.assertEqual(fx._normalize_entry(tx)["Account"], A)
        self.assertEqual(fx._normalize_entry("garbage"), {})

    def test_partial_payment_uses_delivered(self):
        # instructed 25 XRP, delivered 20 XRP (partial): volume = 20
        tx = pay_tx(B, A, amount="25000000")
        tx["meta"]["delivered_amount"] = "20000000"
        page = tx_page([tx])  # sibling-meta live shape
        normed = [fx._normalize_entry(e) for e in page["transactions"]]
        flows = fx.tx_value_flows(normed[0], A)
        self.assertEqual(flows[B]["in"]["XRP"], Decimal("20"))


class DexFillTest(unittest.TestCase):
    def test_partial_fill_direction(self):
        # cp's offer: TakerGets 100 USD (consumed 10), TakerPays 10 XRP
        # (consumed 1 XRP = 1000000 drops). I take it: I receive 10 USD,
        # I pay 1 XRP.
        tx = offer_fill_tx(A, B, 10, 1000000, partial=True)
        fills = fx._dex_fills(tx, A)
        self.assertEqual(len(fills), 1)
        cp, my_in, my_out = fills[0]
        self.assertEqual(cp, B)
        self.assertEqual(my_in, [(f"USD.{ISSUER}", Decimal("10"))])
        self.assertEqual(my_out, [("XRP", Decimal("1"))])

    def test_full_fill_deleted_node(self):
        tx = offer_fill_tx(A, B, 0, 0, partial=False)
        fills = fx._dex_fills(tx, A)
        cp, my_in, my_out = fills[0]
        self.assertEqual(cp, B)
        self.assertEqual(my_in, [(f"USD.{ISSUER}", Decimal("90"))])
        self.assertEqual(my_out, [("XRP", Decimal("9"))])

    def test_own_offer_skipped(self):
        tx = {"Account": A, "TransactionType": "OfferCreate",
              "meta": {"AffectedNodes": [
                  {"ModifiedNode": {"LedgerEntryType": "Offer",
                                    "FinalFields": {"Account": A}}}]}}
        self.assertEqual(fx._dex_fills(tx, A), [])


class ValueFlowTest(unittest.TestCase):
    def test_payment_in_uses_delivered(self):
        tx = pay_tx(B, A, amount="10000000")
        tx["meta"]["delivered_amount"] = "9000000"  # partial payment
        flows = fx.tx_value_flows(tx, A)
        self.assertEqual(flows[B]["in"], {"XRP": Decimal("9")})

    def test_payment_out(self):
        flows = fx.tx_value_flows(pay_tx(A, B, amount="1000000"), A)
        self.assertEqual(flows[B]["out"], {"XRP": Decimal("1")})
        self.assertEqual(flows[B]["txs"], 1)

    def test_unrelated_payment_empty(self):
        self.assertEqual(fx.tx_value_flows(pay_tx(B, C), A), {})

    def test_nft_tx_no_volume(self):
        tx = {"Account": A, "TransactionType": "NFTokenAcceptOffer"}
        self.assertEqual(fx.tx_value_flows(tx, A), {})

    def test_zero_amount_pruned(self):
        tx = pay_tx(B, A, amount="0")
        tx["meta"]["delivered_amount"] = "0"
        self.assertEqual(fx.tx_value_flows(tx, A), {})

    def test_dex_fill_counts_one_tx(self):
        tx = offer_fill_tx(A, B, 10, 1000000, partial=True)
        flows = fx.tx_value_flows(tx, A)
        self.assertEqual(flows[B]["txs"], 1)
        # I took cp's offer: 10 USD in, 1 XRP out
        self.assertIn(f"USD.{ISSUER}", flows[B]["in"])
        self.assertIn("XRP", flows[B]["out"])

    # --- v0.14.1 regression: only successful, delivered value counts ---
    def test_failed_payment_records_no_flow(self):
        tx = pay_tx(B, A, amount="10000000")
        tx["meta"]["TransactionResult"] = "tecPATH_DRY"
        self.assertEqual(fx.tx_value_flows(tx, A), {})

    def test_failed_offer_create_ignored(self):
        tx = offer_fill_tx(A, B, 10, 1000000, partial=True)
        tx["meta"]["TransactionResult"] = "tecUNFUNDED_OFFER"
        self.assertEqual(fx.tx_value_flows(tx, A), {})

    def test_missing_delivered_amount_no_flow(self):
        tx = pay_tx(B, A, amount="10000000")
        del tx["meta"]["delivered_amount"]  # no evidence → unknown, not 10
        self.assertEqual(fx.tx_value_flows(tx, A), {})

    def test_requested_amount_never_used(self):
        # partial payment: requested 10, delivered 9 — the 10 must not
        # leak in anywhere
        tx = pay_tx(B, A, amount="10000000")
        tx["meta"]["delivered_amount"] = "9000000"
        flows = fx.tx_value_flows(tx, A)
        self.assertEqual(flows[B]["in"], {"XRP": Decimal("9")})


# ---------------------------------------------------------------- pinned ranges
# v0.14.1 regression: history scans pin ONE validated ledger and use
# explicit ledger ranges (a bare ledger_index="validated" on account_tx
# selects a single ledger, not history).

class PinnedRangeTest(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake(method, params):
            self.calls.append((method, dict(params)))
            if method == "ledger":
                return {"ledger_index": 107331581}
            if method == "account_tx":
                return tx_page([])
            raise AssertionError(f"unexpected {method}")
        self.fake = fake

    def test_first_tx_scans_genesis_to_pinned(self):
        with mock.patch.object(fx, "_rpc", self.fake):
            fx.first_tx(A, use_cache=False)
        tx_calls = [p for m, p in self.calls if m == "account_tx"]
        self.assertEqual(len(tx_calls), 1)
        p = tx_calls[0]
        self.assertEqual(p["ledger_index_min"], fx.GENESIS_LEDGER)
        self.assertEqual(p["ledger_index_max"], 107331581)
        self.assertTrue(p.get("forward"))  # oldest-first
        self.assertNotIn("ledger_index", p)  # no bare "validated" misuse

    def test_recent_txs_pins_one_upper_ledger(self):
        with mock.patch.object(fx, "_rpc", self.fake):
            fx.recent_txs(A, 50, use_cache=False)
        tx_calls = [p for m, p in self.calls if m == "account_tx"]
        self.assertEqual(len(tx_calls), 1)
        p = tx_calls[0]
        self.assertEqual(p["ledger_index_max"], 107331581)
        self.assertNotIn("ledger_index", p)
        # the pin itself is exactly one ledger RPC call
        ledger_calls = [p for m, p in self.calls if m == "ledger"]
        self.assertEqual(len(ledger_calls), 1)
        self.assertEqual(ledger_calls[0]["ledger_index"], "validated")


# ---------------------------------------------------------------- labels

class LabelsTest(unittest.TestCase):
    def setUp(self):
        fx.reset_labels_cache()
        self.tmp = tempfile.TemporaryDirectory()
        self.shipped = Path(self.tmp.name) / "shipped.json"
        self.user = Path(self.tmp.name) / "user.json"
        self.shipped.write_text(json.dumps({
            "schema_version": 1,
            "labels": [{"address": B, "label": "Example Exchange",
                        "category": "exchange-hot-wallet",
                        "verification": "verified",
                        "evidence": "https://example.com",
                        "added_at": "2026-09-30"}]}))
        self.user.write_text(json.dumps({
            "schema_version": 1,
            "labels": [{"address": B, "label": "My label for B",
                        "category": "known-service",
                        "verification": "unverified",
                        "evidence": "", "added_at": "2026-09-30"},
                       {"address": C, "label": "C service",
                        "category": "faucet",
                        "verification": "unverified",
                        "evidence": "", "added_at": "2026-09-30"}]}))
        self.patch = mock.patch.object(
            fx, "_labels_paths",
            return_value=([self.shipped], self.user))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        fx.reset_labels_cache()
        self.tmp.cleanup()

    def test_user_override_wins(self):
        self.assertEqual(fx.label_of(B)["label"], "My label for B")

    def test_fmt_labeled(self):
        s = fx.fmt_labeled(B)
        # approved Phase 2 rendering: LABEL: r… — "label" (verification)
        self.assertTrue(s.startswith("LABEL: " + B + " — "))
        self.assertIn('"My label for B"', s)
        self.assertIn("(unverified)", s)
        self.assertEqual(fx.fmt_labeled(D), D)

    def test_any_labeled(self):
        self.assertTrue(fx.any_labeled([D, C]))
        self.assertFalse(fx.any_labeled([D]))

    def test_missing_files_ok(self):
        with mock.patch.object(fx, "_labels_paths",
                               return_value=([Path("/nonexistent")],
                                             Path("/nonexistent2"))):
            fx.reset_labels_cache()
            self.assertEqual(fx.load_labels(), {})


# ---------------------------------------------------------------- flow

def make_flow_rpc(pages):
    def fake(method, params):
        if method == "ledger":
            # _validated_ledger_index pins the scan's upper bound
            return {"ledger_index": 107331581}
        if method == "account_tx":
            return tx_page(pages.get(params["account"], []))
        raise AssertionError(f"unexpected {method}")
    return fake


class FlowTest(unittest.TestCase):
    def setUp(self):
        # A receives 25 XRP from B (2 txs), sends 1 XRP to C, buys via DEX
        self.pages = {A: [pay_tx(B, A, "25000000"),
                          pay_tx(B, A, "25000000"),
                          pay_tx(A, C, "1000000"),
                          offer_fill_tx(A, D, 10, 1000000, partial=True)]}

    def test_ranking_and_sections(self):
        with mock.patch.object(fx, "_rpc", make_flow_rpc(self.pages)):
            lines = fx.format_flow(A, window=200, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("RECEIVED", text)
        self.assertIn("SENT", text)
        self.assertIn(B, text)  # 50 XRP in
        self.assertIn(C, text)  # 1 XRP out
        self.assertIn(D, text)  # DEX fill counterparty
        self.assertIn("used", text)

    def test_invalid_address(self):
        lines = fx.format_flow("nope", use_cache=False)
        self.assertIn("not a valid XRPL classic address",
                      "\n".join(lines))

    def test_label_note_when_labeled(self):
        with mock.patch.object(fx, "label_of",
                               side_effect=lambda a: {"label": "X"}
                               if a == B else None):
            with mock.patch.object(fx, "_rpc",
                                    make_flow_rpc(self.pages)):
                lines = fx.format_flow(A, window=200, use_cache=False)
        self.assertIn("usually plumbing", "\n".join(lines))

    def test_thin_node_history_note(self):
        def fake(method, params):
            self.assertIn(method, ("ledger", "account_tx"))
            if method == "ledger":
                return {"ledger_index": 107331581}
            return {"transactions": [], "ledger_index_min": 107331581,
                    "ledger_index_max": 107331581}
        with mock.patch.object(fx, "_rpc", fake):
            lines = fx.format_flow(A, window=50, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("107,331,581", text)
        self.assertIn("can't see older activity", text)

    def test_full_history_no_note(self):
        def fake(method, params):
            if method == "ledger":
                return {"ledger_index": 107331581}
            return {"transactions": [], "ledger_index_min": 32570,
                    "ledger_index_max": 107331581}
        with mock.patch.object(fx, "_rpc", fake):
            lines = fx.format_flow(A, window=50, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("(none in window)", text)
        self.assertNotIn("only reported history", text)


# ---------------------------------------------------------------- nft-trail

def make_nft_rpc(history, offers=None, fail_history=False, holders=None):
    offers = offers or {}
    holders = holders or {}

    def fake(method, params):
        if method == "nft_history":
            if fail_history:
                raise RuntimeError("unknown method")
            # live shape: meta is a sibling of tx
            pages = []
            for t in history:
                t = dict(t)
                meta = t.pop("meta", None)
                entry = {"tx": t, "validated": True}
                if isinstance(meta, dict):
                    entry["meta"] = meta
                pages.append(entry)
            return {"transactions": pages}
        if method == "ledger_entry":
            idx = params.get("index")
            o = offers.get(idx)
            if o:
                return {"node": {"LedgerEntryType": "NFTokenOffer",
                                 "Account": o[0], "Amount": o[1]}}
            return {"node": {}}
        if method in ("nft_sell_offers", "nft_buy_offers"):
            return {"offers": []}
        if method == "account_nfts":
            acct = params.get("account")
            nfts = [{"NFTokenID": tid} for tid in holders.get(acct, [])]
            return {"account_nfts": nfts}
        if method == "account_tx":
            return {"transactions": []}
        raise AssertionError(f"unexpected {method}")
    return fake


def mint_tx(minter, token_id=TOKEN_ID):
    # live NFTokenMint txs carry NO NFTokenID field — the token id only
    # appears in the minter's NFTokenPage metadata node.
    return {"Account": minter, "TransactionType": "NFTokenMint",
            "ledger_index": 10, "hash": "M" * 64, "date": 800000000,
            "meta": {"AffectedNodes": [{"ModifiedNode": {
                "LedgerEntryType": "NFTokenPage",
                "FinalFields": {"NFTokens": [{"NFToken": {
                    "NFTokenID": token_id}}]}}}]}}


def accept_tx(accepter, sell_idx):
    return {"Account": accepter, "TransactionType": "NFTokenAcceptOffer",
            "NFTokenSellOffer": sell_idx, "ledger_index": 20,
            "hash": "S" * 64, "date": 800000100}


class NftTrailTest(unittest.TestCase):
    def test_id_validation(self):
        self.assertTrue(fx._nft_id_valid(TOKEN_ID))
        self.assertFalse(fx._nft_id_valid("nope"))
        self.assertFalse(fx._nft_id_valid("00" * 32 + "zz"))

    def test_b58_zero_vector(self):
        self.assertEqual(fx._b58check_encode(bytes(20)), ZERO)

    def test_issuer_decode(self):
        zero_id = "00010000" + "00" * 20 + "00000001" + "00000005"
        self.assertEqual(fx.nft_issuer_of(zero_id), ZERO)

    def test_mint_matches_via_metadata(self):
        # live mint txs carry no NFTokenID field — match via the
        # NFTokenPage metadata node (sibling meta, as served live).
        tx = fx._normalize_entry(tx_page([mint_tx(A)])["transactions"][0])
        self.assertNotIn("NFTokenID", tx)
        self.assertTrue(fx._mint_matches(tx, TOKEN_ID))
        self.assertFalse(fx._mint_matches(tx, "00" * 32))
        self.assertFalse(fx._mint_matches({}, TOKEN_ID))

    def test_full_chain(self):
        history = [accept_tx(C, "IDX1"), mint_tx(A)]  # newest first
        offers = {"IDX1": (B, "5000000")}  # B sold to C for 5 XRP
        with mock.patch.object(fx, "_rpc",
                               make_nft_rpc(history, offers,
                                            holders={C: [TOKEN_ID]})):
            lines = fx.format_nft_trail(TOKEN_ID, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("minted by", text)
        self.assertIn(A, text)
        self.assertIn("sold", text)
        self.assertIn(B, text)
        self.assertIn(C, text)
        self.assertIn("5 XRP", text)
        self.assertIn("currently held by", text)
        self.assertIn("verified at validated ledger", text)
        self.assertIn("open offers now", text)

    def test_both_offers_direct_sale_holder(self):
        # Regression (v0.14.1): an NFTokenAcceptOffer carrying BOTH a
        # sell offer and a buy offer is a direct sale — the accepter is
        # the SELLER and the buy-offer owner is the buyer. The old code
        # treated any accept with NFTokenSellOffer set as "accepter
        # buys", reporting the seller as the current holder. Here the
        # buy offer is already consumed (unresolvable via ledger_entry),
        # so the holder must come from ledger verification, not from
        # derivation — and it must be C (the buyer), never B (seller).
        accept = {"Account": B, "TransactionType": "NFTokenAcceptOffer",
                  "NFTokenSellOffer": "SELLIDX", "NFTokenBuyOffer": "BUYIDX",
                  "ledger_index": 30, "hash": "T" * 64, "date": 800000200}
        buy_offer = {"Account": C, "TransactionType": "NFTokenCreateOffer",
                     "Amount": "904142", "ledger_index": 25,
                     "hash": "O" * 64, "date": 800000150}
        history = [accept, buy_offer, mint_tx(A)]  # newest first
        with mock.patch.object(fx, "_rpc",
                               make_nft_rpc(history,
                                            holders={C: [TOKEN_ID]})):
            lines = fx.format_nft_trail(TOKEN_ID, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("currently held by", text)
        self.assertIn(C, text)
        self.assertIn("verified at validated ledger", text)
        self.assertNotIn(f"currently held by {B}", text)

    def test_unverified_holder_not_asserted(self):
        # If nobody in the trail holds the token at the validated
        # ledger, the trail must not assert a holder.
        history = [accept_tx(C, "IDX1"), mint_tx(A)]  # newest first
        offers = {"IDX1": (B, "5000000")}
        with mock.patch.object(fx, "_rpc",
                               make_nft_rpc(history, offers)):
            lines = fx.format_nft_trail(TOKEN_ID, use_cache=False)
        text = "\n".join(lines)
        self.assertNotIn("currently held by", text)
        self.assertIn("UNVERIFIED", text)

    def test_fallback_when_no_nft_history(self):
        issuer = fx.nft_issuer_of(TOKEN_ID)

        def fake(method, params):
            if method == "nft_history":
                raise RuntimeError("unknown method")
            if method == "ledger":
                # _nft_trail_fallback pins one validated upper ledger
                return {"ledger_index": 107331581}
            if method == "account_tx" and params["account"] == issuer:
                return tx_page([mint_tx(A)])
            if method in ("nft_sell_offers", "nft_buy_offers"):
                return {"offers": []}
            raise AssertionError(f"unexpected {method}")

        with mock.patch.object(fx, "_rpc", fake):
            lines = fx.format_nft_trail(TOKEN_ID, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("minted by", text)
        self.assertIn("nft_history is unavailable", text)

    def test_invalid_id(self):
        lines = fx.format_nft_trail("xyz", use_cache=False)
        self.assertIn("not a valid NFTokenID", "\n".join(lines))


# ---------------------------------------------------------------- token-trail

def make_token_rpc(info, lines_pages, txs):
    def fake(method, params):
        if method == "account_info":
            return {"account_data": info}
        if method == "account_lines":
            return {"lines": lines_pages}
        if method == "account_tx":
            return tx_page(txs)
        raise AssertionError(f"unexpected {method}")
    return fake


class TokenTrailTest(unittest.TestCase):
    def test_normalize_currency(self):
        self.assertEqual(fx._normalize_currency("USD"), "USD")
        self.assertEqual(fx._normalize_currency("usd"), "USD")
        rl = "524C555344" + "0" * 30
        self.assertEqual(fx._normalize_currency("RLUSD"), rl)
        self.assertEqual(fx._normalize_currency(rl.lower()), rl)
        self.assertIsNone(fx._normalize_currency(""))
        self.assertIsNone(fx._normalize_currency("no way!"))

    def setUp(self):
        self.info = {"Domain": "6578616d706c652e636f6d",  # example.com
                     "TransferRate": 1002000000,  # 0.2%
                     "Flags": 0x00400000,  # global freeze
                     "TickSize": 5}
        self.lines = [
            {"account": B, "currency": "USD", "balance": "1000"},
            {"account": C, "currency": "USD", "balance": "50"},
            {"account": D, "currency": "EUR", "balance": "999"},
        ]
        self.txs = [iou_tx(B, C, "USD", ISSUER, "25"),
                    iou_tx(C, B, "USD", ISSUER, "10"),
                    pay_tx(B, C, "1000000")]

    def test_issuer_profile(self):
        with mock.patch.object(fx, "_rpc",
                               make_token_rpc(self.info, [], [])):
            prof = fx.issuer_profile(ISSUER, use_cache=False)
        self.assertEqual(prof["domain"], "example.com")
        self.assertAlmostEqual(prof["transfer_fee_pct"], 0.2)
        self.assertTrue(prof["global_freeze"])
        self.assertFalse(prof["unknown"])

    def test_issuer_profile_unknown(self):
        with mock.patch.object(fx, "_rpc",
                               make_token_rpc({}, [], [])):
            prof = fx.issuer_profile(ISSUER, use_cache=False)
        self.assertTrue(prof["unknown"])

    def test_full_token_trail(self):
        with mock.patch.object(fx, "_rpc", make_token_rpc(
                self.info, self.lines, self.txs)):
            lines = fx.format_token_trail(ISSUER, "USD", window=200,
                                          use_cache=False)
        text = "\n".join(lines)
        self.assertIn("Issuer:", text)
        self.assertIn("transfer fee 0.2%", text)
        self.assertIn("GLOBAL FREEZE", text)
        self.assertIn("example.com", text)
        self.assertIn("Top holders", text)
        self.assertIn(B, text)  # 1000 USD top holder
        self.assertIn("partial", text)
        self.assertIn("Movers", text)
        self.assertIn("issuer-involved flow only", text)
        self.assertIn("holder-to-holder transfers don't touch the issuer",
                      text)
        # EUR holder D must not appear in USD holders
        holders_sec = text.split("Top holders")[1].split("Movers")[0]
        self.assertNotIn(D, holders_sec)

    def test_bad_inputs(self):
        self.assertIn("not a valid issuer address",
                      "\n".join(fx.format_token_trail("nope", "USD",
                                                      use_cache=False)))
        self.assertIn("must be a 3-letter code",
                      "\n".join(fx.format_token_trail(ISSUER, "has space!",
                                                      use_cache=False)))

    def test_currency_validation(self):
        self.assertEqual(fx._normalize_currency("USD"), "USD")
        self.assertEqual(fx._normalize_currency("00" * 20), "00" * 20)
        self.assertIsNone(fx._normalize_currency("US"))
        self.assertIsNone(fx._normalize_currency("USD$"))
        self.assertIsNone(fx._normalize_currency(""))


# ---------------------------------------------------------------- links token section

def make_links_rpc():
    def fake(method, params):
        if method == "account_tx":
            return {"transactions": []}
        if method == "account_info":
            acct = params["account"]
            if acct == ISSUER:
                return {"account_data": {"TransferRate": 1001000000,
                                         "Flags": 0}}
            return {"account_data": {}}
        if method == "account_objects":
            return {"account_objects": []}
        if method == "account_lines":
            return {"lines": [{"account": ISSUER, "currency": "USD",
                                "balance": "10"}]}
        if method == "ledger":
            return {"ledger_index": 107331581,
                    "ledger": {"close_time": 800000000}}
        if method == "ledger_entry":
            return {"node": {}}
        raise AssertionError(f"unexpected {method}")
    return fake


class LinksTokensTest(unittest.TestCase):
    def test_shared_tokens_section(self):
        with mock.patch.object(fx, "_rpc", make_links_rpc()):
            lines = fx.format_links(A, B, window=50, use_cache=False)
        text = "\n".join(lines)
        self.assertIn("Shared tokens (1):", text)
        self.assertIn("USD.", text)
        self.assertIn("transfer fee" if "transfer fee" in text else "fee",
                      text)
        self.assertIn("weak link", text)

    def test_account_tokens(self):
        with mock.patch.object(fx, "_rpc", make_links_rpc()):
            toks = fx.account_tokens(A, [], use_cache=False)
        self.assertIn(("USD", ISSUER), toks)
        self.assertTrue(toks[("USD", ISSUER)]["held"])


# ---------------------------------------------------------------- language

class LanguageTest(unittest.TestCase):
    def _all_outputs(self):
        with mock.patch.object(fx, "_rpc", make_flow_rpc({A: []})):
            yield fx.format_flow(A, window=10, use_cache=False)
        with mock.patch.object(fx, "_rpc",
                               make_nft_rpc([mint_tx(A)])):
            yield fx.format_nft_trail(TOKEN_ID, use_cache=False)
        with mock.patch.object(fx, "_rpc",
                               make_token_rpc({}, [], [])):
            yield fx.format_token_trail(ISSUER, "USD", window=10,
                                        use_cache=False)
        with mock.patch.object(fx, "_rpc", make_links_rpc()):
            yield fx.format_links(A, B, window=10, use_cache=False)

    def test_owner_never_appears(self):
        # standalone "owner"/"owners" banned; "ownership" in the
        # "not ownership" disclaimer is the discipline working (Phase 1
        # convention)
        for lines in self._all_outputs():
            for ln in lines:
                self.assertIsNone(re.search(r"\bowners?\b", ln.lower()))

    def test_nft_uses_held_by(self):
        with mock.patch.object(fx, "_rpc",
                               make_nft_rpc([mint_tx(A)],
                                            holders={A: [TOKEN_ID]})):
            text = "\n".join(fx.format_nft_trail(TOKEN_ID,
                                                 use_cache=False))
        self.assertIn("held by", text)


if __name__ == "__main__":
    unittest.main()
