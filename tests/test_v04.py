#!/usr/bin/env python3
"""v0.4 adversarial logic tests — no network. Run: python3 tests/test_v04.py

Covers the v0.3 audit findings (unknown-tx rejection, extra-field rejection,
summary/meta tampering, network+timestamp tampering, unlimited IOU payments,
token/token offers, exact-pair enforcement, policy-file tampering,
X-address tag conflicts, concurrent limit enforcement) plus the v0.4
hardening: envelope invariants, NaN/Infinity rejection, bounded offer
lifetime, true rolling-24h window, ambiguity-safe reservations with ledger
sweep, protected signer state, hardened price validation (both sides,
spread cap, min depth, depth-weighted mid), fail-closed RequireDestTag.
"""
import importlib.util
import json
import sys
import tempfile
import threading
import time
from decimal import Decimal
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    # Register the shared helper under the name both CLIs import, so the
    # test and xrpl-sign use ONE module instance (the v0.2 loader bug).
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
T = load(BIN / "xrpl-trade", "xrpl_trade_v04")
S = load(BIN / "xrpl-sign", "xrpl_sign_v04")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


RLUSD = C.currency_code("RLUSD")
R = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"

# Real (offline-generated) addresses — the canonical binary codec rejects
# fake ones, so tests use the same validity rules as production.
from xrpl.wallet import Wallet
ACCT = Wallet.create().classic_address
DEST = Wallet.create().classic_address
ARMY_ISS = Wallet.create().classic_address
FOO_ISS = Wallet.create().classic_address

with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    # Redirect ALL shared paths to the sandbox (single module instance!).
    C.XRPL_DIR = tmp
    C.PROPOSALS_DIR = tmp / "proposals"
    C.POLICY_PATH = tmp / "policy.json"
    C.STATE_PATH = tmp / "state.json"
    C.STATE_LOCK_PATH = tmp / "state.lock"
    C.AUDIT_PATH = tmp / "audit.log"
    C.APPROVED_PATH = tmp / "approved.json"
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/RLUSD": {"base": "XRP", "base_issuer": None,
                      "quote": "RLUSD", "quote_issuer": R},
        "ARMY/XRP": {"base": "ARMY", "base_issuer": ARMY_ISS,
                     "quote": "XRP", "quote_issuer": None}}}))
    base_policy = dict(C.DEFAULT_POLICY)
    base_policy["spend_limits"] = {
        "XRP": {"per_tx": "25", "per_day": "100"},
        f"RLUSD.{R}": {"per_tx": "40", "per_day": "150"},
    }
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- fake network client (no real network in tests) ---
    class FakeResp:
        def __init__(self, result, ok=True):
            self._r, self._ok = result, ok

        def is_successful(self):
            return self._ok

        @property
        def result(self):
            return self._r

    class FakeClient:
        """Canned book (DW mid ~1.5095 RLUSD/XRP, depth 100/side) + flags."""
        def __init__(self, mode="normal", require_tag=False,
                     tag_error=False, book_error=False):
            self.mode = mode
            self.require_tag = require_tag
            self.tag_error = tag_error
            self.book_error = book_error
            self.calls = 0

        def _book(self, side):
            q = lambda v: {"currency": RLUSD, "issuer": R, "value": v}
            x = lambda drops: str(drops)
            if self.mode == "empty":
                return []
            if self.mode == "one_sided":
                return [] if side == "asks" else [
                    {"TakerPays": x(50_000000), "TakerGets": q("75.450000")}]
            if self.mode == "wide_spread":
                if side == "asks":
                    return [{"TakerPays": q("80.000000"),
                             "TakerGets": x(50_000000)}]
                return [{"TakerPays": x(50_000000),
                         "TakerGets": q("70.000000")}]
            if self.mode == "thin":
                if side == "asks":
                    return [{"TakerPays": q("1.510000"),
                             "TakerGets": x(1_000000)}]
                return [{"TakerPays": x(1_000000),
                         "TakerGets": q("1.509000")}]
            if self.mode == "dusty":
                # one honest level + one absurd dust level: the dust must
                # not move the depth-weighted mid
                if side == "asks":
                    return [{"TakerPays": q("75.500000"),
                             "TakerGets": x(50_000000)},
                            {"TakerPays": q("0.000002"),
                             "TakerGets": x(1)}]
                return [{"TakerPays": x(50_000000),
                         "TakerGets": q("75.450000")},
                        {"TakerPays": x(1),
                         "TakerGets": q("0.000002")}]
            # normal: two levels/side, 100 XRP depth each side
            if side == "asks":
                return [{"TakerPays": q("75.500000"),
                         "TakerGets": x(50_000000)},
                        {"TakerPays": q("75.750000"),
                         "TakerGets": x(50_000000)}]
            return [{"TakerPays": x(50_000000),
                     "TakerGets": q("75.450000")},
                    {"TakerPays": x(50_000000),
                     "TakerGets": q("75.200000")}]

        def request(self, req):
            from xrpl.models.requests import BookOffers, AccountInfo
            if isinstance(req, BookOffers):
                self.calls += 1
                if self.book_error:
                    raise RuntimeError("node down")
                side = "asks" if self.calls % 2 == 1 else "bids"
                return FakeResp({"offers": self._book(side)})
            if isinstance(req, AccountInfo):
                if self.tag_error:
                    raise RuntimeError("node down")
                flags = 0x00020000 if self.require_tag else 0
                return FakeResp({"account_data": {"Flags": flags}})
            raise AssertionError(f"unexpected request {req!r}")

    class FakeSweep:
        """Canned ledger for sweep_pending tests."""
        def __init__(self, ledger_index=2000, tx_found=True,
                     tx_result="tesSUCCESS", raise_tx=False,
                     raise_ledger=False):
            self.ledger_index = ledger_index
            self.tx_found = tx_found
            self.tx_result = tx_result
            self.raise_tx = raise_tx
            self.raise_ledger = raise_ledger

        def request(self, req):
            from xrpl.models.requests import Ledger, Tx
            if isinstance(req, Ledger):
                if self.raise_ledger:
                    raise RuntimeError("node down")
                return FakeResp({"ledger_index": self.ledger_index})
            if isinstance(req, Tx):
                if self.raise_tx:
                    raise RuntimeError("node down")
                if not self.tx_found:
                    return FakeResp({"error": "txnNotFound"}, ok=False)
                return FakeResp(
                    {"meta": {"TransactionResult": self.tx_result}})
            raise AssertionError(f"unexpected request {req!r}")

    def xrp(drops):
        return str(drops)

    def iou(ccy, iss, v):
        return {"currency": ccy, "issuer": iss, "value": v}

    def offer_tx(pays, gets, seq=1, lifetime=3600):
        return {"TransactionType": "OfferCreate", "Account": ACCT,
                "TakerPays": pays, "TakerGets": gets,
                "Expiration": C.ripple_time_from_now(lifetime),
                "Fee": "12", "Sequence": seq, "LastLedgerSequence": 999}

    def prop_of(tx, network="testnet", action="buy"):
        h, path = C.save_proposal(tx, network, ACCT, action)
        return json.loads(path.read_text()), path, h

    def policy_denials(tx, network="testnet", client=None, action="buy"):
        prop, _, _ = prop_of(tx, network, action)
        pol = C.load_policy()
        return S.check_policy(prop, tx, pol, client or FakeClient(),
                              C.SpentTracker())

    def invariants_raise(prop, tx):
        try:
            C.verify_envelope_invariants(prop, tx)
            return None
        except C.ProposalError as e:
            return str(e)

    # --- 1. currency encoding (regression) ---
    check("RLUSD hex-encodes to 40 chars", len(RLUSD) == 40)
    check("RLUSD roundtrips", C.display_currency(RLUSD) == "RLUSD")

    # --- 2. buy/sell direction (the ed8fa202 regression) ---
    buy = T.build_offer_tx("rX", "ARMY", ARMY_ISS, "XRP", None,
                           Decimal("1000"), Decimal("0.005"), "buy", 3600).to_xrpl()
    check("buy: TakerPays is BASE (ARMY)",
          buy["TakerPays"]["currency"] == C.currency_code("ARMY"))
    sell = T.build_offer_tx("rX", "ARMY", ARMY_ISS, "XRP", None,
                            Decimal("1000"), Decimal("0.005"), "sell", 3600).to_xrpl()
    check("sell: TakerGets is BASE (ARMY)",
          sell["TakerGets"]["currency"] == C.currency_code("ARMY"))

    # --- 3. envelope tamper-evidence ---
    tx0 = offer_tx(xrp("1000000"), iou(RLUSD, R, "1.470000"))
    prop, path, h = prop_of(tx0)
    try:
        C.verify_proposal(prop, path)
        C.verify_envelope_invariants(prop, prop["tx"])
        check("valid envelope verifies (hash + invariants)", True)
    except C.ProposalError:
        check("valid envelope verifies (hash + invariants)", False)

    def tampered(mutate):
        p2 = json.loads(json.dumps(prop))
        mutate(p2)
        try:
            C.verify_proposal(p2, path)
            return False
        except C.ProposalError:
            return True

    check("network tampering rejected",
          tampered(lambda p: p.update(network="mainnet")))
    check("created_at tampering rejected",
          tampered(lambda p: p.update(created_at=p["created_at"] - 99999)))
    check("tx tampering rejected",
          tampered(lambda p: p["tx"].update(Fee="5000")))
    check("tx_binary tampering rejected",
          tampered(lambda p: p.update(tx_binary="00" + p["tx_binary"][2:])))
    check("policy_version tampering rejected",
          tampered(lambda p: p.update(policy_version=2)))
    check("format tampering rejected",
          tampered(lambda p: p.update(format="xrpl-proposal/2")))

    # --- 4. envelope invariants (defense in depth) ---
    p2 = json.loads(json.dumps(prop))
    p2["account"] = DEST
    check("envelope/tx account mismatch rejected",
          invariants_raise(p2, p2["tx"]) is not None)
    check("action/type mismatch rejected (buy vs Payment)",
          invariants_raise(prop, {"TransactionType": "Payment",
                                  "Account": ACCT, "Destination": DEST,
                                  "Amount": xrp("1"), "Fee": "12",
                                  "Sequence": 1,
                                  "LastLedgerSequence": 999}) is not None)
    no_ll = dict(tx0)
    del no_ll["LastLedgerSequence"]
    check("missing LastLedgerSequence rejected",
          invariants_raise(prop, no_ll) is not None)
    sig_tx = dict(tx0)
    sig_tx["TxnSignature"] = "00" * 64
    check("TxnSignature in unsigned proposal rejected",
          invariants_raise(prop, sig_tx) is not None)
    fut = json.loads(json.dumps(prop))
    fut["created_at"] = int(time.time()) + 3600
    check("created_at far in the future rejected",
          invariants_raise(fut, fut["tx"]) is not None)
    # orientation: envelope says buy but the offer gives BASE (a sell)
    wrong_way = offer_tx(iou(RLUSD, R, "1.470000"), xrp("1000000"))
    wp, _, _ = prop_of(wrong_way, action="buy")
    check("buy envelope with sell orientation rejected",
          invariants_raise(wp, wp["tx"]) is not None)
    right_way = offer_tx(iou(RLUSD, R, "1.470000"), xrp("1000000"))
    rp, _, _ = prop_of(right_way, action="sell")
    check("sell envelope with sell orientation passes",
          invariants_raise(rp, rp["tx"]) is None)

    # --- 5. summary is derived from the tx, never stored/trusted ---
    lines = C.describe_tx(tx0, "buy")
    blob = "\n".join(lines)
    check("derived summary shows give (1.47 RLUSD)",
          "1.470000" in blob and "RLUSD" in blob)
    check("derived summary shows receive (1 XRP)", "1.000000 XRP" in blob)
    check("no summary stored in envelope", "summary" not in prop)

    # --- 6. unknown transaction types rejected ---
    srk = {"TransactionType": "SetRegularKey", "Account": ACCT,
           "RegularKey": DEST, "Fee": "12", "Sequence": 1,
           "LastLedgerSequence": 999}
    probs = C.validate_tx_shape(srk, C.DEFAULT_ALLOWED_TX_TYPES)
    check("SetRegularKey rejected by shape validation",
          any("not in the allowlist" in p for p in probs))
    denials, _ = policy_denials(srk, action="evil")
    check("SetRegularKey denied by policy", len(denials) > 0)

    # --- 7. smuggled fields rejected ---
    pay_paths = {"TransactionType": "Payment", "Account": ACCT,
                 "Destination": DEST, "Amount": xrp("1000000"),
                 "Paths": [["x"]], "Fee": "12", "Sequence": 1,
                 "LastLedgerSequence": 999}
    check("Payment+Paths rejected",
          any("Paths" in p for p in C.validate_tx_shape(
              pay_paths, C.DEFAULT_ALLOWED_TX_TYPES)))
    pay_partial = {"TransactionType": "Payment", "Account": ACCT,
                   "Destination": DEST, "Amount": xrp("1000000"),
                   "Flags": 131072, "Fee": "12", "Sequence": 1,
                   "LastLedgerSequence": 999}
    check("Payment+tfPartialPayment rejected",
          any("Flags" in p for p in C.validate_tx_shape(
              pay_partial, C.DEFAULT_ALLOWED_TX_TYPES)))
    offer_memo = dict(tx0)
    offer_memo["Memos"] = [{"Memo": {"MemoData": "hi"}}]
    check("OfferCreate+Memos rejected",
          any("Memos" in p for p in C.validate_tx_shape(
              offer_memo, C.DEFAULT_ALLOWED_TX_TYPES)))

    # --- 8. missing required fields ---
    bad_offer = dict(tx0)
    del bad_offer["TakerGets"]
    check("OfferCreate without TakerGets flagged",
          any("TakerGets" in p for p in C.validate_tx_shape(
              bad_offer, C.DEFAULT_ALLOWED_TX_TYPES)))

    # --- 9. NaN / Infinity amounts rejected (limit-comparison poison) ---
    nan_pay = {"TransactionType": "Payment", "Account": ACCT,
               "Destination": DEST,
               "Amount": iou(RLUSD, R, "NaN"),
               "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
    check("NaN amount rejected",
          any("not finite" in p for p in C.validate_amounts(nan_pay)))
    inf_offer = offer_tx(xrp("1000000"), iou(RLUSD, R, "Infinity"))
    check("Infinity amount rejected",
          any("not finite" in p for p in C.validate_amounts(inf_offer)))
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    # (NaN cannot be binary-encoded, so no proposal file can exist for it —
    # check_policy is called directly with a minimal envelope)
    denials, _ = S.check_policy({"network": "testnet"}, nan_pay, pol,
                                FakeClient(), C.SpentTracker())
    check("NaN payment denied by policy (fail closed)",
          any("not finite" in d for d in denials))
    # a hand-crafted envelope carrying an un-encodable tx is rejected cleanly
    evil_env = {"format": C.ENVELOPE_FORMAT, "network": "testnet",
                "account": ACCT, "action": "send",
                "created_at": int(time.time()),
                "policy_version": C.POLICY_VERSION,
                "tx": nan_pay, "tx_binary": "00"}
    core = {k: evil_env[k] for k in C.ENVELOPE_HASH_KEYS}
    evil_env["proposal_hash"] = C.canonical_hash(core)
    try:
        C.verify_proposal(evil_env, tmp / (evil_env["proposal_hash"] + ".json"))
        check("un-encodable tx rejected cleanly", False)
    except C.ProposalError as e:
        check("un-encodable tx rejected cleanly",
              "canonically encoded" in str(e))
    C.POLICY_PATH.write_text(json.dumps(base_policy))
    for bad in ("NaN", "Infinity", "-Infinity"):
        try:
            C.dec(bad, "amount")
            check(f"dec({bad}) rejected", False)
        except SystemExit:
            check(f"dec({bad}) rejected", True)

    # --- 10. exact-pair enforcement (token/token bypass) ---
    tt = offer_tx(iou(C.currency_code("ARMY"), ARMY_ISS, "100"),
                  iou(RLUSD, R, "0.5"))
    denials, _ = policy_denials(tt)
    check("unlisted ARMY/RLUSD offer denied (exact-pair)",
          any("exactly-approved pair" in d for d in denials))

    # --- 11. approved pair passes shape+pair+price ---
    ok_tx = offer_tx(xrp("1000000"), iou(RLUSD, R, "1.470000"))
    denials, spends = policy_denials(ok_tx)
    check("approved XRP/RLUSD offer passes", denials == [])
    check("spends measured on TakerGets (RLUSD 1.47)",
          spends.get(f"RLUSD.{R}") == Decimal("1.470000"))

    # --- 12. deviation still enforced from the tx ---
    far_tx = offer_tx(xrp("1000000"), iou(RLUSD, R, "1.300000"))
    denials, _ = policy_denials(far_tx)
    check("13.9% off-mid offer denied", any("deviates" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(mode="empty"))
    check("empty book fails closed", any("fail closed" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(mode="one_sided"))
    check("one-sided book fails closed",
          any("one-sided" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(mode="wide_spread"))
    check("wide-spread book fails closed",
          any("spread" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(mode="thin"))
    check("thin book fails closed", any("too thin" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(mode="dusty"))
    check("dust offer does not distort the depth-weighted mid",
          denials == [])
    denials, _ = policy_denials(ok_tx, client=FakeClient(book_error=True))
    check("book RPC error fails closed",
          any("fail closed" in d for d in denials))

    # --- 13. bounded offer lifetime ---
    past_tx = dict(ok_tx)
    past_tx["Expiration"] = C.ripple_time_from_now(-100)
    denials, _ = policy_denials(past_tx)
    check("already-expired offer denied",
          any("Expiration" in d for d in denials))
    far_exp = dict(ok_tx)
    far_exp["Expiration"] = C.ripple_time_from_now(86400 * 30)
    denials, _ = policy_denials(far_exp)
    check("30-day offer lifetime denied",
          any("allowed window" in d for d in denials))
    ok_life = dict(ok_tx)
    ok_life["Expiration"] = C.ripple_time_from_now(3600)
    denials, _ = policy_denials(ok_life)
    check("1-hour offer lifetime passes", denials == [])

    # --- 14. per-asset caps: the 999999999999 TOK payment ---
    huge = {"TransactionType": "Payment", "Account": ACCT,
            "Destination": DEST, "Amount": iou(RLUSD, R, "999999999999"),
            "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(huge, action="send")
    check("999999999999 RLUSD payment denied (per-tx)",
          any("per-tx limit" in d for d in denials))
    big_xrp = {"TransactionType": "Payment", "Account": ACCT,
               "Destination": DEST, "Amount": xrp("50000000"),
               "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
    denials, _ = policy_denials(big_xrp, action="send")
    check("50 XRP payment denied (per-tx)", any("per-tx limit" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))  # restore

    # --- 15. asset with no configured limit fails closed ---
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/FOO": {"base": "XRP", "base_issuer": None, "quote": "FOO",
                    "quote_issuer": FOO_ISS}}}))
    foo_pay = {"TransactionType": "Payment", "Account": ACCT,
               "Destination": DEST,
               "Amount": iou(C.currency_code("FOO"), FOO_ISS, "1"),
               "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(foo_pay, action="send")
    check("allowlisted-but-unlimited asset fails closed",
          any("no spend limit" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/RLUSD": {"base": "XRP", "base_issuer": None,
                      "quote": "RLUSD", "quote_issuer": R},
        "ARMY/XRP": {"base": "ARMY", "base_issuer": ARMY_ISS,
                     "quote": "XRP", "quote_issuer": None}}}))

    # --- 16. destination (address, tag) exact matching ---
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": 7}]
    C.POLICY_PATH.write_text(json.dumps(pol))

    def pay_to(tag):
        p = {"TransactionType": "Payment", "Account": ACCT,
             "Destination": DEST, "Amount": xrp("1000000"),
             "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
        if tag is not None:
            p["DestinationTag"] = tag
        return p

    denials, _ = policy_denials(pay_to(7), action="send")
    check("allowlisted (address, tag) passes", denials == [])
    denials, _ = policy_denials(pay_to(8), action="send")
    check("wrong tag denied", any("destination_allowlist" in d or
                                  "not in" in d for d in denials))
    denials, _ = policy_denials(pay_to(None), action="send")
    check("missing tag denied", any("not in" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 17. RequireDestTag (fail closed on lookup trouble) ---
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(
        pay_to(None), action="send", client=FakeClient(require_tag=True))
    check("RequireDestTag destination without tag denied",
          any("requires a destination tag" in d for d in denials))
    denials, _ = policy_denials(
        pay_to(None), action="send", client=FakeClient(tag_error=True))
    check("RequireDestTag lookup error fails closed (no fee burned)",
          any("fail closed" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 18. X-address / CLI tag conflict (proposer-side) ---
    from xrpl.core.addresscodec import classic_address_to_xaddress
    xa = classic_address_to_xaddress(R, 7, False)
    try:
        T.resolve_destination(xa, 8)
        check("X-address/CLI tag conflict rejected", False)
    except SystemExit:
        check("X-address/CLI tag conflict rejected", True)
    addr, tag = T.resolve_destination(xa, 7)
    check("matching X-address/CLI tags accepted", tag == 7 and addr == R)

    # --- 19. real address validation in setup ---
    check("valid classic address accepted",
          C.is_valid_classic_address(ACCT))
    check("corrupted checksum rejected",
          not C.is_valid_classic_address(ACCT[:-1] + ("1" if ACCT[-1] != "1" else "2")))
    check("non-address rejected", not C.is_valid_classic_address("hello"))

    # --- 20. policy file is read live (tampering changes enforcement) ---
    denials, _ = policy_denials(big_xrp, action="send")
    check("50 XRP denied under live policy", any("per-tx limit" in d for d in denials))
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    pol["spend_limits"]["XRP"] = {"per_tx": "100", "per_day": "1000"}
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(big_xrp, action="send")
    check("raised caps in policy file take effect", denials == [])
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 21. true rolling-24h window (no reset-boundary doubling) ---
    now = int(time.time())
    C.STATE_PATH.write_text(json.dumps({"entries": [
        {"rid": "old", "ts": now - 90000, "asset": "XRP", "amount": "50",
         "status": "confirmed", "tx_hash": None, "last_ledger": None},
        {"rid": "recent", "ts": now - 3600, "asset": "XRP", "amount": "90",
         "status": "confirmed", "tx_hash": None, "last_ledger": None},
    ]}))
    tracker = C.SpentTracker()
    cpol = {"spend_limits": {"XRP": {"per_tx": "25", "per_day": "100"}}}
    check("25h-old spend no longer counts",
          tracker.check({"XRP": Decimal("5")}, cpol) == [])
    check("recent spend still counts toward the rolling cap",
          any("rolling-24h" in d
              for d in tracker.check({"XRP": Decimal("20")}, cpol)))
    C.STATE_PATH.unlink()

    # --- 22. concurrent reservation still atomic ---
    tracker = C.SpentTracker()
    cpol2 = {"spend_limits": {"XRP": {"per_tx": "10", "per_day": "25"}}}
    outcomes = []

    def worker():
        outcomes.append(tracker.try_reserve({"XRP": Decimal("10")}, cpol2)[0])

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok_n = sum(1 for d in outcomes if d == [])
    st = json.loads(C.STATE_PATH.read_text())
    total = sum(Decimal(e["amount"]) for e in st["entries"])
    check("concurrent reserves never exceed daily cap",
          total <= 25 and ok_n == 2 and total == 20)
    C.STATE_PATH.unlink()

    # --- 23. ambiguous submission: reservation HELD, swept later ---
    tracker = C.SpentTracker()
    denials, rid = tracker.try_reserve({"XRP": Decimal("1")}, cpol)
    check("reservation created", denials == [] and rid)
    tracker.bind_reservation(rid, "AA" * 32, 999)
    # node down during sweep -> stays pending (fail closed, never released)
    tracker.sweep_pending(FakeSweep(ledger_index=2000, raise_tx=True))
    st = json.loads(C.STATE_PATH.read_text())
    check("ambiguous outcome keeps reservation pending",
          len(st["entries"]) == 1 and st["entries"][0]["status"] == "pending")
    # tx provably never included after last ledger -> released
    tracker.sweep_pending(FakeSweep(ledger_index=2000, tx_found=False))
    st = json.loads(C.STATE_PATH.read_text())
    check("proven non-inclusion releases the reservation",
          st["entries"] == [])
    # validated success -> confirmed (keeps counting)
    denials, rid = tracker.try_reserve({"XRP": Decimal("1")}, cpol)
    tracker.bind_reservation(rid, "BB" * 32, 999)
    tracker.sweep_pending(FakeSweep(ledger_index=2000, tx_found=True,
                                    tx_result="tesSUCCESS"))
    st = json.loads(C.STATE_PATH.read_text())
    check("validated success confirms the reservation",
          len(st["entries"]) == 1 and st["entries"][0]["status"] == "confirmed")
    # validated failure -> released
    denials, rid = tracker.try_reserve({"XRP": Decimal("1")}, cpol)
    tracker.bind_reservation(rid, "CC" * 32, 999)
    tracker.sweep_pending(FakeSweep(ledger_index=2000, tx_found=True,
                                    tx_result="tecUNFUNDED_PAYMENT"))
    st = json.loads(C.STATE_PATH.read_text())
    check("validated failure releases the reservation",
          all(e["tx_hash"] != "CC" * 32 for e in st["entries"]))
    # ledger not yet past last_ledger -> untouched
    denials, rid = tracker.try_reserve({"XRP": Decimal("1")}, cpol)
    tracker.bind_reservation(rid, "DD" * 32, 5000)
    tracker.sweep_pending(FakeSweep(ledger_index=2000, tx_found=False))
    st = json.loads(C.STATE_PATH.read_text())
    check("unexpired last_ledger keeps reservation pending",
          any(e["tx_hash"] == "DD" * 32 and e["status"] == "pending"
              for e in st["entries"]))
    # pre-sign failure path: unbound reservation released by id
    denials, rid = tracker.try_reserve({"XRP": Decimal("1")}, cpol)
    tracker.release_reservation(rid)
    st = json.loads(C.STATE_PATH.read_text())
    check("pre-sign failure releases by reservation id",
          all(e.get("rid") != rid for e in st["entries"]))
    # v0.3 bucket format migrates
    C.STATE_PATH.write_text(json.dumps(
        {"window_start": now - 3600, "totals": {"XRP": "7"}}))
    check("v0.3 state migrates to entries",
          tracker.check({"XRP": Decimal("1")}, cpol) == [] and
          any("rolling-24h" in d
              for d in tracker.check({"XRP": Decimal("95")}, cpol)))
    C.STATE_PATH.unlink()

    # --- 24. protected signer state ---
    for p in (C.POLICY_PATH, C.APPROVED_PATH, C.AUDIT_PATH):
        if p.exists():
            p.chmod(0o600)
    C.AUDIT_PATH.write_text("")  # ensure it exists
    C.AUDIT_PATH.chmod(0o600)
    try:
        C.check_protected_files()
        check("owner-only state files pass the guard", True)
    except SystemExit:
        check("owner-only state files pass the guard", False)
    C.POLICY_PATH.chmod(0o644)
    try:
        C.check_protected_files()
        check("world-readable policy refused", False)
    except SystemExit:
        check("world-readable policy refused", True)
    C.POLICY_PATH.chmod(0o600)

    # --- 25. network lock ---
    denials, _ = policy_denials(ok_tx, network="mainnet")
    check("mainnet locked by default", any("network_lock" in d for d in denials))

    # --- 26. fee cap ---
    fee_tx = dict(tx0)
    fee_tx["Fee"] = "5000"
    denials, _ = policy_denials(fee_tx)
    check("fee cap enforced", any("fee" in d for d in denials))

    # --- 27. offer without expiry ---
    noexp = dict(tx0)
    del noexp["Expiration"]
    denials, _ = policy_denials(noexp)
    check("offer without Expiration denied",
          any("Expiration" in d for d in denials))

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
