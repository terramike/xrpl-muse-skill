#!/usr/bin/env python3
"""v0.3 adversarial logic tests — no network. Run: python3 tests/test_v03.py

Covers the audit findings: unknown-tx rejection, extra-field rejection,
summary/meta tampering, network+timestamp tampering, unlimited IOU payments,
token/token offers, exact-pair enforcement, policy-file tampering,
X-address tag conflicts, and concurrent daily-limit enforcement.
"""
import importlib.util
import json
import sys
import tempfile
import threading
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
T = load(BIN / "xrpl-trade", "xrpl_trade_v03")
S = load(BIN / "xrpl-sign", "xrpl_sign_v03")

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
        """Canned book (mid ~1.5095 RLUSD/XRP) + account flags."""
        def __init__(self, empty_book=False, require_tag=False):
            self.empty_book = empty_book
            self.require_tag = require_tag
            self.calls = 0

        def request(self, req):
            from xrpl.models.requests import BookOffers, AccountInfo
            if isinstance(req, BookOffers):
                self.calls += 1
                if self.empty_book:
                    return FakeResp({"offers": []})
                if self.calls % 2 == 1:  # asks
                    return FakeResp({"offers": [{
                        "TakerPays": {"currency": RLUSD, "issuer": R,
                                      "value": "1.510000"},
                        "TakerGets": "1000000"}]})
                return FakeResp({"offers": [{  # bids
                    "TakerGets": {"currency": RLUSD, "issuer": R,
                                  "value": "1.509000"},
                    "TakerPays": "1000000"}]})
            if isinstance(req, AccountInfo):
                flags = 0x00020000 if self.require_tag else 0
                return FakeResp({"account_data": {"Flags": flags}})
            raise AssertionError(f"unexpected request {req!r}")

    def offer_tx(pays, gets, seq=1):
        return {"TransactionType": "OfferCreate", "Account": ACCT,
                "TakerPays": pays, "TakerGets": gets,
                "Expiration": 999999999, "Fee": "12",
                "Sequence": seq, "LastLedgerSequence": 999}

    def xrp(drops):
        return str(drops)

    def iou(ccy, iss, v):
        return {"currency": ccy, "issuer": iss, "value": v}

    def prop_of(tx, network="testnet"):
        h, path = C.save_proposal(tx, network, ACCT, "buy")
        return json.loads(path.read_text()), path, h

    def policy_denials(tx, network="testnet", client=None, action="buy"):
        prop, _, _ = prop_of(tx, network)
        pol = C.load_policy()
        return S.check_policy(prop, tx, pol, client or FakeClient(),
                              C.SpentTracker())

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
        check("valid envelope verifies", True)
    except C.ProposalError:
        check("valid envelope verifies", False)

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

    # --- 4. summary is derived from the tx, never stored/trusted ---
    lines = C.describe_tx(tx0, "buy")
    blob = "\n".join(lines)
    check("derived summary shows give (1.47 RLUSD)",
          "1.470000" in blob and "RLUSD" in blob)
    check("derived summary shows receive (1 XRP)", "1.000000 XRP" in blob)
    check("no summary stored in envelope", "summary" not in prop)

    # --- 5. unknown transaction types rejected ---
    srk = {"TransactionType": "SetRegularKey", "Account": ACCT,
           "RegularKey": DEST, "Fee": "12", "Sequence": 1}
    probs = C.validate_tx_shape(srk, C.DEFAULT_ALLOWED_TX_TYPES)
    check("SetRegularKey rejected by shape validation",
          any("not in the allowlist" in p for p in probs))
    denials, _ = policy_denials(srk)
    check("SetRegularKey denied by policy", len(denials) > 0)

    # --- 6. smuggled fields rejected ---
    pay_paths = {"TransactionType": "Payment", "Account": ACCT,
                 "Destination": DEST, "Amount": xrp("1000000"),
                 "Paths": [["x"]], "Fee": "12", "Sequence": 1}
    check("Payment+Paths rejected",
          any("Paths" in p for p in C.validate_tx_shape(
              pay_paths, C.DEFAULT_ALLOWED_TX_TYPES)))
    pay_partial = {"TransactionType": "Payment", "Account": ACCT,
                   "Destination": DEST, "Amount": xrp("1000000"),
                   "Flags": 131072, "Fee": "12", "Sequence": 1}
    check("Payment+tfPartialPayment rejected",
          any("Flags" in p for p in C.validate_tx_shape(
              pay_partial, C.DEFAULT_ALLOWED_TX_TYPES)))
    offer_memo = dict(tx0)
    offer_memo["Memos"] = [{"Memo": {"MemoData": "hi"}}]
    check("OfferCreate+Memos rejected",
          any("Memos" in p for p in C.validate_tx_shape(
              offer_memo, C.DEFAULT_ALLOWED_TX_TYPES)))

    # --- 7. missing required fields ---
    bad_offer = dict(tx0)
    del bad_offer["TakerGets"]
    check("OfferCreate without TakerGets flagged",
          any("TakerGets" in p for p in C.validate_tx_shape(
              bad_offer, C.DEFAULT_ALLOWED_TX_TYPES)))

    # --- 8. exact-pair enforcement (token/token bypass) ---
    # approved: XRP/RLUSD + ARMY/XRP. ARMY/RLUSD is NOT an approved pair.
    tt = offer_tx(iou(C.currency_code("ARMY"), ARMY_ISS, "100"),
                  iou(RLUSD, R, "0.5"))
    denials, _ = policy_denials(tt)
    check("unlisted ARMY/RLUSD offer denied (exact-pair)",
          any("exactly-approved pair" in d for d in denials))

    # --- 9. approved pair passes shape+pair (deviation stubbed near) ---
    ok_tx = offer_tx(xrp("1000000"), iou(RLUSD, R, "1.470000"))
    denials, spends = policy_denials(ok_tx)
    check("approved XRP/RLUSD offer passes", denials == [])
    check("spends measured on TakerGets (RLUSD 1.47)",
          spends.get(f"RLUSD.{R}") == Decimal("1.470000"))

    # --- 10. deviation still enforced from the tx ---
    far_tx = offer_tx(xrp("1000000"), iou(RLUSD, R, "1.300000"))
    denials, _ = policy_denials(far_tx)
    check("13.9% off-mid offer denied", any("deviates" in d for d in denials))
    denials, _ = policy_denials(ok_tx, client=FakeClient(empty_book=True))
    check("empty book fails closed", any("empty book" in d for d in denials))

    # --- 11. per-asset caps: the 999999999999 TOK payment ---
    huge = {"TransactionType": "Payment", "Account": ACCT,
            "Destination": DEST, "Amount": iou(RLUSD, R, "999999999999"),
            "Fee": "12", "Sequence": 1}
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(huge)
    check("999999999999 RLUSD payment denied (per-tx)",
          any("per-tx limit" in d for d in denials))
    big_xrp = {"TransactionType": "Payment", "Account": ACCT,
               "Destination": DEST, "Amount": xrp("50000000"),
               "Fee": "12", "Sequence": 1}
    denials, _ = policy_denials(big_xrp)
    check("50 XRP payment denied (per-tx)", any("per-tx limit" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))  # restore

    # --- 12. asset with no configured limit fails closed ---
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/FOO": {"base": "XRP", "base_issuer": None, "quote": "FOO",
                    "quote_issuer": FOO_ISS}}}))
    foo_pay = {"TransactionType": "Payment", "Account": ACCT,
               "Destination": DEST,
               "Amount": iou(C.currency_code("FOO"), FOO_ISS, "1"),
               "Fee": "12", "Sequence": 1}
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(foo_pay)
    check("allowlisted-but-unlimited asset fails closed",
          any("no spend limit" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/RLUSD": {"base": "XRP", "base_issuer": None,
                      "quote": "RLUSD", "quote_issuer": R},
        "ARMY/XRP": {"base": "ARMY", "base_issuer": ARMY_ISS,
                     "quote": "XRP", "quote_issuer": None}}}))

    # --- 13. destination (address, tag) exact matching ---
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": 7}]
    C.POLICY_PATH.write_text(json.dumps(pol))

    def pay_to(tag):
        p = {"TransactionType": "Payment", "Account": ACCT,
             "Destination": DEST, "Amount": xrp("1000000"),
             "Fee": "12", "Sequence": 1}
        if tag is not None:
            p["DestinationTag"] = tag
        return p

    denials, _ = policy_denials(pay_to(7))
    check("allowlisted (address, tag) passes", denials == [])
    denials, _ = policy_denials(pay_to(8))
    check("wrong tag denied", any("destination_allowlist" in d or
                                  "not in" in d for d in denials))
    denials, _ = policy_denials(pay_to(None))
    check("missing tag denied", any("not in" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 14. RequireDestTag ---
    denials, _ = policy_denials(
        pay_to(None), client=FakeClient(require_tag=True))
    # (also fails allowlist since base_policy has empty dest list; check tag msg)
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(
        pay_to(None), client=FakeClient(require_tag=True))
    check("RequireDestTag destination without tag denied",
          any("requires a destination tag" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 15. X-address / CLI tag conflict (proposer-side) ---
    from xrpl.core.addresscodec import classic_address_to_xaddress
    xa = classic_address_to_xaddress(R, 7, False)
    try:
        T.resolve_destination(xa, 8)
        check("X-address/CLI tag conflict rejected", False)
    except SystemExit:
        check("X-address/CLI tag conflict rejected", True)
    addr, tag = T.resolve_destination(xa, 7)
    check("matching X-address/CLI tags accepted", tag == 7 and addr == R)

    # --- 16. policy file is read live (tampering changes enforcement) ---
    denials, _ = policy_denials(big_xrp)
    check("50 XRP denied under live policy", any("per-tx limit" in d for d in denials))
    pol = C.load_policy()
    pol["destination_allowlist"] = [{"address": DEST, "destination_tag": None}]
    pol["spend_limits"]["XRP"] = {"per_tx": "100", "per_day": "1000"}
    C.POLICY_PATH.write_text(json.dumps(pol))
    denials, _ = policy_denials(big_xrp)
    check("raised caps in policy file take effect", denials == [])
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    # --- 17. concurrent daily-limit reservation ---
    tracker = C.SpentTracker()
    cpol = {"spend_limits": {"XRP": {"per_tx": "10", "per_day": "25"}}}
    outcomes = []

    def worker():
        outcomes.append(tracker.try_reserve({"XRP": Decimal("10")}, cpol))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok_n = sum(1 for d in outcomes if d == [])
    st = json.loads(C.STATE_PATH.read_text())
    total = Decimal(st["totals"]["XRP"])
    check("concurrent reserves never exceed daily cap",
          total <= 25 and ok_n == 2 and total == 20)

    # --- 18. network lock ---
    denials, _ = policy_denials(ok_tx, network="mainnet")
    check("mainnet locked by default", any("network_lock" in d for d in denials))

    # --- 19. fee cap ---
    fee_tx = dict(tx0)
    fee_tx["Fee"] = "5000"
    denials, _ = policy_denials(fee_tx)
    check("fee cap enforced", any("fee" in d for d in denials))

    # --- 20. offer without expiry ---
    noexp = dict(tx0)
    del noexp["Expiration"]
    denials, _ = policy_denials(noexp)
    check("offer without Expiration denied",
          any("Expiration" in d for d in denials))

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
