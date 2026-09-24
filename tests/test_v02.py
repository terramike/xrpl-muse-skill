#!/usr/bin/env python3
"""v0.2 logic tests — no network. Run: python3 tests/test_v02.py"""
import importlib.util
import json
import os
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(name, str(BIN / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


C = load("xrpl_common.py")
T = load("xrpl-trade")  # builders only; no network touched below

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


# --- currency encoding roundtrip ---
check("RLUSD hex-encodes to 40 chars", len(C.currency_code("RLUSD")) == 40)
check("RLUSD roundtrips", C.display_currency(C.currency_code("RLUSD")) == "RLUSD")
check("XRP passes through", C.currency_code("XRP") == "XRP")

# --- buy/sell direction (the ed8fa202 regression) ---
buy = T.build_offer_tx("rX", "ARMY", "rISS", "XRP", None,
                       Decimal("1000"), Decimal("0.005"), "buy", 3600).to_xrpl()
check("buy: TakerPays is BASE (ARMY)",
      buy["TakerPays"]["currency"] == C.currency_code("ARMY"))
check("buy: TakerGets is QUOTE (XRP drops)", isinstance(buy["TakerGets"], str))
check("buy: has Expiration", "Expiration" in buy)

sell = T.build_offer_tx("rX", "ARMY", "rISS", "XRP", None,
                        Decimal("1000"), Decimal("0.005"), "sell", 3600).to_xrpl()
check("sell: TakerGets is BASE (ARMY)",
      sell["TakerGets"]["currency"] == C.currency_code("ARMY"))
check("sell: TakerPays is QUOTE (XRP drops)", isinstance(sell["TakerPays"], str))

# --- proposal hashing ---
h1 = C.canonical_hash(buy)
h2 = C.canonical_hash(json.loads(json.dumps(buy)))  # roundtrip
check("hash deterministic across JSON roundtrip", h1 == h2)
buy2 = dict(buy); buy2["Sequence"] = 999
check("hash changes when tx changes", C.canonical_hash(buy2) != h1)

# --- token extraction from raw tx JSON (allowlist bypass impossible) ---
raw_offer = {"TransactionType": "OfferCreate",
             "TakerPays": {"currency": C.currency_code("FAKE"), "issuer": "rEvil", "value": "1"},
             "TakerGets": "1000000"}
check("tx_tokens catches raw-issuer token",
      C.tx_tokens(raw_offer) == {("FAKE", "rEvil")})
check("tx_tokens ignores XRP", C.tx_tokens(
    {"TransactionType": "Payment", "Amount": "1000000"}) == set())

# --- xrp at risk ---
check("offer xrp at risk",
      C.tx_xrp_at_risk(raw_offer) == Decimal("1"))
check("payment xrp at risk",
      C.tx_xrp_at_risk({"TransactionType": "Payment", "Amount": "2500000"})
      == Decimal("2.5"))
check("fee parsed",
      C.tx_fee_xrp({"Fee": "12"}) == Decimal("0.000012"))

# --- policy on synthetic proposals (no client needed for these types) ---
with tempfile.TemporaryDirectory() as td:
    C.XRPL_DIR = Path(td)
    C.PROPOSALS_DIR = Path(td) / "proposals"
    C.POLICY_PATH = Path(td) / "policy.json"
    C.STATE_PATH = Path(td) / "state.json"
    C.APPROVED_PATH = Path(td) / "approved.json"
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {
        "XRP/RLUSD": {"base": "XRP", "base_issuer": None, "quote": "RLUSD",
                      "quote_issuer": "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"}}}))
    C.POLICY_PATH.write_text(json.dumps(C.DEFAULT_POLICY))

    def prop(tx, network="testnet"):
        return {"proposal_hash": C.canonical_hash(tx), "network": network,
                "tx": tx, "action": "t", "summary": [], "meta": {}}

    pol = C.load_policy()
    S = load("xrpl-sign")

    good_ts = {"TransactionType": "TrustSet", "Account": "rX",
               "LimitAmount": {"currency": C.currency_code("RLUSD"),
                               "issuer": "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De",
                               "value": "1000"},
               "Fee": "12"}
    denials, _ = S.check_policy(prop(good_ts), pol, None)
    check("allowlisted trustline passes", denials == [])

    evil_ts = {"TransactionType": "TrustSet", "Account": "rX",
               "LimitAmount": {"currency": C.currency_code("FAKE"),
                               "issuer": "rEvil", "value": "1000"},
               "Fee": "12"}
    denials, _ = S.check_policy(prop(evil_ts), pol, None)
    check("non-allowlisted token denied",
          any("not in approved allowlist" in d for d in denials))

    mainnet = prop(good_ts, network="mainnet")
    denials, _ = S.check_policy(mainnet, pol, None)
    check("mainnet locked by default",
          any("network_lock" in d for d in denials))

    bigfee = dict(good_ts); bigfee["Fee"] = "5000"
    denials, _ = S.check_policy(prop(bigfee), pol, None)
    check("fee cap enforced", any("fee" in d for d in denials))

    pay = {"TransactionType": "Payment", "Account": "rX",
           "Destination": "rNobody", "Amount": "1000000", "Fee": "12"}
    denials, _ = S.check_policy(prop(pay), pol, None)
    check("payment to non-allowlisted dest denied",
          any("destination_allowlist" in d for d in denials))

    big = {"TransactionType": "Payment", "Account": "rX",
           "Destination": "rX", "Amount": "50000000", "Fee": "12"}
    pol2 = dict(pol); pol2["destination_allowlist"] = ["rX"]
    denials, _ = S.check_policy(prop(big), pol2, None)
    check("per-tx XRP cap enforced (50 XRP > 25)",
          any("per_tx_max" in d for d in denials))

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
