#!/usr/bin/env python3
"""Regression tests for nft_sell_price — no network. Run: python3 tests/test_nft_sell_price.py

Covers the 2026-09-30 crash: an NFT with sell offers whose first offer has
no readable "Amount" made fmt_amount(None) raise TypeError, killing
`xrpl-trade nft-new` mid-scan. nft_sell_price must degrade to a soft
(no-price, problem-text) result instead.
"""
import importlib.util
import sys
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


C = load(BIN / "xrpl_common.py", "xrpl_common_sellprice")

PASS = []


def check(name, ok):
    PASS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name)


class FakeResp:
    def __init__(self, offers, ok=True):
        self._offers = offers
        self._ok = ok

    def is_successful(self):
        return self._ok

    @property
    def result(self):
        return {"offers": self._offers}


class FakeClient:
    def __init__(self, offers, ok=True):
        self._offers = offers
        self._ok = ok

    def request(self, req):
        return FakeResp(self._offers, self._ok)


# 1. Offer with no Amount at all -> soft result, no crash
price, problem = C.nft_sell_price(FakeClient([{"nft_offer_index": "ABC"}]), "TOKEN")
check("offer missing Amount returns no price with problem text",
      price is None and problem is not None and "Amount" in problem)

# 2. Offer with explicit Amount: null -> same soft result
price, problem = C.nft_sell_price(FakeClient([{"Amount": None}]), "TOKEN")
check("offer with null Amount returns no price with problem text",
      price is None and problem is not None)

# 3. Normal XRP-denominated offer still prices
price, problem = C.nft_sell_price(FakeClient([{"Amount": "2000000"}]), "TOKEN")
check("XRP offer prices normally",
      price is not None and "XRP" in price and problem is None)

# 4. No offers -> (None, None), unchanged
price, problem = C.nft_sell_price(FakeClient([]), "TOKEN")
check("no offers returns (None, None)", price is None and problem is None)

# 5. Mixed: bad first offer, good XRP second offer -> cheapest XRP wins
price, problem = C.nft_sell_price(
    FakeClient([{"nft_offer_index": "BAD"}, {"Amount": "5000000"}]), "TOKEN")
check("XRP offer still found when first offer is malformed",
      price is not None and "XRP" in price and problem is None)

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
