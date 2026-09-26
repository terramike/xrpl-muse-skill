"""Offline unit tests for P1-5 book_reference changes (mocked client, no network)."""
import sys, types
from pathlib import Path
BIN = Path(__file__).resolve().parents[1] / "bin"
from decimal import Decimal

sys.path.insert(0, str(BIN))
src = open(str(BIN / "xrpl-sign")).read()
mod = types.ModuleType("xrpl_sign")
mod.__file__ = "xrpl-sign"
exec(compile(src, "xrpl-sign", "exec"), mod.__dict__)
import xrpl_common as C

RLUSD = "524C555344" + "0"*30
ISS = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"

# Hermetic approved-pairs fixture: XRP/RLUSD, base=XRP quote=RLUSD.
C.load_approved = lambda: {"XRP/RLUSD": {"base": "XRP", "base_issuer": None,
                                        "quote": "RLUSD", "quote_issuer": ISS}}

def rlusd(v):
    return {"currency": RLUSD, "issuer": ISS, "value": str(v)}

def xrp_drops(xrp):
    return str(int(Decimal(str(xrp)) * 1_000_000))

class Resp:
    def __init__(self, result, ok=True):
        self.result = result
        self._ok = ok
    def is_successful(self):
        return self._ok

class FakeClient:
    """Routes Ledger -> pinned index; BookOffers -> canned sides; records requests."""
    def __init__(self, ledger_index=9012345, asks=(), bids=(),
                 fail_ledger=False, echo_wrong=False):
        self.ledger_index = ledger_index
        self.asks, self.bids = asks, bids
        self.fail_ledger = fail_ledger
        self.echo_wrong = echo_wrong
        self.seen = []
    def request(self, req):
        self.seen.append(req)
        name = type(req).__name__
        if name == "Ledger":
            if self.fail_ledger:
                return Resp({}, ok=False)
            return Resp({"ledger_index": self.ledger_index})
        if name == "BookOffers":
            echo = self.ledger_index if not self.echo_wrong else self.ledger_index + 1
            side = self.asks if req.taker_gets == mod._cur_from_amount(
                xrp_drops(1)).__class__ and str(req.taker_gets) != "XRP" or True else ()
            # decide side by which taker_gets currency was requested
            tg = req.taker_gets
            is_xrp = getattr(tg, "currency", None) is None and type(tg).__name__ == "XRP"
            offers = self.asks if is_xrp else self.bids
            # NOTE: routing by request order is brittle; instead route by
            # call count: first BookOffers = asks, second = bids.
            n = sum(1 for r in self.seen if type(r).__name__ == "BookOffers")
            offers = self.asks if n == 1 else self.bids
            return Resp({"offers": list(offers), "ledger_index": echo})
        raise AssertionError(f"unexpected request {name}")

POLICY = {"min_book_depth": "5", "max_spread_bps": 1000,
          "max_deviation_bps": 200}

def mk_offer(taker_gets, taker_pays, funded_gets=None, funded_pays=None):
    o = {"TakerGets": taker_gets, "TakerPays": taker_pays}
    if funded_gets is not None:
        o["taker_gets_funded"] = funded_gets
    if funded_pays is not None:
        o["taker_pays_funded"] = funded_pays
    return o

passed = []
def check(name, cond, extra=""):
    passed.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f" — {extra}" if extra and not cond else ""))

# ---- 1. happy path: BUY 1 XRP (pays=XRP base, gets=RLUSD quote) ----
# asks side: BookOffers(taker_gets=XRP, taker_pays=RLUSD): offers selling XRP for RLUSD
asks = [mk_offer(xrp_drops(2), rlusd(3.1)),      # fully funded: 2 XRP / 3.1 RLUSD
        mk_offer(xrp_drops(4), rlusd(6.3),
                 funded_gets=xrp_drops(4), funded_pays=rlusd(6.3))]
# bids side: BookOffers(taker_gets=RLUSD, taker_pays=XRP): offers buying XRP with RLUSD
bids = [mk_offer(rlusd(3.0), xrp_drops(2)),
        mk_offer(rlusd(6.0), xrp_drops(4),
                 funded_gets=rlusd(6.0), funded_pays=xrp_drops(4))]
cli = FakeClient(asks=asks, bids=bids)
pays, gets = xrp_drops(1), rlusd(1.55635)   # BUY: TakerPays=base, TakerGets=quote
mid, problem = mod.book_reference(cli, pays, gets, POLICY)
check("happy-path returns mid", mid is not None and problem is None, f"{mid} {problem}")
# both book reads pinned to the same explicit ledger
book_reqs = [r for r in cli.seen if type(r).__name__ == "BookOffers"]
check("both sides use pinned ledger index",
      len(book_reqs) == 2 and all(r.ledger_index == 9012345 for r in book_reqs),
      str([getattr(r, "ledger_index", None) for r in book_reqs]))
# expected mid: asks dw = (3.1/2*3.1 + 6.3/4*6.3)/(3.1+6.3) in RLUSD per XRP
exp_ask = (Decimal("3.1")/2*Decimal("3.1") + Decimal("6.3")/4*Decimal("6.3"))/(Decimal("3.1")+Decimal("6.3"))
exp_bid = (Decimal("3.0")/2*Decimal("3.0") + Decimal("6.0")/4*Decimal("6.0"))/(Decimal("3.0")+Decimal("6.0"))
check("mid matches funded depth-weighted value",
      mid is not None and abs(mid - (exp_ask+exp_bid)/2) < Decimal("1e-9"), f"{mid}")

# ---- 2. audit attack: huge nominal, 0.001 funded vs 5-unit minimum ----
thin_asks = [mk_offer(xrp_drops(1000), rlusd(1550),
                      funded_gets=xrp_drops("0.0005"), funded_pays=rlusd("0.001"))]
thin_bids = [mk_offer(rlusd(1550), xrp_drops(1000),
                      funded_gets=rlusd("0.001"), funded_pays=xrp_drops("0.0005"))]
cli2 = FakeClient(asks=thin_asks, bids=thin_bids)
mid2, prob2 = mod.book_reference(cli2, pays, gets, POLICY)
check("phantom liquidity denied (thin book)",
      mid2 is None and prob2 is not None and "too thin" in prob2, f"{mid2} {prob2}")
check("denial names quote asset", prob2 is not None and "RLUSD" in prob2, str(prob2))

# ---- 3. funded field present-but-zero with nonzero nominal -> zero ----
zero_asks = [mk_offer(xrp_drops(1000), rlusd(1550),
                      funded_gets=xrp_drops(0), funded_pays=rlusd(0))]
zero_bids = [mk_offer(rlusd(1550), xrp_drops(1000),
                      funded_gets=rlusd(0), funded_pays=xrp_drops(0))]
cli3 = FakeClient(asks=zero_asks, bids=zero_bids)
mid3, prob3 = mod.book_reference(cli3, pays, gets, POLICY)
check("zero-funded levels contribute nothing",
      mid3 is None and prob3 is not None, f"{mid3} {prob3}")

# ---- 4. ledger pin failure -> fail closed ----
cli4 = FakeClient(asks=asks, bids=bids, fail_ledger=True)
mid4, prob4 = mod.book_reference(cli4, pays, gets, POLICY)
check("ledger pin failure denies", mid4 is None and "pin validated ledger" in (prob4 or ""), str(prob4))

# ---- 5. ledger echo mismatch -> fail closed ----
cli5 = FakeClient(asks=asks, bids=bids, echo_wrong=True)
mid5, prob5 = mod.book_reference(cli5, pays, gets, POLICY)
check("mixed-ledger echo denied", mid5 is None and "same validated ledger" in (prob5 or ""), str(prob5))

# ---- 6. SELL direction: depth still measured in QUOTE (RLUSD) ----
# SELL 1 XRP: TakerPays=RLUSD (quote), TakerGets=XRP (base)
spays, sgets = rlusd(1.55635), xrp_drops(1)
# asks: taker_gets=RLUSD, taker_pays=XRP ; bids: taker_gets=XRP, taker_pays=RLUSD
sasks = [mk_offer(rlusd(3.0), xrp_drops(2)), mk_offer(rlusd(6.0), xrp_drops(4))]
sbids = [mk_offer(xrp_drops(2), rlusd(3.1)), mk_offer(xrp_drops(4), rlusd(6.3))]
cli6 = FakeClient(asks=sasks, bids=sbids)
mid6, prob6 = mod.book_reference(cli6, spays, sgets, POLICY)
check("sell direction passes with quote depth", mid6 is not None, str(prob6))
# now starve the quote side on a sell: funded RLUSD 0.001 per side
sasks_t = [mk_offer(rlusd(1550), xrp_drops(1000),
                    funded_gets=rlusd("0.001"), funded_pays=xrp_drops("0.0005"))]
sbids_t = [mk_offer(xrp_drops(1000), rlusd(1550),
                    funded_gets=xrp_drops("0.0005"), funded_pays=rlusd("0.001"))]
cli6b = FakeClient(asks=sasks_t, bids=sbids_t)
mid6b, prob6b = mod.book_reference(cli6b, spays, sgets, POLICY)
check("sell direction thin-quote denied", mid6b is None and "too thin" in (prob6b or ""), str(prob6b))
check("sell denial names quote asset", prob6b is not None and "RLUSD" in prob6b, str(prob6b))

# ---- 7. one-sided / crossed books still deny ----
cli7 = FakeClient(asks=asks, bids=[])
mid7, prob7 = mod.book_reference(cli7, pays, gets, POLICY)
check("one-sided book denies", mid7 is None and "one-sided" in (prob7 or ""), str(prob7))
# crossed: asks priced BELOW bids (in gets per pays)
c_asks = [mk_offer(xrp_drops(2), rlusd(2.0))]   # ask 1.0 RLUSD/XRP
c_bids = [mk_offer(rlusd(6.0), xrp_drops(4))]   # bid 1.5 RLUSD/XRP -> crossed
cli8 = FakeClient(asks=c_asks, bids=c_bids)
mid8, prob8 = mod.book_reference(cli8, pays, gets, {"min_book_depth": "0.5", "max_spread_bps": 100000})
check("crossed book denies", mid8 is None and "crossed" in (prob8 or ""), str(prob8))

# ---- 8. check_deviation still works end-to-end (orientation untouched) ----
tx = {"TakerPays": xrp_drops(1), "TakerGets": rlusd(1.55635)}
cli9 = FakeClient(asks=asks, bids=bids)
dev = mod.check_deviation(cli9, tx, POLICY)
check("deviation passes near mid", dev is None, str(dev))
tx_far = {"TakerPays": xrp_drops(1), "TakerGets": rlusd(3.0)}  # ~2x mid
dev2 = mod.check_deviation(FakeClient(asks=asks, bids=bids), tx_far, POLICY)
check("deviation denies far limit", dev2 is not None and "deviates" in dev2, str(dev2))

fails = [n for n, ok in passed if not ok]
print(f"\n{len(passed)-len(fails)}/{len(passed)} passed")
sys.exit(1 if fails else 0)
