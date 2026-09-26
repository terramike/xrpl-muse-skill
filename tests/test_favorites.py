#!/usr/bin/env python3
"""Artist favorites + nft-new unit/adversarial tests — no network.

Run: python3 tests/test_favorites.py

Covers: favorite-name validation, classic-address checksum refusal,
duplicate/rename/remove semantics, 0600 file creation, corrupt-file
handling, protected-file inclusion, name/address resolution for read
commands, URI decoding, mint-token-ID extraction from tx metadata
(CreatedNode + ModifiedNode diff), account_tx window/watermark
filtering, pagination cap, sell-price extraction (XRP lowest, IOU,
not-listed, lookup failure), the xrp.cafe link format, watermark
advance semantics (--days never moves it), and empty-favorites
handling. The ledger is stubbed; nothing touches the network.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
from contextlib import redirect_stdout
from decimal import Decimal
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


C = load(BIN / "xrpl_common.py", "xrpl_common")
T = load(BIN / "xrpl-trade", "xrpl_trade_fav")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet  # noqa: E402

GOOD_ADDR = Wallet.create().classic_address
GOOD_ADDR2 = Wallet.create().classic_address
BAD_ADDR = GOOD_ADDR[:-1] + ("1" if GOOD_ADDR[-1] != "1" else "2")
NID1 = "0008000000000000000000000000000000000000000000000000000000000001"
NID2 = "0008000000000000000000000000000000000000000000000000000000000002"
URI_HEX = "ipfs://bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvy".encode().hex()
ISSUER = Wallet.create().classic_address


class FakeResp:
    def __init__(self, result, ok=True):
        self.result = result
        self._ok = ok

    def is_successful(self):
        return self._ok


class FakeClient:
    """Canned ledger. handlers: method -> fn(request_dict) -> FakeResp."""

    def __init__(self, handlers):
        self.handlers = handlers
        self.calls = []

    def request(self, req):
        d = req.to_dict()
        self.calls.append(d["method"])
        h = self.handlers.get(d["method"])
        if h is None:
            raise AssertionError(f"unexpected request {d['method']}")
        return h(d)


def mint_entry(ledger_index, ripple_date, uri_hex, taxon, meta):
    return {"ledger_index": ledger_index,
            "tx": {"TransactionType": "NFTokenMint", "Account": GOOD_ADDR,
                   "URI": uri_hex, "NFTokenTaxon": taxon,
                   "date": ripple_date},
            "meta": meta, "validated": True}


def created_meta(nid, uri_hex):
    return {"AffectedNodes": [
        {"CreatedNode": {"LedgerEntryType": "NFTokenPage",
                         "NewFields": {"NFTokens": [
                             {"NFToken": {"NFTokenID": nid,
                                          "URI": uri_hex}}]}}}]}

class A:
    """argparse-like namespace."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def expect_exit(fn):
    try:
        fn()
    except SystemExit:
        return True
    return False


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    C.XRPL_DIR = tmp
    C.POLICY_PATH = tmp / "policy.json"
    C.STATE_PATH = tmp / "state.json"
    C.STATE_LOCK_PATH = tmp / "state.lock"
    C.AUDIT_PATH = tmp / "audit.log"
    C.APPROVED_PATH = tmp / "approved.json"
    C.FAVORITES_PATH = tmp / "favorites.json"
    fav_file = C.FAVORITES_PATH

    # --- 1. name validation ---
    for good in ["lara", "a", "x1-y_z", "0abc", "a" * 32]:
        check(f"name {good!r} accepted",
              C.validate_favorite_name(good) is None)
    for bad in ["LARA", "a b", "", "a" * 33, "-lead", "dot.name",
                "semi;colon", "ünïcode"]:
        check(f"name {bad!r} refused",
              C.validate_favorite_name(bad) is not None)

    # --- 2. classic-address checksum ---
    check("real classic address valid",
          C.is_valid_classic_address(GOOD_ADDR))
    check("corrupted checksum refused",
          not C.is_valid_classic_address(BAD_ADDR))
    check("plain name is not an address",
          not C.is_valid_classic_address("lara"))

    # --- 3. favorites round trip through the command layer ---
    check("starts empty", C.load_favorites() == {})
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_favorites(A(fav_cmd="add", name="lara", address=GOOD_ADDR,
                           note="test artist"))
    check("add prints confirmation", "lara" in out.getvalue())
    check("file created owner-only",
          fav_file.exists() and (fav_file.stat().st_mode & 0o777) == 0o600)
    check("duplicate add refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="add", name="lara", address=GOOD_ADDR2, note=None))))
    check("uppercase name refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="add", name="LARA", address=GOOD_ADDR2, note=None))))
    check("bad-checksum address refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="add", name="bad", address=BAD_ADDR, note=None))))
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_favorites(A(fav_cmd="list"))
    check("list shows the favorite",
          "lara" in out.getvalue() and GOOD_ADDR in out.getvalue())
    check("rename missing refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="rename", old="ghost", new="spook"))))
    with redirect_stdout(io.StringIO()):
        T.cmd_favorites(A(fav_cmd="rename", old="lara", new="larva"))
    with redirect_stdout(io.StringIO()):
        T.cmd_favorites(A(fav_cmd="add", name="x", address=GOOD_ADDR2,
                           note=None))
    check("rename onto existing name refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="rename", old="larva", new="x"))))
    check("remove missing refused",
          expect_exit(lambda: T.cmd_favorites(
              A(fav_cmd="remove", name="ghost"))))
    with redirect_stdout(io.StringIO()):
        T.cmd_favorites(A(fav_cmd="remove", name="larva"))
        T.cmd_favorites(A(fav_cmd="remove", name="x"))
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_favorites(A(fav_cmd="list"))
    check("empty list is friendly, not an error",
          "no favorites yet" in out.getvalue())

    # --- 4. corrupt file fails loud ---
    fav_file.write_text("{not json")
    try:
        C.load_favorites()
        check("corrupt favorites raises", False)
    except C.FavoritesError:
        check("corrupt favorites raises", True)
    fav_file.unlink()

    # --- 5. protected-file check covers favorites.json ---
    fav_file.write_text("{}")
    os.chmod(fav_file, 0o644)
    check("group-readable favorites.json fails the protected check",
          expect_exit(C.check_protected_files))
    os.chmod(fav_file, 0o600)
    check("owner-only favorites.json passes the protected check",
          not expect_exit(C.check_protected_files))
    fav_file.unlink()

    # --- 6. name/address resolution for read commands ---
    favs = {"lara": {"address": GOOD_ADDR, "added_at": 1,
                     "last_checked_ledger": None}}
    addr, prob = C.resolve_fav_or_addr("lara", favs)
    check("favorite name resolves", addr == GOOD_ADDR and prob is None)
    addr, prob = C.resolve_fav_or_addr(GOOD_ADDR2, {})
    check("raw address passes through", addr == GOOD_ADDR2 and prob is None)
    addr, prob = C.resolve_fav_or_addr("nope", {})
    check("garbage is a problem, not a guess",
          addr is None and prob is not None)
    addr, prob = C.resolve_fav_or_addr(BAD_ADDR, {})
    check("bad-checksum address refused by resolver",
          addr is None and prob is not None)

    # --- 7. URI decoding ---
    check("hex URI decodes",
          C.decode_nft_uri(URI_HEX) == bytes.fromhex(URI_HEX).decode())
    check("non-hex URI is explicit",
          C.decode_nft_uri("zzzz") == "<uri is not valid hex>")
    check("long URI truncates",
          C.decode_nft_uri("ab" * 100, 90).endswith("…"))

    # --- 8. token-id extraction from mint metadata ---
    check("CreatedNode yields the new token id",
          C.extract_mint_token_ids(created_meta(NID1, URI_HEX)) == [NID1])
    modified = {"AffectedNodes": [
        {"ModifiedNode": {"LedgerEntryType": "NFTokenPage",
                          "FinalFields": {"NFTokens": [
                              {"NFToken": {"NFTokenID": NID1}},
                              {"NFToken": {"NFTokenID": NID2}}]},
                          "PreviousFields": {"NFTokens": [
                              {"NFToken": {"NFTokenID": NID1}}]}}}]}
    check("ModifiedNode diff yields only the new token id",
          C.extract_mint_token_ids(modified) == [NID2])
    check("garbage metadata yields []",
          C.extract_mint_token_ids(None) == []
          and C.extract_mint_token_ids({"AffectedNodes": None}) == [])

    # --- 9. account_tx window / watermark filtering ---
    now_ripple = int(time.time()) - C.RIPPLE_EPOCH
    pay_entry = {"ledger_index": 100,
                 "tx": {"TransactionType": "Payment", "Account": GOOD_ADDR,
                        "date": now_ripple - 100},
                 "meta": {}, "validated": True}

    # window: mint 1d ago kept, mint 10d ago stops the walk
    m1 = mint_entry(100, now_ripple - 86400, URI_HEX, 0,
                    created_meta(NID1, URI_HEX))
    m2 = mint_entry(90, now_ripple - 10 * 86400, URI_HEX, 1,
                    created_meta(NID2, URI_HEX))
    calls = {"n": 0}

    def win_handler(d):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResp({"transactions": [m1, pay_entry],
                             "marker": "m1"})
        return FakeResp({"transactions": [m2], "marker": None})

    fc = FakeClient({"account_tx": win_handler})
    mints, pages, prob = C.scan_artist_mints(
        fc, GOOD_ADDR, cutoff_unix=int(time.time()) - 7 * 86400)
    check("window keeps in-window mint, drops old + non-mint",
          prob is None and len(mints) == 1
          and mints[0]["token_ids"] == [NID1]
          and mints[0]["taxon"] == 0)
    check("walk stops at first out-of-window tx", pages == 2)

    # watermark: only ledger_index > watermark reported
    def wm_handler(d):
        return FakeResp({"transactions": [
            mint_entry(100, now_ripple - 100, URI_HEX, 0,
                       created_meta(NID1, URI_HEX)),
            mint_entry(90, now_ripple - 200, URI_HEX, 0,
                       created_meta(NID2, URI_HEX)),
            mint_entry(80, now_ripple - 300, URI_HEX, 0,
                       created_meta(NID2, URI_HEX)),
        ], "marker": None})

    fc = FakeClient({"account_tx": wm_handler})
    mints, _pages, prob = C.scan_artist_mints(fc, GOOD_ADDR, stop_ledger=85)
    check("watermark reports only newer ledgers",
          prob is None and len(mints) == 2
          and all(m["ledger_index"] > 85 for m in mints))

    # pagination cap
    def endless(d):
        return FakeResp({"transactions": [], "marker": "again"})

    fc = FakeClient({"account_tx": endless})
    _m, _p, prob = C.scan_artist_mints(fc, GOOD_ADDR)
    check("pagination capped",
          prob is None and fc.calls.count("account_tx") == 5)

    # lookup failure is a soft problem
    def boom(d):
        return FakeResp({"error": "accountNotFound"}, ok=False)

    fc = FakeClient({"account_tx": boom})
    _m, _p, prob = C.scan_artist_mints(fc, GOOD_ADDR)
    check("account_tx failure is a soft per-favorite problem",
          prob is not None and _m == [])

    # --- 10. sell-price extraction ---
    def sell_xrp(d):
        return FakeResp({"offers": [
            {"Amount": "2000000", "nft_offer_index": "A" * 64},
            {"Amount": "1000000", "nft_offer_index": "B" * 64}]})

    fc = FakeClient({"nft_sell_offers": sell_xrp})
    price, perr = C.nft_sell_price(fc, NID1)
    check("cheapest XRP offer wins",
          price == "1.000000 XRP" and perr is None)

    def sell_iou(d):
        return FakeResp({"offers": [
            {"Amount": {"currency": "USD", "issuer": ISSUER,
                        "value": "42.5"}}]})

    fc = FakeClient({"nft_sell_offers": sell_iou})
    price, perr = C.nft_sell_price(fc, NID1)
    check("IOU price shown as-is",
          perr is None and price.startswith("42.5 USD."))

    fc = FakeClient({"nft_sell_offers":
                     lambda d: FakeResp({"offers": []})})
    price, perr = C.nft_sell_price(fc, NID1)
    check("no offers -> not listed", price is None and perr is None)

    def sell_boom(d):
        raise RuntimeError("node down")

    fc = FakeClient({"nft_sell_offers": sell_boom})
    price, perr = C.nft_sell_price(fc, NID1)
    check("lookup failure is soft", price is None and perr is not None)

    # --- 11. validated ledger ---
    fc = FakeClient({"ledger": lambda d: FakeResp({"ledger_index": 12345, "validated": True})})
    idx, prob = C.get_validated_ledger(fc)
    check("validated ledger index read", idx == 12345 and prob is None)
    fc = FakeClient({"ledger": lambda d: FakeResp({}, ok=False)})
    idx, prob = C.get_validated_ledger(fc)
    check("validated ledger failure is a problem",
          idx is None and prob is not None)

    # --- 12. xrp.cafe link format ---
    check("xrp.cafe link format",
          C.XRP_CAFE_NFT_URL.format(NID1)
          == f"https://xrp.cafe/nft/{NID1}")

    # --- 13. nft-new end to end (stubbed ledger) ---
    C.save_favorites({"lara": {"address": GOOD_ADDR, "added_at": 1,
                               "last_checked_ledger": None}})

    def new_handler(d):
        return FakeResp({"transactions": [
            mint_entry(999990, now_ripple - 3600, URI_HEX, 7,
                       created_meta(NID1, URI_HEX))], "marker": None})

    fc = FakeClient({
        "ledger": lambda d: FakeResp({"ledger_index": 999999, "validated": True}),
        "account_tx": new_handler,
        "nft_sell_offers": lambda d: FakeResp({"offers": [
            {"Amount": "2500000", "nft_offer_index": "C" * 64}]}),
    })
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_nft_new(A(days=None), {}, fc)
    text = out.getvalue()
    check("nft-new reports the mint",
          NID1 in text and "2.500000 XRP" in text)
    check("nft-new prints the xrp.cafe link",
          f"https://xrp.cafe/nft/{NID1}" in text)
    check("watermark advanced to validated ledger",
          C.load_favorites()["lara"]["last_checked_ledger"] == 999999)
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_nft_new(A(days=None), {}, fc)
    check("second run reports nothing new",
          "nothing new" in out.getvalue())
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_nft_new(A(days=1), {}, fc)
    check("--days re-reports the window",
          NID1 in out.getvalue())
    check("--days does not move the watermark",
          C.load_favorites()["lara"]["last_checked_ledger"] == 999999)
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_nft_new(A(days=None), {}, fc)
    check("watermark still quiet after --days",
          "nothing new" in out.getvalue())

    # --- 14. empty favorites is friendly ---
    C.save_favorites({})
    out = io.StringIO()
    with redirect_stdout(out):
        T.cmd_nft_new(A(days=None), {}, fc)
    check("nft-new with no favorites is friendly",
          "no favorites yet" in out.getvalue())
    check("--days bounds enforced",
          expect_exit(lambda: T.cmd_nft_new(A(days=0), {}, fc))
          and expect_exit(lambda: T.cmd_nft_new(A(days=91), {}, fc)))

    # --- 15. live-testnet account_tx shapes (tx_json, close_time_iso) ---
    check("meta-level nftoken_id is a fallback",
          C.extract_mint_token_ids({"nftoken_id": NID1}) == [NID1])
    check("AffectedNodes wins over meta-level nftoken_id",
          C.extract_mint_token_ids(
              {"nftoken_id": NID2, **created_meta(NID1, URI_HEX)}) == [NID1])

    iso_entry = {"ledger_index": 21030789,
                 "close_time_iso": "2026-09-25T05:16:51Z",
                 "tx_json": {"TransactionType": "NFTokenMint",
                             "Account": GOOD_ADDR, "URI": URI_HEX,
                             "NFTokenTaxon": 7},
                 "meta": {"nftoken_id": NID1, "AffectedNodes": []}}
    rd = C._entry_ripple_date(iso_entry, iso_entry["tx_json"])
    check("close_time_iso converts to ripple time",
          isinstance(rd, int) and abs(
              (rd + C.RIPPLE_EPOCH) - int(time.time())) < 86400 * 400)
    check("tx date wins over close_time_iso",
          C._entry_ripple_date(iso_entry, {"date": 12345}) == 12345)
    check("no date anywhere -> None",
          C._entry_ripple_date({}, {}) is None)

    def json_handler(d):
        return FakeResp({"transactions": [iso_entry], "marker": None})

    fc = FakeClient({"account_tx": json_handler})
    mints, _p, prob = C.scan_artist_mints(
        fc, GOOD_ADDR, cutoff_unix=int(time.time()) - 7 * 86400)
    check("scanner reads tx_json entries",
          prob is None and len(mints) == 1
          and mints[0]["token_ids"] == [NID1]
          and mints[0]["uri_hex"] == URI_HEX
          and mints[0]["taxon"] == 7)

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} favorites checks passed")
sys.exit(1 if n_fail else 0)
