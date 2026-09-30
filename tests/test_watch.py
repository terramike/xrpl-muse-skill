#!/usr/bin/env python3
"""Read-only wallet watchlist + offer-watcher tests — no network.

Run: python3 tests/test_watch.py

Covers: `watch add/list/remove` round-trips (kind='watch' in the shared
favorites store), address/seed/name validation, `favorites add --kind
watch`, watch-kind filtering, remove-kind guard, `watch check`
watermark semantics (baseline seeding, new-offer detection, API-failure
fail-open, watermark pruning), and `incoming --watch/--all-watched`
argument guards. The offers API is stubbed; nothing touches the network.
"""
import importlib.util
import io
import json
import sys
import tempfile
import types
from argparse import Namespace
from contextlib import redirect_stdout
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
T = load(BIN / "xrpl-trade", "xrpl_trade_watch")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def exits(fn):
    try:
        fn()
    except SystemExit:
        return True
    return False


def run_watch(cmd, **kw):
    args = Namespace(watch_cmd=cmd, **kw)
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_watch(args)
    return buf.getvalue()


from xrpl.wallet import Wallet  # noqa: E402

A1 = Wallet.create().classic_address
A2 = Wallet.create().classic_address
SEED = Wallet.create().seed
NFT = "0008000000000000000000000000000000000000000000000000000000000001"


def offer(idx, side="bid", amount_s="12.5 XRP"):
    return {"index": idx, "side": side, "counterparty": A2,
            "nft_id": NFT, "amount_s": amount_s, "amount_xrp": 12.5,
            "collection": None, "floor_xrp": None, "floor_diff_pct": None,
            "fraud": False, "fraud_type": None, "owner_is_scam": False,
            "time_ms": 1700000000000}


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    C.XRPL_DIR = tmp
    C.FAVORITES_PATH = tmp / "favorites.json"
    C.WATCH_SEEN_PATH = tmp / "hidden_files" / "watch-seen.json"

    # --- 1. watch add: happy path ---
    out = run_watch("add", name="studio", address=A1, note=None,
                    label="Studio Vault")
    check("watch add prints confirmation", "watched wallet" in out)
    favs = C.load_favorites()
    check("watch add stores kind=watch",
          favs.get("studio", {}).get("kind") == "watch")
    check("watch add stores address",
          favs.get("studio", {}).get("address") == A1)
    check("watch add stores label",
          favs.get("studio", {}).get("label") == "Studio Vault")

    # --- 2. watch add: refusals ---
    check("watch add refuses bad address",
          exits(lambda: run_watch("add", name="bad", address="nope",
                                  note=None, label=None)))
    check("watch add refuses seed",
          exits(lambda: run_watch("add", name="evil", address=SEED,
                                  note=None, label=None)))
    check("watch add refuses duplicate name",
          exits(lambda: run_watch("add", name="studio", address=A2,
                                  note=None, label=None)))
    check("watch add refuses bad name",
          exits(lambda: run_watch("add", name="BAD NAME", address=A2,
                                  note=None, label=None)))
    check("seed never stored",
          all("watch" not in str(v) or v.get("address") != SEED
              for v in C.load_favorites().values()))

    # --- 3. favorites add --kind watch shares the path ---
    T._add_favorite_entry("viafav", A2, "watch", None, None)
    check("favorites add --kind watch accepted",
          C.load_favorites().get("viafav", {}).get("kind") == "watch")
    check("bad kind refused",
          exits(lambda: T._add_favorite_entry("x", A2, "nonsense",
                                              None, None)))

    # --- 4. list filters to kind=watch ---
    T._add_favorite_entry("artist1", Wallet.create().classic_address,
                          "artist", None, None)
    out = run_watch("list")
    check("watch list shows watch wallets",
          "studio" in out and "viafav" in out)
    check("watch list hides artist kind", "artist1" not in out)

    # --- 5. remove guards ---
    check("watch remove unknown exits",
          exits(lambda: run_watch("remove", name="ghost")))
    check("watch remove refuses non-watch kind",
          exits(lambda: run_watch("remove", name="artist1")))
    out = run_watch("remove", name="viafav")
    check("watch remove works", "stopped watching" in out)
    check("watch remove deletes entry",
          "viafav" not in C.load_favorites())

    # --- 6. watch check: watermark semantics (stubbed API) ---
    api_data = {A1: [offer("idx-1"), offer("idx-2")]}
    api_ok = {A1: True}

    def fake_report(account, limit=50):
        if not api_ok.get(account, True):
            return None, False
        return list(api_data.get(account, [])), True

    T.xrpl_to = types.SimpleNamespace(incoming_offers_report=fake_report)

    out = run_watch("check")
    check("first check seeds baseline silently",
          "baseline set" in out and "NEW offers" not in out)
    check("watermark file written",
          C.WATCH_SEEN_PATH.exists())
    seen = json.loads(C.WATCH_SEEN_PATH.read_text())
    check("watermark holds both indices",
          set(seen.get(A1, ())) == {"idx-1", "idx-2"})
    check("watermark file is 0600",
          (C.WATCH_SEEN_PATH.stat().st_mode & 0o777) == 0o600)

    out = run_watch("check")
    check("second check with no change: no NEW",
          "NEW offers" not in out)

    api_data[A1].append(offer("idx-3", side="ask", amount_s="3 XRP"))
    out = run_watch("check")
    check("new offer detected", "NEW offers for" in out)
    check("new offer row shows side+amount",
          "ask" in out and "3 XRP" in out)
    check("points at full safety view",
          "incoming --watch studio" in out)
    seen = json.loads(C.WATCH_SEEN_PATH.read_text())
    check("watermark advances to 3",
          set(seen.get(A1, ())) == {"idx-1", "idx-2", "idx-3"})

    # flagged offer is labeled inline
    bad = offer("idx-4")
    bad["fraud"] = True
    bad["fraud_type"] = "wash"
    api_data[A1].append(bad)
    out = run_watch("check")
    check("flagged new offer labeled", "FLAGGED" in out and "wash" in out)

    # offer disappears → pruned, no phantom alert
    api_data[A1] = [o for o in api_data[A1] if o["index"] != "idx-1"]
    out = run_watch("check")
    check("removed offer pruned silently", "NEW offers" not in out)
    seen = json.loads(C.WATCH_SEEN_PATH.read_text())
    check("watermark drops gone index", "idx-1" not in seen.get(A1, ()))

    # API failure → fail-open, watermark untouched
    before = C.WATCH_SEEN_PATH.read_text()
    api_ok[A1] = False
    out = run_watch("check")
    check("API failure skips wallet", "skipped" in out)
    check("API failure leaves watermark untouched",
          C.WATCH_SEEN_PATH.read_text() == before)
    api_ok[A1] = True

    # --- 7. incoming --watch/--all-watched guards (no network) ---
    cfg, client = {}, None

    def incoming(**kw):
        base = dict(account=None, watch=None, all_watched=False,
                    limit=10, hide_flagged=True, collection=None,
                    min_xrp=None, max_xrp=None, from_addr=None,
                    no_safety=False)
        base.update(kw)
        T.cmd_incoming(Namespace(**base), cfg, client)

    check("incoming rejects --watch + --all-watched together",
          exits(lambda: incoming(watch="studio", all_watched=True)))
    check("incoming rejects unknown watch name",
          exits(lambda: incoming(watch="ghost")))

    # empty the watchlist → --all-watched must refuse, not scan
    for n in list(C.load_favorites()):
        favs = C.load_favorites()
        if favs[n].get("kind") == "watch":
            del favs[n]
            C.save_favorites(favs)
    check("incoming --all-watched with none watched exits",
          exits(lambda: incoming(all_watched=True)))
    check("watch list empty message",
          "no watched wallets" in run_watch("list"))

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
