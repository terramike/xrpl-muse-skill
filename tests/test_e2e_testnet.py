#!/usr/bin/env python3
"""v0.4 testnet end-to-end: propose -> policy-check -> approve -> sign ->
persist -> submit -> validated. Uses throwaway faucet wallets only.

Isolation (v0.4): the test runs with HOME pointed at a fresh
tempfile.TemporaryDirectory(), so it never touches the operator's real
~/.xrpl — no file swapping, no fixed /tmp backup dir. It tests the
repository checkout it lives in (BIN resolved from __file__), not whatever
happens to be installed. Seeds stay in process memory and are passed to
the signer via XRPL_SEED env — never printed or logged.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

# The vendored httpx cannot parse bracketed IPv6 entries in no_proxy
# (e.g. "[::1]") — drop them. The egress proxy itself stays, since
# direct connections are not available from this sandbox.
for _k in ("no_proxy", "NO_PROXY"):
    _v = os.environ.get(_k)
    if _v:
        os.environ[_k] = ",".join(p for p in _v.split(",") if "[" not in p)

# The checkout under test — not an installed copy.
SKILL_BIN = Path(__file__).resolve().parent.parent / "bin"
PYP = str(Path.home() / "workspace" / "tools" / "xrpl-pkgs")

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def run(cmd, home, **kw):
    env = dict(os.environ)
    env["HOME"] = str(home)  # isolate: signer sees an empty ~/.xrpl
    env["PYTHONPATH"] = PYP + os.pathsep + env.get("PYTHONPATH", "")
    env.update(kw.pop("extra_env", {}))
    p = subprocess.run(cmd, capture_output=True, text=True, env=env,
                       timeout=kw.pop("timeout", 120))
    return p


def faucet():
    for attempt in range(6):
        r = httpx.post("https://faucet.altnet.rippletest.net/accounts",
                       json={}, timeout=30.0)
        if r.status_code == 429:
            time.sleep(15 * (attempt + 1))
            continue
        r.raise_for_status()
        d = r.json()
        acct = d["account"]
        return (acct.get("classicAddress") or acct["address"]), d["seed"]
    r.raise_for_status()


TESTNET_RPC = "https://s.altnet.rippletest.net:51234"


def balance_xrp(addr):
    r = httpx.post(TESTNET_RPC,
                   json={"method": "account_info",
                         "params": [{"account": addr,
                                     "ledger_index": "validated"}]},
                   timeout=30.0).json()
    return int(r["result"]["account_data"]["Balance"]) / 1_000_000


def main():
    with tempfile.TemporaryDirectory(prefix="xrpl-e2e-") as td:
        home = Path(td)
        xrpl = home / ".xrpl"
        xrpl.mkdir(parents=True)
        check("isolated HOME has no pre-existing state",
              not (xrpl / "policy.json").exists())

        print("== faucet wallets ==")
        addr_a, seed_a = faucet()
        addr_b, seed_b = faucet()
        check("two faucet wallets created",
              addr_a.startswith("r") and addr_b.startswith("r")
              and addr_a != addr_b)

        (xrpl / "config.json").write_text(json.dumps(
            {"network": "testnet", "address": addr_a}))
        (xrpl / "config.json").chmod(0o600)
        policy = {
            "policy_version": 4,
            "network_lock": "testnet",
            "max_fee_drops": 1000,
            "spend_limits": {"XRP": {"per_tx": "25", "per_day": "100"}},
            "destination_allowlist": [
                {"address": addr_b, "destination_tag": None}],
            "max_deviation_bps": 1000,
            "max_spread_bps": 1000,
            "min_book_depth": "5",
            "max_offer_lifetime_seconds": 86400,
            "proposal_ttl_seconds": 86400,
            "allowed_tx_types": ["OfferCreate", "OfferCancel",
                                 "TrustSet", "Payment",
                                 "NFTokenMint", "NFTokenCreateOffer",
                                 "NFTokenAcceptOffer"],
            "nft": {"max_transfer_fee": 10000,
                    "max_mints_per_day": 10,
                    "allowed_mint_flags": [1, 8],
                    "max_uri_bytes": 256,
                    "allow_buy_offers": True,
                    "max_bid_xrp": "10"},
        }
        (xrpl / "policy.json").write_text(json.dumps(policy))
        (xrpl / "policy.json").chmod(0o600)
        (xrpl / "approved.json").write_text(json.dumps({"pairs": {}}))
        (xrpl / "approved.json").chmod(0o600)

        print("== propose ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "send", "--to", addr_b, "--amount", "1", "--ccy", "XRP"],
                home)
        m = re.search(r"proposal hash: ([0-9a-f]{64})", p.stdout)
        check("propose exits 0", p.returncode == 0)
        check("proposal hash emitted", bool(m))
        if not m:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        h = m.group(1)
        prop_path = xrpl / "proposals" / (h + ".json")
        check("proposal file saved", prop_path.exists())

        print("== policy check, no approval ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", h[:16]], home)
        check("no-approve run exits 0", p.returncode == 0)
        check("policy PASS shown", "policy: PASS" in p.stdout)
        check("full signing account displayed",
              addr_a in p.stdout)
        check("nothing signed without approval",
              "Signed" not in p.stdout and "submitting" not in p.stdout)

        print("== approve + sign + submit ==")
        bal_before = balance_xrp(addr_b)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", h, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        tm = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("approve run exits 0", p.returncode == 0)
        check("signed hash reported", bool(tm))
        check("validated tesSUCCESS",
              "validated: True" in p.stdout and "tesSUCCESS" in p.stdout)
        if not tm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        thash = tm.group(1)

        print("== reconcile ==")
        check("proposal consumed", not prop_path.exists())
        audit = (xrpl / "audit.log").read_text()
        check("audit has signed entry",
              f'"result": "signed"' in audit and thash in audit)
        check("audit has applied entry",
              f'"result": "applied"' in audit and thash in audit)
        check("audit records last_ledger bound",
              "last_ledger=" in audit)
        for _ in range(12):
            time.sleep(5)
            try:
                if balance_xrp(addr_b) >= bal_before + 1 - 1e-9:
                    break
            except Exception:  # noqa: BLE001
                pass
        check("recipient balance increased by 1 XRP",
              balance_xrp(addr_b) >= bal_before + 1 - 1e-9)
        state = json.loads((xrpl / "state.json").read_text())
        spent = sum(float(e["amount"]) for e in state["entries"]
                    if e["asset"] == "XRP")
        check("daily spend tracked (rolling entries)",
              spent >= 1.0)
        check("confirmed entry references the tx hash",
              any(e.get("tx_hash") == thash and e["status"] == "confirmed"
                  for e in state["entries"]))
        st_mode = (xrpl / "state.json").stat().st_mode & 0o777
        check("state file is owner-only", st_mode == 0o600)

        print("== NFT: mint + list ==")
        sys.path.insert(0, str(SKILL_BIN))
        import xrpl_common as C
        # point the module at the isolated dir (it read HOME at import)
        C.XRPL_DIR = xrpl
        C.PROPOSALS_DIR = xrpl / "proposals"
        C.FAVORITES_PATH = xrpl / "favorites.json"
        import asyncio
        from xrpl.clients import JsonRpcClient
        from xrpl.models.transactions import (
            NFTokenCreateOffer, NFTokenCreateOfferFlag,
            NFTokenMint, NFTokenMintFlag)
        from xrpl.transaction import autofill as xrpl_autofill

        nclient = JsonRpcClient(TESTNET_RPC)

        def _req(self, request):
            return asyncio.run(self._request_impl(request, timeout=30.0))

        nclient.request = _req.__get__(nclient, JsonRpcClient)

        # placeholder ipfs:// URI — the ledger never resolves it, so no
        # real Pinata key is needed for ledger tests
        uri_hex = ("ipfs://bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuz"
                   "jevtenxquvyku").encode().hex().upper()
        mint = NFTokenMint(
            account=addr_a, nftoken_taxon=0, uri=uri_hex, transfer_fee=1000,
            flags=int(NFTokenMintFlag.TF_TRANSFERABLE)
            | int(NFTokenMintFlag.TF_BURNABLE))
        mtxd = xrpl_autofill(mint, nclient).to_xrpl()
        mtxd.pop("SigningPubKey", None)
        mtxd.pop("TxnSignature", None)
        mh, mpath = C.save_proposal(mtxd, "testnet", addr_a, "nft-mint")
        check("nft-mint proposal saved", mpath.exists())

        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", mh[:16]], home)
        check("nft-mint policy PASS (no approval)",
              p.returncode == 0 and "policy: PASS" in p.stdout)
        check("mint ceremony shows royalty",
              "royalty" in p.stdout and "1.000%" in p.stdout)

        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", mh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        mm = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("nft-mint approve run exits 0",
              p.returncode == 0 and bool(mm))
        check("nft-mint validated tesSUCCESS",
              "validated: True" in p.stdout and "tesSUCCESS" in p.stdout)
        if not mm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        check("nft-mint proposal consumed", not mpath.exists())

        token_id = None
        for _ in range(12):
            time.sleep(5)
            try:
                r = httpx.post(
                    TESTNET_RPC,
                    json={"method": "account_nfts",
                          "params": [{"account": addr_a, "limit": 400}]},
                    timeout=30.0).json()
            except Exception:  # noqa: BLE001
                continue
            for n in r["result"].get("account_nfts", []):
                if n.get("URI", "").upper() == uri_hex:
                    token_id = n["NFTokenID"]
                    break
            if token_id:
                break
        check("minted NFT visible on ledger with our URI", bool(token_id))
        if not token_id:
            return 1

        offer = NFTokenCreateOffer(
            account=addr_a, nftoken_id=token_id, amount="2000000",
            expiration=C.ripple_time_from_now(3600),
            flags=int(NFTokenCreateOfferFlag.TF_SELL_NFTOKEN))
        otxd = xrpl_autofill(offer, nclient).to_xrpl()
        otxd.pop("SigningPubKey", None)
        otxd.pop("TxnSignature", None)
        oh, opath = C.save_proposal(otxd, "testnet", addr_a, "nft-list")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", oh[:16]], home)
        check("nft-list policy PASS (no approval)",
              p.returncode == 0 and "policy: PASS" in p.stdout)
        check("listing ceremony marks it a SELL",
              "SELL offer" in p.stdout)

        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", oh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        om = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("nft-list approve run exits 0",
              p.returncode == 0 and bool(om))
        check("nft-list validated tesSUCCESS",
              "validated: True" in p.stdout and "tesSUCCESS" in p.stdout)

        listed = False
        offer_idx = None
        for _ in range(12):
            time.sleep(5)
            try:
                r = httpx.post(
                    TESTNET_RPC,
                    json={"method": "nft_sell_offers",
                          "params": [{"nft_id": token_id}]},
                    timeout=30.0).json()
            except Exception:  # noqa: BLE001
                continue
            for o in r["result"].get("offers", []):
                if o.get("amount") == "2000000" and o.get("flags") == 1:
                    listed = True
                    offer_idx = o.get("nft_offer_index")
            if listed:
                break
        check("sell offer live at 2 XRP", listed)
        check("sell offer index captured", bool(offer_idx))
        if not offer_idx:
            return 1

        print("== NFT buy side: inventory + buy + bid ==")
        # B's inventory starts empty
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-inventory", addr_b], home)
        check("B's nft-inventory starts empty",
              p.returncode == 0 and "No NFTs owned" in p.stdout)

        # B buys A's listing through the real CLI path
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-buy", "--offer-index", offer_idx], home,
                extra_env={"XRPL_ADDRESS": addr_b})
        bm = re.search(r"proposal hash: ([0-9a-f]{64})", p.stdout)
        check("nft-buy proposes through the CLI",
              p.returncode == 0 and bool(bm))
        check("nft-buy prints the sell-offer verification",
              "SELL-OFFER VERIFICATION" in p.stdout
              and addr_a in p.stdout and "2.000000 XRP" in p.stdout)
        if not bm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        bh = bm.group(1)
        bal_b = balance_xrp(addr_b)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", bh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_b}, timeout=180)
        buy_m = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("nft-buy approve run exits 0",
              p.returncode == 0 and bool(buy_m))
        check("nft-buy validated tesSUCCESS",
              "validated: True" in p.stdout and "tesSUCCESS" in p.stdout)
        check("signing ceremony re-verified the offer",
              "re-verified from the ledger at signing" in p.stdout)

        b_owns = False
        for _ in range(12):
            time.sleep(5)
            try:
                r = httpx.post(
                    TESTNET_RPC,
                    json={"method": "account_nfts",
                          "params": [{"account": addr_b, "limit": 400}]},
                    timeout=30.0).json()
            except Exception:  # noqa: BLE001
                continue
            if any(n.get("NFTokenID") == token_id
                   for n in r["result"].get("account_nfts", [])):
                b_owns = True
                break
        check("B now owns the NFT on ledger", b_owns)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-inventory", addr_b], home)
        check("B's nft-inventory shows the token",
              p.returncode == 0 and token_id in p.stdout)
        check("B paid 2 XRP (+ fee)",
              balance_xrp(addr_b) <= bal_b - 2)
        state = json.loads((xrpl / "state.json").read_text())
        check("buy price reserved as confirmed spend",
              any(e.get("tx_hash") == buy_m.group(1)
                  and e["status"] == "confirmed"
                  and e["asset"] == "XRP" and float(e["amount"]) >= 2.0
                  for e in state["entries"]))

        # A mints a second NFT; B bids on it
        uri2_hex = ("ipfs://bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuz"
                    "jevtenxquv222").encode().hex().upper()
        mint2 = NFTokenMint(
            account=addr_a, nftoken_taxon=1, uri=uri2_hex, transfer_fee=1000,
            flags=int(NFTokenMintFlag.TF_TRANSFERABLE)
            | int(NFTokenMintFlag.TF_BURNABLE))
        m2txd = xrpl_autofill(mint2, nclient).to_xrpl()
        m2txd.pop("SigningPubKey", None)
        m2txd.pop("TxnSignature", None)
        mh2, mpath2 = C.save_proposal(m2txd, "testnet", addr_a, "nft-mint")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", mh2, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        mm2 = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("second nft-mint validated",
              bool(mm2) and "tesSUCCESS" in p.stdout)
        if not mm2:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1

        token2 = None
        for _ in range(12):
            time.sleep(5)
            try:
                r = httpx.post(
                    TESTNET_RPC,
                    json={"method": "account_nfts",
                          "params": [{"account": addr_a, "limit": 400}]},
                    timeout=30.0).json()
            except Exception:  # noqa: BLE001
                continue
            for n in r["result"].get("account_nfts", []):
                if n.get("URI", "").upper() == uri2_hex:
                    token2 = n["NFTokenID"]
                    break
            if token2:
                break
        check("second NFT visible with its URI", bool(token2))
        if not token2:
            return 1

        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-bid", "--token-id", token2, "--seller", addr_a,
                 "--price-xrp", "1"], home,
                extra_env={"XRPL_ADDRESS": addr_b})
        dm = re.search(r"proposal hash: ([0-9a-f]{64})", p.stdout)
        check("nft-bid proposes through the CLI",
              p.returncode == 0 and bool(dm))
        check("nft-bid ceremony marks it a BUY offer",
              "BUY offer" in p.stdout)
        if not dm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", dm.group(1), "--approve"],
                home, extra_env={"XRPL_SEED": seed_b}, timeout=180)
        check("nft-bid validated tesSUCCESS",
              p.returncode == 0 and "validated: True" in p.stdout
              and "tesSUCCESS" in p.stdout)

        bid_live = False
        for _ in range(12):
            time.sleep(5)
            try:
                r = httpx.post(
                    TESTNET_RPC,
                    json={"method": "nft_buy_offers",
                          "params": [{"nft_id": token2}]},
                    timeout=30.0).json()
            except Exception:  # noqa: BLE001
                continue
            for o in r["result"].get("offers", []):
                if o.get("amount") == "1000000" and o.get("flags") == 0:
                    bid_live = True
            if bid_live:
                break
        check("buy offer live at 1 XRP", bid_live)

        print("== hostile NFT proposals denied ==")
        evil_mint = dict(mtxd)
        evil_mint["TransferFee"] = 50000  # over the 10% policy cap
        eh, epath = C.save_proposal(evil_mint, "testnet", addr_a, "nft-mint")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", eh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a})
        check("over-cap royalty denied even with --approve",
              p.returncode != 0 and ("DENIED" in p.stdout
                                     or "TransferFee" in p.stdout))
        epath.unlink(missing_ok=True)

        evil_list = dict(otxd)
        evil_list["Amount"] = {"currency": "USD", "issuer": addr_b,
                               "value": "5"}
        eh2, epath2 = C.save_proposal(evil_list, "testnet", addr_a,
                                      "nft-list")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", eh2, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a})
        check("IOU-denominated listing denied even with --approve",
              p.returncode != 0 and ("DENIED" in p.stdout
                                     or "XRP-only" in p.stdout))
        epath2.unlink(missing_ok=True)

        print("== artist favorites + nft-new ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "add", "marta", addr_a,
                 "--note", "test artist"], home)
        check("favorites add works",
              p.returncode == 0 and "marta" in p.stdout)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "add", "marta", addr_a], home)
        check("duplicate favorite refused", p.returncode != 0)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "list"], home)
        check("favorites list shows marta",
              p.returncode == 0 and "marta" in p.stdout
              and addr_a in p.stdout)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "rename", "marta", "marta2"], home)
        check("favorites rename works", p.returncode == 0)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "remove", "marta2"], home)
        check("favorites remove works", p.returncode == 0)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "add", "marta", addr_a], home)
        check("favorites re-add works", p.returncode == 0)

        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-inventory", "marta"], home)
        check("nft-inventory resolves a favorite name",
              p.returncode == 0 and token2 in p.stdout)

        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-new"], home, timeout=180)
        check("nft-new reports A's mints",
              p.returncode == 0 and token_id in p.stdout
              and token2 in p.stdout)
        check("nft-new prints xrp.cafe links",
              f"https://xrp.cafe/nft/{token_id}" in p.stdout
              and f"https://xrp.cafe/nft/{token2}" in p.stdout)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-new"], home, timeout=180)
        check("nft-new second run is quiet (watermark advanced)",
              p.returncode == 0 and "nothing new" in p.stdout)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-new", "--days", "1"], home, timeout=180)
        check("nft-new --days re-reports the window",
              p.returncode == 0 and token_id in p.stdout)
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-new"], home, timeout=180)
        check("watermark untouched by --days",
              p.returncode == 0 and "nothing new" in p.stdout)

        print("== hostile proposal still denied ==")
        evil = {"TransactionType": "AccountSet", "Account": addr_a,
                "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
        # C is already imported and pointed at the isolated dir above
        eh, epath = C.save_proposal(evil, "testnet", addr_a, "evil")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", eh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a})
        check("AccountSet denied even with --approve",
              p.returncode != 0 and ("DENIED" in p.stdout
                                     or "rejected" in p.stderr))
        epath.unlink(missing_ok=True)

    n_fail = sum(1 for _, ok in CHECKS if not ok)
    print(f"\n{len(CHECKS) - n_fail}/{len(CHECKS)} e2e checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
