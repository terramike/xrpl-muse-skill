#!/usr/bin/env python3
"""nft-send testnet end-to-end: A mints, A transfer-offers to B (by favorite
name), B accepts, B owns the NFT. Throwaway faucet wallets only.

Isolation: HOME points at a fresh tempfile.TemporaryDirectory(), so the
test never touches the operator's real ~/.xrpl. Seeds stay in process
memory, passed to the signer via XRPL_SEED env — never printed.
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

for _k in ("no_proxy", "NO_PROXY"):
    _v = os.environ.get(_k)
    if _v:
        os.environ[_k] = ",".join(p for p in _v.split(",") if "[" not in p)

SKILL_BIN = Path(__file__).resolve().parent.parent / "bin"
PYP = str(SKILL_BIN)
TESTNET_RPC = "https://s.altnet.rippletest.net:51234"

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def run(cmd, home, **kw):
    env = dict(os.environ)
    env["HOME"] = str(home)
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


def rpc(method, params):
    return httpx.post(TESTNET_RPC,
                      json={"method": method, "params": [params]},
                      timeout=30.0).json()


def main():
    with tempfile.TemporaryDirectory(prefix="xrpl-nftsend-e2e-") as td:
        home = Path(td)
        xrpl = home / ".xrpl"
        xrpl.mkdir(parents=True)

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
            "destination_allowlist": [],
            "max_deviation_bps": 1000,
            "max_spread_bps": 1000,
            "min_book_depth": "5",
            "max_offer_lifetime_seconds": 86400,
            "proposal_ttl_seconds": 86400,
            "allowed_tx_types": ["OfferCreate", "OfferCancel",
                                 "TrustSet", "Payment",
                                 "NFTokenMint", "NFTokenCreateOffer",
                                 "NFTokenAcceptOffer"],
            # allow_buy_offers must be true for B's NFTokenAcceptOffer —
            # the signer gates all NFT accepts behind this toggle.
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

        print("== A mints an NFT (placeholder ipfs URI) ==")
        sys.path.insert(0, str(SKILL_BIN))
        import xrpl_common as C
        C.XRPL_DIR = xrpl
        # Paths are resolved at module import; bind every file path used by
        # proposal creation to this suite's isolated home as well.
        C.POLICY_PATH = xrpl / "policy.json"
        C.PROPOSALS_DIR = xrpl / "proposals"
        C.FAVORITES_PATH = xrpl / "favorites.json"
        import asyncio
        from xrpl.clients import JsonRpcClient
        from xrpl.models.transactions import (
            NFTokenMint, NFTokenMintFlag)
        from xrpl.transaction import autofill as xrpl_autofill

        nclient = JsonRpcClient(TESTNET_RPC)

        def _req(self, request):
            return asyncio.run(self._request_impl(request, timeout=30.0))

        nclient.request = _req.__get__(nclient, JsonRpcClient)

        uri_hex = ("ipfs://bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuz"
                   "jevtenxqsend1").encode().hex().upper()
        mint = NFTokenMint(
            account=addr_a, nftoken_taxon=0, uri=uri_hex, transfer_fee=1000,
            flags=int(NFTokenMintFlag.TF_TRANSFERABLE)
            | int(NFTokenMintFlag.TF_BURNABLE))
        mtxd = xrpl_autofill(mint, nclient).to_xrpl()
        mtxd.pop("SigningPubKey", None)
        mtxd.pop("TxnSignature", None)
        mh, mpath = C.save_proposal(mtxd, "testnet", addr_a, "nft-mint")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", mh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        mm = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("mint validated tesSUCCESS",
              p.returncode == 0 and bool(mm)
              and "tesSUCCESS" in p.stdout)
        if not mm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1

        token_id = None
        for _ in range(12):
            time.sleep(5)
            try:
                r = rpc("account_nfts", {"account": addr_a, "limit": 400})
            except Exception:  # noqa: BLE001
                continue
            for n in r["result"].get("account_nfts", []):
                if n.get("URI", "").upper() == uri_hex:
                    token_id = n["NFTokenID"]
                    break
            if token_id:
                break
        check("minted NFT visible on ledger", bool(token_id))
        if not token_id:
            return 1

        print("== A adds B as a favorite, then nft-sends by name ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "favorites", "add", "runnerup", addr_b], home)
        check("favorite added", p.returncode == 0
              and "runnerup" in p.stdout)

        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-send", "--token-id", token_id, "--to", "runnerup",
                 "--expires-in", "3600"], home)
        sm = re.search(r"proposal hash: ([0-9a-f]{64})", p.stdout)
        check("nft-send proposes through the CLI",
              p.returncode == 0 and bool(sm))
        check("proposal summary says TRANSFER gift",
              "TRANSFER (gift" in p.stdout)
        check("proposal summary shows the favorite name",
              "favorite: runnerup" in p.stdout)
        check("proposal summary shows the resolved address",
              addr_b in p.stdout)
        check("proposal summary never calls it a sale",
              "sale" not in p.stdout.lower().replace("not a sale", ""))
        if not sm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        sh = sm.group(1)

        print("== policy check (no approval): ceremony from the tx ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", sh[:16]], home)
        check("policy PASS", p.returncode == 0 and "policy: PASS" in p.stdout)
        check("signer ceremony says TRANSFER",
              "TRANSFER (gift" in p.stdout)
        check("nothing signed without approval",
              "Signed" not in p.stdout and "submitting" not in p.stdout)

        print("== approve: transfer offer lands on ledger ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", sh, "--approve"],
                home, extra_env={"XRPL_SEED": seed_a}, timeout=180)
        tm = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("nft-send validated tesSUCCESS",
              p.returncode == 0 and bool(tm)
              and "tesSUCCESS" in p.stdout)
        if not tm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1

        offer_idx = None
        for _ in range(12):
            time.sleep(5)
            try:
                r = rpc("nft_sell_offers", {"nft_id": token_id})
            except Exception:  # noqa: BLE001
                continue
            for o in r["result"].get("offers", []):
                if (o.get("amount") == "0" and o.get("flags") == 1
                        and o.get("destination") == addr_b):
                    offer_idx = o.get("nft_offer_index")
            if offer_idx:
                break
        check("0-XRP transfer offer live for B", bool(offer_idx))
        if not offer_idx:
            return 1

        print("== B accepts the gift via nft-buy ==")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-trade"),
                 "nft-buy", "--offer-index", offer_idx], home,
                extra_env={"XRPL_ADDRESS": addr_b})
        bm = re.search(r"proposal hash: ([0-9a-f]{64})", p.stdout)
        check("nft-buy proposes the accept",
              p.returncode == 0 and bool(bm))
        check("accept verification shows 0 XRP price",
              "0 XRP" in p.stdout)
        if not bm:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", bm.group(1), "--approve"],
                home, extra_env={"XRPL_SEED": seed_b}, timeout=180)
        buy_m = re.search(r"transactions/([0-9A-F]{64})", p.stdout)
        check("accept validated tesSUCCESS",
              p.returncode == 0 and bool(buy_m)
              and "tesSUCCESS" in p.stdout)
        if not buy_m:
            print(p.stdout[-2000:]); print(p.stderr[-2000:])
            return 1

        b_owns = False
        for _ in range(12):
            time.sleep(5)
            try:
                r = rpc("account_nfts", {"account": addr_b, "limit": 400})
            except Exception:  # noqa: BLE001
                continue
            if any(n.get("NFTokenID") == token_id
                   for n in r["result"].get("account_nfts", [])):
                b_owns = True
                break
        check("B owns the NFT on ledger", b_owns)
        check("A no longer owns it",
              not any(n.get("NFTokenID") == token_id
                      for n in rpc("account_nfts",
                                   {"account": addr_a,
                                    "limit": 400})["result"]
                      .get("account_nfts", [])))

    n_fail = sum(1 for _, ok in CHECKS if not ok)
    print(f"\n{len(CHECKS) - n_fail}/{len(CHECKS)} e2e checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
