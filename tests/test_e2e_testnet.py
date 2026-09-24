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
        addr_b, _seed_b = faucet()
        check("two faucet wallets created",
              addr_a.startswith("r") and addr_b.startswith("r")
              and addr_a != addr_b)

        (xrpl / "config.json").write_text(json.dumps(
            {"network": "testnet", "address": addr_a}))
        (xrpl / "config.json").chmod(0o600)
        policy = {
            "policy_version": 3,
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
                                 "TrustSet", "Payment"],
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
                 "--hash", h[:16], "--approve"],
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

        print("== hostile proposal still denied ==")
        evil = {"TransactionType": "AccountSet", "Account": addr_a,
                "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}
        sys.path.insert(0, str(SKILL_BIN))
        import xrpl_common as C
        # point the module at the isolated dir (it read HOME at import)
        C.XRPL_DIR = xrpl
        C.PROPOSALS_DIR = xrpl / "proposals"
        eh, epath = C.save_proposal(evil, "testnet", addr_a, "evil")
        p = run([sys.executable, str(SKILL_BIN / "xrpl-sign"),
                 "--hash", eh[:16], "--approve"],
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
