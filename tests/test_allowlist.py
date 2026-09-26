#!/usr/bin/env python3
"""Destination-allowlist audit logging + new-destination recency flag.

- Every allowlist add/remove is written to the audit log (security-relevant
  edits must leave a trail).
- New entries carry added_at; describe_tx() flags Payments to destinations
  added within 24h LOUDLY in the signing ceremony.
- No network. Run: python3 tests/test_allowlist.py
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
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


C = load(BIN / "xrpl_common.py", "xrpl_common_allowlist")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


tmp = Path(tempfile.mkdtemp(prefix="allowlist-"))
C.XRPL_DIR = tmp
C.POLICY_PATH = tmp / "policy.json"
C.AUDIT_PATH = tmp / "audit.log"


def write_policy(entries):
    pol = {"policy_version": C.POLICY_VERSION,
           "destination_allowlist": entries}
    C.POLICY_PATH.write_text(json.dumps(pol))
    os.chmod(C.POLICY_PATH, 0o600)


def read_policy():
    return json.loads(C.POLICY_PATH.read_text())


def audit_entries():
    if not C.AUDIT_PATH.exists():
        return []
    return [json.loads(l) for l in C.AUDIT_PATH.read_text().splitlines()
            if l.strip()]


ADDR_NEW = "rNewDestination11111111111111111111"
ADDR_OLD = "rOldDestination22222222222222222222"
ADDR_GRANDFATHERED = "rGrandfathered3333333333333333333"
ADDR_ABSENT = "rAbsent44444444444444444444444444"

# ---------- add: timestamp + audit ----------

write_policy([])
t0 = int(time.time())
problem = C.add_destination_allowlist_entry(ADDR_NEW, None)
check("add returns None on success", problem is None)
entries = read_policy()["destination_allowlist"]
check("add stores the entry",
      any(e.get("address") == ADDR_NEW and e.get("destination_tag") is None
          for e in entries))
added_at = next(e["added_at"] for e in entries if e["address"] == ADDR_NEW)
check("add records added_at as a recent int timestamp",
      isinstance(added_at, int) and t0 - 5 <= added_at <= int(time.time()) + 5)

aud = audit_entries()
check("add writes one audit entry",
      sum(1 for a in aud if a["action"] == "allowlist_add") == 1)
add_audit = next(a for a in aud if a["action"] == "allowlist_add")
check("audit entry names the address and tag",
      ADDR_NEW in add_audit["note"] and "destination_tag=None" in add_audit["note"])
check("audit entry result is 'added'", add_audit["result"] == "added")
check("audit log is owner-only 0600",
      stat.S_IMODE(os.stat(C.AUDIT_PATH).st_mode) == 0o600)
check("policy stays owner-only 0600 after add",
      stat.S_IMODE(os.stat(C.POLICY_PATH).st_mode) == 0o600)

# ---------- add: idempotent, no duplicate audit ----------

problem = C.add_destination_allowlist_entry(ADDR_NEW, None)
check("duplicate add returns None", problem is None)
entries = read_policy()["destination_allowlist"]
check("duplicate add does not duplicate the entry",
      sum(1 for e in entries if e["address"] == ADDR_NEW) == 1)
check("duplicate add does not write a second audit entry",
      sum(1 for a in audit_entries()
          if a["action"] == "allowlist_add") == 1)

# ---------- remove: audit-logged ----------

problem = C.remove_destination_allowlist_entry(ADDR_NEW, None)
check("remove returns None on success", problem is None)
check("remove drops the entry",
      all(e.get("address") != ADDR_NEW
          for e in read_policy()["destination_allowlist"]))
check("remove writes an allowlist_remove audit entry",
      sum(1 for a in audit_entries()
          if a["action"] == "allowlist_remove"
          and ADDR_NEW in a["note"]) == 1)

problem = C.remove_destination_allowlist_entry(ADDR_ABSENT, None)
check("remove of absent entry is idempotent (None)", problem is None)
check("remove of absent entry writes no audit entry",
      sum(1 for a in audit_entries()
          if a["action"] == "allowlist_remove") == 1)

# ---------- age helper ----------

now = int(time.time())
write_policy([
    {"address": ADDR_NEW, "destination_tag": None, "added_at": now - 30},
    {"address": ADDR_OLD, "destination_tag": 7, "added_at": now - 90000},
    {"address": ADDR_GRANDFATHERED, "destination_tag": None},  # no added_at
])
age_new = C.destination_allowlist_age(ADDR_NEW, None)
check("age of a 30s-old entry is small and non-negative",
      age_new is not None and 0 <= age_new < 120)
age_old = C.destination_allowlist_age(ADDR_OLD, 7)
check("age of a 25h-old entry exceeds the 24h window",
      age_old is not None and age_old > C.ALLOWLIST_NEW_DESTINATION_SECONDS)
check("tag mismatch does not match the entry",
      C.destination_allowlist_age(ADDR_OLD, None) is None)
check("grandfathered entry (no added_at) returns None",
      C.destination_allowlist_age(ADDR_GRANDFATHERED, None) is None)
check("absent destination returns None",
      C.destination_allowlist_age(ADDR_ABSENT, None) is None)

# ---------- describe_tx recency flag ----------

def payment_tx(dest, tag):
    return {"TransactionType": "Payment", "Account": "rSrc",
            "Destination": dest, "DestinationTag": tag,
            "Amount": "1000000"}


new_lines = "\n".join(C.describe_tx(payment_tx(ADDR_NEW, None), "pay"))
check("Payment to a new destination shows the NEW DESTINATION warning",
      "⚠️  NEW DESTINATION" in new_lines)
check("warning tells the human not to approve blindly",
      "DO NOT APPROVE" in new_lines)
check("warning shows the destination (short_addr convention)",
      ADDR_NEW[:8] in new_lines)

old_lines = "\n".join(C.describe_tx(payment_tx(ADDR_OLD, 7), "pay"))
check("Payment to an old destination shows no warning",
      "NEW DESTINATION" not in old_lines)

gf_lines = "\n".join(C.describe_tx(payment_tx(ADDR_GRANDFATHERED, None), "pay"))
check("Payment to a grandfathered destination shows no warning",
      "NEW DESTINATION" not in gf_lines)

absent_lines = "\n".join(C.describe_tx(payment_tx(ADDR_ABSENT, None), "pay"))
check("Payment to a non-allowlisted destination shows no warning "
      "(signer denies it separately via check_payment_destination)",
      "NEW DESTINATION" not in absent_lines)

offer_lines = "\n".join(C.describe_tx(
    {"TransactionType": "OfferCreate", "TakerPays": "1000000",
     "TakerGets": {"currency": "USD", "issuer": ADDR_NEW, "value": "1"}},
    "buy"))
check("OfferCreate shows no destination warning", "NEW DESTINATION" not in offer_lines)

# ---------- describe_tx never crashes without a policy file ----------

C.POLICY_PATH.unlink()
try:
    no_pol_lines = C.describe_tx(payment_tx(ADDR_NEW, None), "pay")
    check("describe_tx survives a missing policy file (no crash)",
          isinstance(no_pol_lines, list))
    check("no warning without a readable policy",
          "NEW DESTINATION" not in "\n".join(no_pol_lines))
except SystemExit:
    check("describe_tx survives a missing policy file (no crash)", False)

# ---------- age formatting ----------

check("format just-now", C.format_allowlist_age(30) == "just now")
check("format minutes", C.format_allowlist_age(300) == "5m ago")
check("format hours", C.format_allowlist_age(7200) == "2h ago")

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
