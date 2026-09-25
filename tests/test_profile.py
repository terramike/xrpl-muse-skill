#!/usr/bin/env python3
"""Assistant profile (onboarding) tests — no network.

Run: python3 tests/test_profile.py

Covers: seed/secret refusal (the loud warning, never stored), classic
address checksum validation, scalar field validation (display_name,
alerts.price_moves, alerts.threshold_pct), membership/interest tag
normalization + dedupe, 0600 file creation, corrupt-file and
future-schema failure, init questionnaire flow (scripted input,
seed re-prompt), init-when-exists, and clear.
"""
import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
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
T = load(BIN / "xrpl-trade", "xrpl_trade_prof")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="xrpl_prof_test_"))
C.PROFILE_PATH = TMP / "profile.json"

W1 = Wallet.create()
W2 = Wallet.create()
GOOD_ADDR = W1.classic_address
GOOD_ADDR2 = W2.classic_address
SEED = W1.seed  # family seed, starts with 's'
# Synthetic ed25519-style seed (sEd + base58) — exercises the heuristic.
ED_SEED = "sEdV19K6j7m8N9pQ2rS3tU4vW5wX6yZ8aB"
BAD_ADDR = GOOD_ADDR[:-1] + ("1" if GOOD_ADDR[-1] != "1" else "2")


def ns(**kw):
    return argparse.Namespace(**kw)


def run(cmd, expect_exit=False, **kw):
    """Run cmd_profile; returns (stdout, exit_message_or_None)."""
    kw["prof_cmd"] = cmd
    buf = io.StringIO()
    msg = None
    with redirect_stdout(buf):
        try:
            T.cmd_profile(ns(**kw))
        except SystemExit as e:
            msg = str(e)
            if not expect_exit:
                raise AssertionError(
                    f"unexpected SystemExit({msg!r}) for {cmd} {kw}")
        else:
            if expect_exit:
                raise AssertionError(
                    f"expected SystemExit for {cmd} {kw}, got none")
    return buf.getvalue(), msg


def fresh():
    if C.PROFILE_PATH.exists():
        C.PROFILE_PATH.unlink()
    return C.default_profile()


# ---------- seed / secret refusal ----------

check("looks_like_secret: family seed", C.looks_like_secret(SEED))
check("looks_like_secret: ed25519 seed", C.looks_like_secret(ED_SEED))
check("looks_like_secret: classic address is not secret",
      not C.looks_like_secret(GOOD_ADDR))
check("looks_like_secret: 'my secret words'",
      C.looks_like_secret("my secret words"))
check("looks_like_secret: plain name", not C.looks_like_secret("Mike"))

fresh()
out, msg = run("add-address", expect_exit=True, address=SEED)
check("add-address refuses seed with loud warning",
      msg is not None and "SEED" in msg and "Nothing was saved" in msg)
check("seed was not persisted", not C.PROFILE_PATH.exists())

out, msg = run("add-address", expect_exit=True, address=ED_SEED)
check("add-address refuses ed25519 seed",
      msg is not None and "SEED" in msg)

out, msg = run("add-address", expect_exit=True, address="my secret phrase")
check("add-address refuses 'secret' phrase",
      msg is not None and "SEED" in msg)

out, msg = run("add-address", expect_exit=True, address=BAD_ADDR)
check("add-address refuses bad checksum without seed warning",
      msg is not None and "SEED" not in msg and "checksum" in msg)

out, msg = run("add-address", address=GOOD_ADDR)
check("add-address accepts valid address",
      msg is None and GOOD_ADDR in out)
check("address persisted",
      GOOD_ADDR in C.load_profile()["xrpl_addresses"])

out, msg = run("add-address", expect_exit=True, address=GOOD_ADDR)
check("add-address dedupes", msg is not None and "already" in msg)

out, msg = run("remove-address", expect_exit=True, address=GOOD_ADDR2)
check("remove-address missing -> error", msg is not None)
out, msg = run("remove-address", address=GOOD_ADDR)
check("remove-address works", GOOD_ADDR not in C.load_profile()["xrpl_addresses"])

# ---------- scalar fields ----------

fresh()
out, msg = run("set", expect_exit=True, field="display_name", value="   ")
check("set display_name refuses empty", msg is not None)
out, msg = run("set", expect_exit=True, field="display_name", value="x" * 41)
check("set display_name refuses >40 chars", msg is not None)
out, msg = run("set", field="display_name", value="  Mike  ")
check("set display_name strips",
      C.load_profile()["display_name"] == "Mike")

for val, want in [("true", True), ("yes", True), ("1", True),
                  ("false", False), ("no", False), ("0", False)]:
    out, msg = run("set", field="alerts.price_moves", value=val)
    check(f"set alerts.price_moves {val} -> {want}",
          C.load_profile()["alerts"]["price_moves"] is want)
out, msg = run("set", expect_exit=True, field="alerts.price_moves",
               value="maybe")
check("set alerts.price_moves refuses junk", msg is not None)

out, msg = run("set", field="alerts.threshold_pct", value="5")
check("set alerts.threshold_pct 5",
      C.load_profile()["alerts"]["threshold_pct"] == 5.0)
for bad in ["abc", "0.1", "100", "-3"]:
    out, msg = run("set", expect_exit=True, field="alerts.threshold_pct",
                   value=bad)
    check(f"set alerts.threshold_pct refuses {bad!r}", msg is not None)

out, msg = run("set", expect_exit=True, field="nope", value="x")
check("set unknown field refused", msg is not None and "unknown" in msg)

# ---------- memberships / interests ----------

fresh()
out, msg = run("add-membership", name="XAO DAO")
check("add-membership normalizes case/space",
      C.load_profile()["memberships"] == ["xao dao"])
out, msg = run("add-membership", expect_exit=True, name="XAO DAO")
check("add-membership dedupes", msg is not None and "already" in msg)
out, msg = run("add-membership", expect_exit=True, name="bad!!name")
check("add-membership refuses bad chars", msg is not None)
out, msg = run("add-interest", name="Trading")
check("add-interest normalizes",
      C.load_profile()["interests"] == ["trading"])
out, msg = run("remove-interest", expect_exit=True, name="defi")
check("remove-interest missing -> error", msg is not None)
out, msg = run("remove-membership", name="xao dao")
check("remove-membership works",
      C.load_profile()["memberships"] == [])

# ---------- show / clear ----------

fresh()
out, msg = run("show")
check("show with no profile points at init", "profile init" in out)
run("set", field="display_name", value="Mike")
out, msg = run("show")
check("show renders name", "Mike" in out)
out, msg = run("clear")
check("clear deletes file", not C.PROFILE_PATH.exists())

# ---------- file handling ----------

fresh()
run("set", field="display_name", value="Mike")
mode = oct(C.PROFILE_PATH.stat().st_mode & 0o777)
check("profile file is 0600", mode == "0o600")

C.PROFILE_PATH.write_text("{not json")
try:
    C.load_profile()
    check("corrupt profile raises ProfileError", False)
except C.ProfileError:
    check("corrupt profile raises ProfileError", True)

C.PROFILE_PATH.write_text(json.dumps({"schema_version": 99}))
try:
    C.load_profile()
    check("future schema raises ProfileError", False)
except C.ProfileError as e:
    check("future schema raises ProfileError", "newer" in str(e))

# missing keys get defaults, not a crash
C.PROFILE_PATH.write_text(json.dumps({"display_name": "Zed"}))
prof = C.load_profile()
check("partial profile fills defaults",
      prof["xrpl_addresses"] == [] and prof["alerts"]["threshold_pct"] == 3.0
      and prof["display_name"] == "Zed")

# ---------- init questionnaire ----------

fresh()
script = iter([
    "Mike",            # display name
    SEED,              # address attempt 1: seed -> refused, re-prompt
    GOOD_ADDR,         # address attempt 2: ok
    "",                # done with addresses
    "xaodao",          # memberships
    "trading, nfts",   # interests
    "y",               # price alerts yes
    "5",               # threshold
    "",                # giveaway opt-in: skip
])


def fake_input(prompt):
    return next(script)


buf = io.StringIO()
with redirect_stdout(buf):
    T.run_profile_init(C.default_profile(), _input=fake_input)
out = buf.getvalue()
prof = C.load_profile()
check("init: seed refused loudly, re-prompted",
      "SEED" in out and prof["xrpl_addresses"] == [GOOD_ADDR])
check("init: name saved", prof["display_name"] == "Mike")
check("init: membership saved", prof["memberships"] == ["xaodao"])
check("init: interests saved", prof["interests"] == ["trading", "nfts"])
check("init: alerts saved",
      prof["alerts"] == {"price_moves": True, "threshold_pct": 5.0})
check("init: giveaway defaults (not opted in)",
      prof["giveaway"] == {"opt_in": False, "opt_in_tx": None})

# schema-v1 profiles written before the giveaway feature gain the defaults
old_path = TMP / "old_profile.json"
old_path.write_text(json.dumps({"display_name": "Old"}))
prof = C.load_profile(old_path)
check("old v1 profile gains giveaway defaults",
      prof["giveaway"] == {"opt_in": False, "opt_in_tx": None}
      and prof["display_name"] == "Old")

# init when a profile already exists: no prompts, no overwrite
calls = []


def counting_input(prompt):
    calls.append(prompt)
    return ""


buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_profile(ns(prof_cmd="init"))
check("init with existing profile does not prompt",
      not calls and "already have a profile" in buf.getvalue())
check("init with existing profile keeps data",
      C.load_profile()["display_name"] == "Mike")

# init abort via quit: nothing saved
fresh()
buf = io.StringIO()
with redirect_stdout(buf):
    T.run_profile_init(C.default_profile(), _input=lambda p: "quit")
check("init quit saves nothing", not C.PROFILE_PATH.exists())

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
