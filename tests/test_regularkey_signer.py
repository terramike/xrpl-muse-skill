#!/usr/bin/env python3
"""RegularKey signer-path regression tests — no network.

v0.8.0 shipped a hard `wallet.classic_address != tx["Account"]` refusal in
xrpl-sign that ran BEFORE any RegularKey check, so a seed deriving to the
account's on-ledger RegularKey (the legitimate signer for disabled-master
accounts) was rejected outright. v0.8.1 verifies the derived address against
the validated ledger's RegularKey field instead.

Run: python3 tests/test_regularkey_signer.py
"""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as ns

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common_regkey")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


ACCT = "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB"
REGKEY = "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB"
FOREIGN = "rForeignSeedDerivesHere111111111111"


def mock_client(regular_key="__unset__", ok=True, raises=False):
    """Fake XRPL client returning a canned AccountInfo response."""
    def request(req):
        if raises:
            raise ConnectionError("node down")
        result = {"account_data": {"Account": ACCT, "Flags": 0}}
        if regular_key != "__unset__":
            result["account_data"]["RegularKey"] = regular_key
        return ns(is_successful=lambda: ok, result=result)
    return ns(request=request)


# --- validated_regular_key ---

r = C.validated_regular_key(mock_client(regular_key=REGKEY), ACCT)
check("validated_regular_key returns on-ledger RegularKey", r == REGKEY)

r = C.validated_regular_key(mock_client(regular_key=None), ACCT)
check("validated_regular_key returns None when unset", r is None)

r = C.validated_regular_key(mock_client(raises=True), ACCT)
check("validated_regular_key returns ERROR on node exception", r == "ERROR")

r = C.validated_regular_key(mock_client(ok=False), ACCT)
check("validated_regular_key returns ERROR on bad response", r == "ERROR")

# --- check_signer_authorization ---

d = C.check_signer_authorization(mock_client(regular_key=REGKEY), ACCT, ACCT)
check("master seed accepted (delegated to disabled-master check)",
      d is None)

d = C.check_signer_authorization(mock_client(regular_key=REGKEY), ACCT, REGKEY)
check("REGRESSION: RegularKey seed accepted (was refused pre-v0.8.1)",
      d is None)

d = C.check_signer_authorization(mock_client(regular_key=REGKEY), ACCT, FOREIGN)
check("foreign seed refused when RegularKey is set",
      d is not None and "refusing" in d)

d = C.check_signer_authorization(mock_client(regular_key=None), ACCT, FOREIGN)
check("foreign seed refused when no RegularKey set",
      d is not None and "refusing" in d)

d = C.check_signer_authorization(mock_client(raises=True), ACCT, REGKEY)
check("fail closed on node error (even for the real RegularKey)",
      d is not None and "fail closed" in d)

d = C.check_signer_authorization(mock_client(regular_key=REGKEY), ACCT, FOREIGN)
check("denial names the derived address and on-ledger key",
      FOREIGN in d and REGKEY in d)

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
