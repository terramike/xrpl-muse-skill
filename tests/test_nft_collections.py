#!/usr/bin/env python3
"""NFT collections + templates + attribution tests — no network (ledger
lookups are faked). Run: python3 tests/test_nft_collections.py

Covers: registry CRUD + validation (collections, templates), taxon uint32
validation, template field parsing, --collection resolution (royalty
default / explicit override / conflicts), attribution injection + opt-out,
the authorized-minter check (mocked ledger), stage-format/issuer/field
digest binding, and issuer threading into the NFTokenMint.
"""
import argparse
import importlib.util
import json
import sys
import tempfile
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
T = load(BIN / "xrpl-trade", "xrpl_trade_coll")
P = load(BIN / "xrpl_pin.py", "xrpl_pin")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet
ACCT = Wallet.create().classic_address
ISSUER = Wallet.create().classic_address
MINTER = Wallet.create().classic_address
OTHER = Wallet.create().classic_address


class FakeResp:
    def __init__(self, result, ok=True):
        self.result = result
        self._ok = ok

    def is_successful(self):
        return self._ok


class FakeClient:
    """Fake XRPL client. handler(request) -> FakeResp (or raises)."""
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, req):
        self.calls.append(req)
        return self.handler(req)


def expect_exit(fn, *a, **k):
    try:
        fn(*a, **k)
    except SystemExit as e:
        return str(e)
    return None


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    C.XRPL_DIR = tmp
    C.COLLECTIONS_PATH = tmp / "collections.json"
    C.TEMPLATES_PATH = tmp / "nft-templates.json"
    C.STAGE_DIR = tmp / "stage"
    C.AUDIT_PATH = tmp / "audit.log"

    # pinner mocks (same approach as test_nft.py)
    tmedia = Path(tempfile.mkdtemp(prefix="xrpl-coll-media-"))
    T.xrpl_pin = P
    real_pmd = P.protected_media_dir
    P.protected_media_dir = lambda: str(tmedia)
    PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    art = tmedia / "art.png"
    art.write_bytes(PNG)
    cfg = {"address": ACCT, "network": "testnet"}

    def stage_ns(**kw):
        base = dict(file=str(art), name="Test NFT", description="",
                    royalty_bps=None, taxon=None, collection=None,
                    issuer=None, template=None, meta=None,
                    no_attribution=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def coll_ns(cmd, **kw):
        base = dict(coll_cmd=cmd, name=None, taxon=None, issuer=None,
                    description="", royalty_bps=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def tmpl_ns(cmd, **kw):
        base = dict(tmpl_cmd=cmd, name=None, field=None)
        base.update(kw)
        return argparse.Namespace(**base)

    # --- 1. validate_taxon ---
    t, p = C.validate_taxon(200)
    check("validate_taxon accepts 200", t == 200 and p is None)
    t, p = C.validate_taxon("200")
    check("validate_taxon accepts '200'", t == 200 and p is None)
    t, p = C.validate_taxon(0)
    check("validate_taxon accepts 0", t == 0 and p is None)
    t, p = C.validate_taxon(0xFFFFFFFF)
    check("validate_taxon accepts uint32 max", t == 0xFFFFFFFF and p is None)
    for bad in (-1, 0x100000000, "abc", "", None, 1.5, True):
        t, p = C.validate_taxon(bad)
        check(f"validate_taxon refuses {bad!r}", t is None and p)

    # --- 2. registry name validation ---
    check("good collection name",
          C.validate_registry_name("xrjets-2", "collection") is None)
    for bad in ("Jets", "has space", "a" * 33, "", "UPPER", "dot.name"):
        check(f"registry name refused: {bad!r}",
              C.validate_registry_name(bad, "collection") is not None)

    # --- 3. template field parsing ---
    label, req, p = C.parse_template_field("attack:required")
    check("field 'attack:required'",
          label == "attack" and req is True and p is None)
    label, req, p = C.parse_template_field("gun1")
    check("field 'gun1' defaults optional",
          label == "gun1" and req is False and p is None)
    label, req, p = C.parse_template_field("speed:optional")
    check("field 'speed:optional'",
          label == "speed" and req is False and p is None)
    label, req, p = C.parse_template_field("a:b:required")
    check("label containing ':' keeps prefix",
          label == "a:b" and req is True and p is None)
    for bad in ("name:required", "image", "minted_with_url:optional", "",
                "x" * 65, "bad\x01label"):
        label, req, p = C.parse_template_field(bad)
        check(f"field refused: {bad!r}", p is not None)

    # --- 4. collections CRUD ---
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="jets", taxon="200",
                              issuer=ISSUER, description="jets coll",
                              royalty_bps=1000), cfg, None)
    check("collection create succeeds", msg is None)
    check("collection file is 0600",
          (C.COLLECTIONS_PATH.stat().st_mode & 0o777) == 0o600)
    colls = C.load_collections()
    check("collection entry shape",
          colls["jets"]["issuer"] == ISSUER
          and colls["jets"]["taxon"] == 200
          and colls["jets"]["royalty_bps"] == 1000
          and colls["jets"]["description"] == "jets coll"
          and isinstance(colls["jets"]["created_at"], int))
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="jets", taxon="1",
                              issuer=ISSUER), cfg, None)
    check("duplicate collection refused", msg is not None and "already exists" in msg)
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="bad", taxon="99999999999",
                              issuer=ISSUER), cfg, None)
    check("collection create refuses bad taxon",
          msg is not None and "uint32" in msg)
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="bad2", taxon="5",
                              issuer="notanaddress"), cfg, None)
    check("collection create refuses bad issuer",
          msg is not None and "valid classic address" in msg)
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="Bad Name", taxon="5",
                              issuer=ISSUER), cfg, None)
    check("collection create refuses bad name",
          msg is not None and "invalid" in msg)
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="r2", taxon="5",
                              issuer=ISSUER, royalty_bps=99999), cfg, None)
    check("collection create refuses royalty > 5000",
          msg is not None and "0..5000" in msg)
    # default issuer = configured account
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="mine", taxon="7"), cfg, None)
    check("collection create defaults issuer to account",
          msg is None and C.load_collections()["mine"]["issuer"] == ACCT)
    # corrupt registry fails loud
    C.COLLECTIONS_PATH.write_text("{not json")
    try:
        C.load_collections()
        check("corrupt collections registry fails loud", False)
    except C.RegistryError:
        check("corrupt collections registry fails loud", True)
    msg = expect_exit(T.cmd_collection, coll_ns("list"), cfg, None)
    check("commands refuse corrupt registry", msg is not None)
    C.COLLECTIONS_PATH.unlink()
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="jets", taxon="200",
                              issuer=ISSUER, royalty_bps=1000), cfg, None)
    check("recreate after corrupt delete", msg is None)
    msg = expect_exit(T.cmd_collection, coll_ns("remove", name="nope"),
                      cfg, None)
    check("remove unknown collection refused", msg is not None)
    msg = expect_exit(T.cmd_collection, coll_ns("remove", name="jets"),
                      cfg, None)
    check("collection remove succeeds",
          msg is None and "jets" not in C.load_collections())

    # --- 5. templates CRUD ---
    msg = expect_exit(T.cmd_template,
                      tmpl_ns("create", name="jets",
                              field=["attack:required", "speed:required",
                                     "gun1"]), cfg, None)
    check("template create (args) succeeds", msg is None)
    check("template file is 0600",
          (C.TEMPLATES_PATH.stat().st_mode & 0o777) == 0o600)
    tmpls = C.load_templates()
    check("template entry shape",
          tmpls["jets"]["fields"] == [
              {"label": "attack", "required": True},
              {"label": "speed", "required": True},
              {"label": "gun1", "required": False}])
    msg = expect_exit(T.cmd_template,
                      tmpl_ns("create", name="jets", field=["x"]), cfg, None)
    check("duplicate template refused", msg is not None and "already exists" in msg)
    msg = expect_exit(T.cmd_template,
                      tmpl_ns("create", name="bad",
                              field=["attack", "attack"]), cfg, None)
    check("duplicate field label refused", msg is not None and "duplicate" in msg)
    msg = expect_exit(T.cmd_template,
                      tmpl_ns("create", name="bad2",
                              field=["name:required"]), cfg, None)
    check("reserved field label refused", msg is not None and "reserved" in msg)
    # interactive create with zero fields -> refused ("at least one field")
    answers = iter(["emptyname", ""])
    import builtins
    orig_input = builtins.input
    builtins.input = lambda prompt="": next(answers)
    try:
        msg = expect_exit(T.cmd_template, tmpl_ns("create"), cfg, None)
    finally:
        builtins.input = orig_input
    check("template with no fields refused",
          msg is not None and "at least one field" in msg)
    check("nothing saved after empty interactive create",
          "emptyname" not in C.load_templates())
    # interactive create (mocked input)
    answers = iter(["ijets", "power", "y", "color", "n", ""])
    import builtins
    orig_input = builtins.input
    builtins.input = lambda prompt="": next(answers)
    try:
        msg = expect_exit(T.cmd_template, tmpl_ns("create"), cfg, None)
    finally:
        builtins.input = orig_input
    check("template create (interactive) succeeds", msg is None)
    it = C.load_templates()["ijets"]["fields"]
    check("interactive fields parsed",
          it == [{"label": "power", "required": True},
                 {"label": "color", "required": False}])
    msg = expect_exit(T.cmd_template, tmpl_ns("remove", name="nope"),
                      cfg, None)
    check("remove unknown template refused", msg is not None)
    msg = expect_exit(T.cmd_template, tmpl_ns("remove", name="ijets"),
                      cfg, None)
    check("template remove succeeds",
          msg is None and "ijets" not in C.load_templates())
    C.TEMPLATES_PATH.write_text("[1,2")
    try:
        C.load_templates()
        check("corrupt templates registry fails loud", False)
    except C.RegistryError:
        check("corrupt templates registry fails loud", True)
    C.TEMPLATES_PATH.unlink()

    # --- 6. check_nft_mint_authorization (mocked ledger) ---
    check("signer == issuer needs no lookup",
          C.check_nft_mint_authorization(FakeClient(lambda r: (_ for _ in ()).throw(
              AssertionError("must not call the ledger"))), ISSUER, ISSUER) is None)

    def minter_client(minter_value, ok=True, validated=True, explode=False):
        def handler(req):
            if explode:
                raise ConnectionError("node down")
            return FakeResp({"validated": validated,
                             "account_data": {"NFTokenMinter": minter_value}},
                            ok=ok)
        return FakeClient(handler)

    check("authorized minter passes",
          C.check_nft_mint_authorization(
              minter_client(MINTER), ISSUER, MINTER) is None)
    p = C.check_nft_mint_authorization(minter_client(OTHER), ISSUER, MINTER)
    check("wrong minter refused", p is not None and "refusing" in p)
    p = C.check_nft_mint_authorization(minter_client(None), ISSUER, MINTER)
    check("absent NFTokenMinter refused", p is not None and "refusing" in p)
    p = C.check_nft_mint_authorization(
        minter_client(MINTER, ok=False), ISSUER, MINTER)
    check("node error refused", p is not None and "refusing" in p)
    p = C.check_nft_mint_authorization(
        minter_client(MINTER, validated=False), ISSUER, MINTER)
    check("unvalidated ledger data refused",
          p is not None and "unvalidated" in p)
    p = C.check_nft_mint_authorization(
        minter_client(MINTER, explode=True), ISSUER, MINTER)
    check("lookup exception refused", p is not None and "refusing" in p)

    # --- 7. count_collection_tokens (mocked ledger) ---
    def nfts_client(entries, validated=True, ok=True):
        def handler(req):
            return FakeResp({"validated": validated,
                             "account_nfts": entries}, ok=ok)
        return FakeClient(handler)
    entries = [{"NFTokenID": "AA" * 32, "NFTokenTaxon": 200},
               {"NFTokenID": "BB" * 32, "NFTokenTaxon": 7},
               {"NFTokenID": "CC" * 32, "NFTokenTaxon": 200}]
    count, recent, problem = C.count_collection_tokens(
        nfts_client(entries), ISSUER, 200)
    check("inspect counts only matching taxon",
          count == 2 and recent == ["AA" * 32, "CC" * 32] and problem is None)
    count, recent, problem = C.count_collection_tokens(
        nfts_client(entries, validated=False), ISSUER, 200)
    check("inspect refuses unvalidated data", problem is not None)
    count, recent, problem = C.count_collection_tokens(
        nfts_client(entries, ok=False), ISSUER, 200)
    check("inspect refuses node error", problem is not None)

    # --- 8. nft-stage --collection resolution ---
    msg = expect_exit(T.cmd_collection,
                      coll_ns("create", name="jets", taxon="200",
                              issuer=ACCT, royalty_bps=1000), cfg, None)
    assert msg is None
    msg = expect_exit(T.cmd_template,
                      tmpl_ns("create", name="jets",
                              field=["attack:required", "gun1"]), cfg, None)
    assert msg is None
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(collection="jets", template="jets",
                                 meta=["attack=90", "gun1=railgun"]),
                        cfg, None)
    out = buf.getvalue()
    rec = json.loads((C.STAGE_DIR / f"{out.split('stage id: ')[1].split()[0]}.json").read_text())
    check("collection resolves taxon", rec["taxon"] == 200)
    check("collection resolves royalty default",
          rec["royalty_bps"] == 1000)
    # self-issued collection (issuer == minter): normalized to None so the
    # mint carries no Issuer field
    check("self-issued collection normalizes issuer to None",
          rec["issuer"] is None)
    check("collection name recorded", rec["collection"] == "jets")
    check("template fields land in metadata",
          rec["metadata"]["attack"] == "90"
          and rec["metadata"]["gun1"] == "railgun")
    # explicit royalty overrides the collection default
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(collection="jets", royalty_bps=500),
                        cfg, None)
    out = buf.getvalue()
    rec = json.loads((C.STAGE_DIR / f"{out.split('stage id: ')[1].split()[0]}.json").read_text())
    check("explicit --royalty-bps overrides collection default",
          rec["royalty_bps"] == 500)
    # conflicts and unknowns
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="jets", taxon=5), cfg, None)
    check("--collection + --taxon refused",
          msg is not None and "not both" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="nope"), cfg, None)
    check("unknown collection refused", msg is not None and "unknown" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="jets", issuer=OTHER), cfg, None)
    check("--issuer mismatching the collection refused",
          msg is not None and "does not match" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="jets", template="jets",
                 meta=["attack=90", "bogus=1"]), cfg, None)
    check("unknown --meta key vs template refused",
          msg is not None and "not a field of template" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="jets", template="jets",
                 meta=["gun1=x"]), cfg, None)
    check("missing required template field refused",
          msg is not None and "requires" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(collection="jets", template="nope",
                 meta=["attack=1"]), cfg, None)
    check("unknown template refused", msg is not None and "unknown" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(meta=["name=x"]), cfg, None)
    check("ad-hoc --meta colliding with reserved key refused",
          msg is not None and "reserved" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(meta=["oops"]), cfg, None)
    check("malformed --meta refused", msg is not None and "KEY=VALUE" in msg)
    msg = expect_exit(T.cmd_nft_stage, stage_ns(meta=["k="]), cfg, None)
    check("empty --meta value refused", msg is not None and "empty value" in msg)
    # minter check runs BEFORE staging: unauthorized issuer, no stage written
    before = set(p.name for p in C.STAGE_DIR.glob("*.json"))
    msg = expect_exit(T.cmd_nft_stage, stage_ns(issuer=ISSUER), cfg,
                      minter_client(OTHER))
    after = set(p.name for p in C.STAGE_DIR.glob("*.json"))
    check("unauthorized issuer refused before staging",
          msg is not None and "refusing" in msg and before == after)

    # --- 9. attribution injection + opt-out ---
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(), cfg, None)
    out = buf.getvalue()
    rec = json.loads((C.STAGE_DIR / f"{out.split('stage id: ')[1].split()[0]}.json").read_text())
    check("attribution injected by default",
          rec["attribution"] is True
          and rec["metadata"]["minted_with"] == "XRPL-Muse"
          and rec["metadata"]["minted_with_url"]
          == "https://github.com/terramike/xrpl-muse-skill")
    check("stage review shows attribution",
          "Minted with XRPL-Muse" in out)
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(no_attribution=True), cfg, None)
    out = buf.getvalue()
    rec = json.loads((C.STAGE_DIR / f"{out.split('stage id: ')[1].split()[0]}.json").read_text())
    check("--no-attribution omits the block",
          rec["attribution"] is False
          and "minted_with" not in rec["metadata"]
          and "minted_with_url" not in rec["metadata"])
    check("stage review shows omission",
          "--no-attribution" in out)

    # --- 10. pin step: digest binding + issuer threading + ceremony ---
    real_propose = T.propose
    proposed = {}

    def fake_propose(tx, client, cfg_, action, summary_lines):
        proposed["tx"] = tx
        proposed["summary"] = "\n".join(summary_lines)
        return "deadbeef" * 8

    T.propose = fake_propose
    real_pin_data = P.pin_data
    real_pin_json = P.pin_json
    pinned = {}
    P.pin_data = lambda data, filename: (pinned.update(bytes=bytes(data)), "bafyimg")[1]
    P.pin_json = lambda obj, name="metadata.json": (pinned.update(meta=dict(obj)), "bafymeta")[1]

    # issuer threading: minter != issuer (recheck needs a client, so pass
    # the fake ledger client instead of None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(issuer=ISSUER),
                        {"address": MINTER, "network": "testnet"},
                        minter_client(MINTER))
    out = buf.getvalue()
    sid = out.split("nft-pin-and-propose --stage ")[1].split()[0]
    h = T.pin_and_propose_stage(
        sid, {"address": MINTER, "network": "testnet"},
        minter_client(MINTER))
    check("pin succeeds for authorized minter", h == "deadbeef" * 8)
    txd = proposed["tx"].to_xrpl()
    check("NFTokenMint carries the collection Issuer",
          txd.get("Issuer") == ISSUER and txd.get("Account") == MINTER)
    check("pinned metadata carries attribution",
          pinned["meta"].get("minted_with") == "XRPL-Muse")
    check("proposal ceremony shows attribution",
          "Minted with XRPL-Muse" in proposed["summary"])
    check("proposal ceremony shows issuer flow",
          "authorized minter" in proposed["summary"])

    # self-issued: no Issuer field on the tx
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(), cfg, None)
    sid = buf.getvalue().split("nft-pin-and-propose --stage ")[1].split()[0]
    T.pin_and_propose_stage(sid, cfg, None)
    txd = proposed["tx"].to_xrpl()
    check("self-issued mint has no Issuer field", "Issuer" not in txd)
    # pin-time recheck: authorization revoked after staging -> the pin
    # refuses BEFORE Pinata is contacted
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_nft_stage(stage_ns(issuer=ISSUER),
                        {"address": MINTER, "network": "testnet"},
                        minter_client(MINTER))
    sid = buf.getvalue().split("nft-pin-and-propose --stage ")[1].split()[0]
    pinned.clear()
    msg = expect_exit(T.pin_and_propose_stage,
                      sid, {"address": MINTER, "network": "testnet"},
                      minter_client(OTHER))
    check("pin refuses revoked authorization before Pinata",
          msg is not None and "revoked" in msg and not pinned)
    # pin-time recheck without a client -> refuse rather than mint blind
    msg = expect_exit(T.pin_and_propose_stage,
                      sid, {"address": MINTER, "network": "testnet"}, None)
    check("pin refuses authorized-minter flow without a client",
          msg is not None and "without a network client" in msg)
    # strict schema: NFTokenMint with Issuer (authorized-minter flow) and
    # without (self-issued) both pass validate_tx_shape
    shape = lambda d: C.validate_tx_shape(d, C.DEFAULT_ALLOWED_TX_TYPES)
    base = {"TransactionType": "NFTokenMint", "Account": MINTER,
            "NFTokenTaxon": 200, "URI": "B" * 64, "Flags": 11,
            "TransferFee": 1000}
    check("strict schema accepts authorized-minter NFTokenMint",
          shape({**base, "Issuer": ISSUER}) == [])
    check("strict schema accepts self-issued NFTokenMint",
          shape(base) == [])

    # tamper: edited issuer in the stage record
    stage_file = C.STAGE_DIR / f"{sid}.json"
    rec = json.loads(stage_file.read_text())
    rec["issuer"] = OTHER
    stage_file.write_text(json.dumps(rec))
    msg = expect_exit(T.pin_and_propose_stage, sid, cfg, None)
    check("pin refuses edited issuer",
          msg is not None and "stage digest does not match" in msg)
    # tamper: dropped attribution key from metadata
    rec = json.loads(stage_file.read_text())
    rec["issuer"] = None
    del rec["metadata"]["minted_with"]
    stage_file.write_text(json.dumps(rec))
    msg = expect_exit(T.pin_and_propose_stage, sid, cfg, None)
    check("pin refuses dropped attribution key",
          msg is not None and "attribution block is inconsistent" in msg)
    # tamper: injected metadata field
    rec = json.loads(stage_file.read_text())
    rec["metadata"]["minted_with"] = "XRPL-Muse"
    rec["metadata"]["evil"] = "1"
    stage_file.write_text(json.dumps(rec))
    msg = expect_exit(T.pin_and_propose_stage, sid, cfg, None)
    check("pin refuses injected metadata field",
          msg is not None and "inconsistent" in msg)
    # old stage/2 records are rejected
    rec["format"] = "nft-stage/2"
    stage_file.write_text(json.dumps(rec))
    msg = expect_exit(T.pin_and_propose_stage, sid, cfg, None)
    check("pre-v3 stage records are rejected",
          msg is not None and "unsupported format" in msg)

    T.propose = real_propose
    P.pin_data = real_pin_data
    P.pin_json = real_pin_json
    P.protected_media_dir = real_pmd

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
