# AGENTS.md — contributor guidance for xrpl-muse-skill

This repo is a terminal skill for trading the XRP Ledger, built for AI
agents. Two programs, one hard boundary: `bin/xrpl-trade` builds
transactions and **never signs**; `bin/xrpl-sign` is the only program
that touches a seed, and only with explicit human approval of an exact
proposal hash. Read `SKILL.md` for the full operator manual and
`SECURITY.md` for the safety model before changing behavior.

## Setup

```bash
pip install -r requirements-locked.txt
export PATH="$PWD/bin:$PATH"
```

No keys needed for reads or for running the unit tests.

## Tests

```bash
python3 -m unittest tests.test_readonly   # read-only ceremony, no network
python3 -m unittest tests.test_eco        # ecosystem connectors, no network
python3 -m unittest tests.test_onboarding # wizard spec, no network
python3 -m unittest tests.test_v04        # 78 adversarial logic tests
```

Run the affected suites before every change; keep them green. Known
issues (don't "fix" by deleting): `tests/test_v060.py` references a
removed symbol (`C.StateCorruptError` — stale test, needs a real fix);
`tests/test_wallet.py` needs live network and hangs offline.

## Conventions

- **Read-only first.** New features default to keyless reads. Anything
  that signs goes through propose → approve → sign, no exceptions.
- **Fail open on reads.** A down endpoint prints a clear "unavailable"
  note — never raise, never fabricate data.
- **Attribute external data.** Every third-party line names its source
  (e.g. "per DefiLlama"); aggregator data is labeled
  aggregator-not-authority, oracle data publisher-attested.
- **Tickers mean nothing on XRPL.** Token identity is the issuer
  address; pairs map to vetted issuers.
- **Tests are behavior specs.** When you change a command, update its
  tests in the same commit.

## Never do these

- Never request, reveal, or record a seed — in code, docs, tests, or
  chat. No exceptions.
- Never add a bypass around the `live` typed ceremony. No CLI flag, no
  env var, no config shortcut. The existing test asserts the bypass is
  absent; keep it that way.
- Never silently edit the policy model (`policy.example.json` documents
  it; real policy files live outside this repo). Policy changes are
  explicit, versioned, and human-approved.
- Keep hidden commands hidden: don't add them to `--help`, menus,
  `SKILL.md`, `llms.txt`, or release notes.
- Don't invent prices, availability, fees, or network facts in docs or
  output. If it isn't on the ledger or from a named source, say so.

## Releases (maintainer only)

Releases are cut by the maintainer with a Git Data API helper — don't
try to push tags or releases yourself. Two standing rules the helper
enforces and you must preserve:

1. **Autonomous mode is local-only, dry-run-only, unreleased.** Its
   files are excluded from the public tree. Don't re-add them to a
   release, and don't document a live autonomous mode that doesn't
   exist here.
2. **Review before publish.** Nothing ships until the exact scope —
   commit list, diff, and release notes — has been explicitly approved.

`SKILL.md` is the source of truth for behavior; if code and docs
disagree, fix the code or update the docs in the same change — never
leave them contradicting each other.
