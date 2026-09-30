# Forensic mode (Phase 1: light)

Read-only investigative tools. No keys, no proposals, no signing —
pure public-ledger reads with a hard API-call budget.

## Commands

```bash
xrpl-trade trace <address> [--depth N] [--no-cache]
xrpl-trade links <addressA> <addressB> [--window N] [--no-cache]
```

**`trace`** walks the funding chain backwards: the account's first
transaction (fetched oldest-first via `account_tx` with `forward: true`
— one RPC call), its funder, and so on. Default depth 2, max 3. Each
hop also reports control signals from `account_info` + `account_objects`:
RegularKey set?, signer list (quorum + member count)?, domain? (decoded
from hex). A hop whose birth tx isn't an inbound Payment ends the chain
honestly instead of guessing.

**`links`** compares two accounts over their N most recent validated
txs (default 200, max 500) and reports, strongest signal first:

1. **Control overlap** — same RegularKey on both accounts, or shared
   signer-list members.
2. **Shared counterparties** — addresses appearing in both windows,
   ranked by combined tx count, with per-side counts.
3. **Shared trustline issuers** — from `account_lines`.

Counterparties are extracted per tx type: Payment → sender/destination,
TrustSet → the other party, EscrowCreate/Finish and PaymentChannelCreate
→ counterparty, NFTokenAcceptOffer → the offer holder (via a capped
`ledger_entry` lookup, 5 per account). `OfferCreate` counts as DEX
activity with no counterparty claim — light mode doesn't attribute
DEX fills.

## Budgets and caching

- `trace`: ≤ 4 RPC calls per hop (first tx, account info, account
  objects, ledger close-time) → ≤ 16 at max depth. Actual usage is
  printed (`used 8 of ≤8 RPC calls`).
- `links`: ~2 tx-page calls + 2 info + 2 objects + 2 lines per account
  at default window; NFT offer lookups capped at 5 per account.
- Results cached 1 hour under `~/.xrpl/forensics-cache/`
  (override: `XRPL_FORENSICS_CACHE`); `--no-cache` bypasses.

## Language discipline

Output uses `LINK:` for on-ledger relationships (facts) and `NOTE:`
for caveats. The word "owner" never appears in output — a link is not
proof of common control, and the tool never blurs that line. A shared
counterparty can be an exchange hot wallet or public service; every
shared-counterparty section carries that caveat.

## Failure behavior

Fail open, like every other read in the skill: a dead endpoint prints
`⚠️ … (network error)` and whatever was gathered is still shown.
Network failure is distinguished from empty results — "no on-ledger
history" is only printed when the network actually answered. Partial
results are labeled partial, never presented as complete.

## What's NOT here (Phase 2 backlog)

Flow analysis (volume over time), a known-exchange address list to
suppress false-positive links, and `nft-trail` (full mint → sale
provenance for a token ID).

Implementation: `bin/xrpl_forensics.py`. Tests:
`tests/test_forensics.py` (28 tests, fixture-driven, no network).
