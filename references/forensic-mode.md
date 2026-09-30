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
- `links`: per account ~1–3 tx pages (window/200) + 1 info + 1 objects +
  1–2 trustline pages + up to 5 NFT-offer lookups; plus up to 3
  issuer-profile lookups enriching the shared-token section. Actual
  usage is printed (`used 17 RPC calls (cached where possible)`).
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

## Phase 2

Three new commands, a token section in `links`, and a known-address
label registry.

**`flow <address> [--window N]`** — top counterparties by volume, in
and out, over the N most recent validated txs (default 200, max 500).
Payments use delivered amounts; `OfferCreate` txs attribute executed
fills to their makers via `AffectedNodes`. Ranked by XRP volume (IOU
volumes shown per row, units unconverted). Volumes are wash-tradable —
flow is discovery, not proof of economic substance.

**`nft-trail <token-id>`** — provenance for one NFToken: mint →
offers → transfers/sales → currently held by. Primary source is the
`nft_history` ledger method (newest-first, walked chronologically);
when a node doesn't support it, the tool falls back to a bounded scan
of the issuer's history for the mint tx (the issuer address is decoded
from the token ID itself) and says so. Open sell/buy offers are shown.
The chain is on-ledger only — off-ledger deals are invisible.

**`token-trail --issuer r… --currency CODE [--window N]`** — the token
lens. Three parts: (1) issuer profile — decoded domain, transfer fee,
global-freeze / no-freeze flags, tick size (advisory, reuses
`inspect-token` signals); (2) holder spread — top 10 from a bounded
`account_lines` scan, **explicitly labeled partial**, never a full
distribution; (3) movers — top addresses by token volume in the window,
**issuer-involved flow only** (issuance, redemption, rippling through
the issuer): ordinary holder-to-holder transfers don't touch the issuer
account and are invisible to this scan, so this is not a general
"most active traders" list. Currency accepts 3-letter codes, 40-char
hex, and short names like `RLUSD` (normalized to ledger hex form).
Issuer flags are current state and can change.

**`links` token section** — a fourth section after shared issuers:
tokens (currency + issuer) both accounts hold or touched, ranked by
combined tx count, with transfer-fee / freeze flags for the top 3
issuers. Printed with the explicit caveat that sharing a token is a
weak link.

**Labels.** `references/known-labels.json` ships the registry (starts
empty — framework first; entries are only added `verified` with
on-ledger or official-source evidence). The user's own
`~/.xrpl/labels.local.json` overrides it. Wherever a labeled address
appears (`trace` / `links` / `flow` / `nft-trail` / `token-trail`), it
prints inline as
`LABEL: r… — "Example Exchange hot wallet" (verified)`
plus a once-per-command note: links through labeled service wallets are
usually plumbing, not relationships. Labels are not identity proof.

Language additions: `LABEL:` for registry labels; NFTs are "held by",
never "owned by". `flow`, `nft-trail`, and `token-trail` state their
budgets up front; `links` prints actual usage (`used N RPC calls`).
Response metadata arrives beside the tx on live nodes and is merged
before parsing, so delivered amounts and DEX fills read correctly. A
history-thin node (fewer than ~100k ledgers of history) that returns an
empty window gets an explicit note — empty can mean the node is blind,
not that the account is quiet. Zero-amount payments are pruned from
volume rankings. The 1h cache and fail-open behavior are unchanged.

Implementation: `bin/xrpl_forensics.py`. Tests:
`tests/test_forensics.py` (29 tests) + `tests/test_forensics_p2.py`
(42 tests), fixture-driven, no network.
