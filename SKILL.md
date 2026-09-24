# xrpl-muse-skill

Trade the XRP Ledger from the terminal — any token pair, with a hard safety
boundary between proposing a trade and signing it.

## Architecture: propose → approve → sign (v0.3)

Two programs. The agent only ever runs the first.

1. **`xrpl-trade` — the proposer.** Builds transactions, autofills them against
   the live network, prints the full ceremony (account, network, assets with
   issuers, amounts, limit price, max spend, fee, sequence, expiry), and saves
   a **hash-bound proposal envelope**. It **never sees the seed** and **never
   submits**.
2. **`xrpl-sign` — the policy-gated signer.** The only program that touches the
   seed (from the `XRPL_SEED` env var — never from a config file). It verifies
   the proposal envelope, enforces `~/.xrpl/policy.json`, derives the summary
   from the transaction itself, and signs **only** when a human passes
   `--approve` for that exact hash.

### The envelope (what the hash binds)

A proposal is `format: xrpl-proposal/3` and the approval hash covers:

- `network`, `account`, `action`, `created_at`, `policy_version`
- the **canonical XRPL binary** of the complete transaction
  (`xrpl.core.binarycodec.encode`)

The signer re-verifies all of it and rejects anything tampered with —
including the envelope file itself. Old-format proposals are rejected;
rebuild them with the current `xrpl-trade`.

### What the signer enforces

- **Transaction-type allowlist**: `OfferCreate`, `OfferCancel`, `TrustSet`,
  `Payment` only. Anything else is rejected.
- **Strict per-type field schemas**: no `Paths`, `SendMax`, `DeliverMin`,
  `Memos`, partial-payment flags, or any other smuggled field.
- **Derived, never stored**: the summary, pair, side, amounts, and price are
  computed from the transaction inside the signer. There is no summary or
  metadata field to tamper with.
- **Exact-pair enforcement**: offers must match an approved pair from
  `~/.xrpl/approved.json` exactly — token/token combinations that aren't
  listed are denied.
- **Per-asset spend limits**: per-transaction and rolling-24h caps per asset
  (`spend_limits`), reserved atomically under a file lock so concurrent
  signers can't double-spend the daily budget. Assets with no configured
  limit are **blocked** (fail closed).
- **Offer safety**: `Expiration` required; limit price within
  `max_deviation_bps` of the live book mid (derived from the transaction,
  orientation-agnostic; fail-closed on an empty book).
- **Destination policy**: payments only to allowlisted `(address,
  destination_tag)` combinations; conflicting X-address/CLI tags are
  rejected; destinations with `RequireDestTag` set refuse untagged payments.
- **Network lock**: default `testnet`. Mainnet proposals **hard-fail** until
  you explicitly opt in.
- **Crash-safe submission**: sign → persist the signed hash and
  `LastLedgerSequence` to the audit log → submit → wait for the validated
  result. A crash between signing and submission still leaves a
  reconciliation trail.
- **Seed-address match**: the seed's derived address must equal the
  proposal's account, or signing is refused.

Every signed transaction is appended to `~/.xrpl/audit.log`
(hash, result, network — never secrets).

### The platform boundary (read this)

`--approve` is an *assertion*, not evidence of human approval. v0.3 is
mainnet-ready **only** when all of these hold:

- Muse requires real user confirmation for each signing use (a typed
  command is not consent by itself).
- The vault releases `XRPL_SEED` to the signer only on that genuine
  confirmation — the seed is never a hand-exported shell variable.
- The signer and the policy file sit behind a vault, separate OS identity,
  or privileged signing service the agent cannot rewrite.

Without those platform guarantees, v0.3 is a hardened testnet tool — not
generically mainnet-safe. The design states this honestly; see `SECURITY.md`.

## The ceremony (every write)

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → prints the full proposal + hash, e.g. a2c72140d080ca0f…
# → NOTHING is submitted.

# A human reviews the exact hash, then:
xrpl-sign --hash a2c72140d080ca0f --approve
# → envelope verify → policy checks → sign → persist → submit_and_wait
# → validated ledger result → audit log
```

Without `--approve`, `xrpl-sign` only checks policy and prints the
transaction-derived summary — it never signs.

## Policy (`xrpl-sign init-policy` creates `~/.xrpl/policy.json`, v3)

- `network_lock` — default `testnet`. The emergency brake.
- `spend_limits` — per-asset `{per_tx, per_day}` caps, e.g.
  `"XRP": {"per_tx": "25", "per_day": "100"}`,
  `"RLUSD.rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De": {"per_tx": "40", "per_day": "150"}`.
  Assets without an entry are blocked. (`xrpl-sign migrate-policy`
  upgrades a v2 file, keeping a `.v2.bak`.)
- `allowed_tx_types` — default the four safe types above.
- `destination_allowlist` — `[{address, destination_tag}]` pairs
  (empty = no payments).
- `max_fee_drops`, `max_deviation_bps`, `proposal_ttl_seconds`
  (proposals expire after 24h by default).
- Token (currency, issuer) identities are extracted from the transaction
  JSON itself, so passing a raw issuer can't bypass the allowlist. Tickers
  mean nothing on XRPL; issuers are the identity.

## Commands

Reading (no seed, no proposals):

- `balance [address]` — XRP + trustline balances
- `quote --pair ARMY/XRP` — order book top-of-book, any pair
- `offers [address]` — open offers
- `pairs` — approved pairs
- `inspect-token --currency FUZZY --issuer r…` — issuer risk: domain,
  transfer fee, global-freeze / no-freeze flags
- `plan-trade --pair ARMY/XRP --side buy --amount 1000 --price 0.005` —
  estimated fill, price impact vs mid, max spend (read-only)
- `reconcile --hash …` — validated outcome of a submitted transaction

Writing (always propose → human `--approve` → sign):

- `buy --pair P --amount A --price Px` — buy BASE with QUOTE at limit
- `sell --pair P --amount A --price Px` — sell BASE for QUOTE at limit
- `trustline --pair P --limit N` — trustline the pair's base token
- `cancel --seq N` — cancel an open offer
- `send --to r… --amount A --ccy XRP [--destination-tag N]`

`--amount` is always BASE units, `--price` is always QUOTE per BASE.
`--pair NAME` resolves through `~/.xrpl/approved.json` (copy
`approved.example.json` there and add vetted issuers). Explicit
`--base/--quote/--base-issuer/--quote-issuer` also works — but the signer
still enforces the allowlist on the resulting tokens.

## Setup

```bash
pip install -r requirements.txt
xrpl-trade setup            # address + network only (never the seed)
xrpl-sign init-policy       # writes ~/.xrpl/policy.json (testnet-locked)
```

The signer reads the seed **only** from `XRPL_SEED`, provided by your
secret manager or the Muse vault after human approval. Fund a testnet
wallet: `xrpl-trade faucet --network testnet`.

## Safety rules for the operator

- Start on testnet. Opt into mainnet in the policy file deliberately.
- Trade from a dedicated limited-funds wallet.
- Always review the proposal hash yourself before `--approve`.
- `tesSUCCESS` from submission is provisional until the validated ledger
  confirms it — `xrpl-sign` waits and reports the validated result.
- See `SECURITY.md` for the disclosure policy, the platform boundary, and
  the pre-`c3273e59` buy/sell inversion advisory.

## Layout

- `bin/xrpl-trade` — proposer (builds + previews, never signs)
- `bin/xrpl-sign` — policy-gated signer
- `bin/xrpl_common.py` — shared helpers (envelopes, policy, allowlist, limits)
- `tests/test_v03.py` — 40 adversarial logic tests, no network needed
- `tests/test_e2e_testnet.py` — 17 end-to-end checks on testnet
  (propose → approve → sign → persist → validated)
