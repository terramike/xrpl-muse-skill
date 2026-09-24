# xrpl-muse-skill

Trade the XRP Ledger from the terminal — any token pair, with a hard safety
boundary between proposing a trade and signing it.

## Architecture: propose → approve → sign (v0.2)

Two programs. The agent only ever runs the first.

1. **`xrpl-trade` — the proposer.** Builds transactions, autofills them against
   the live network, prints the full ceremony (account, network, assets with
   issuers, amounts, limit price, max spend, fee, sequence, expiry), hashes the
   exact bytes-to-be-approved, and saves a proposal. It **never sees the seed**
   and **never submits**.
2. **`xrpl-sign` — the policy-gated signer.** The only program that touches the
   seed (from the `XRPL_SEED` env var — never written to disk by the proposer).
   It re-verifies the proposal hash, enforces `~/.xrpl/policy.json`, and signs
   **only** when a human passes `--approve` for that exact hash.

## The ceremony (every write)

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → prints the full proposal + hash, e.g. a2c72140d080ca0f…
# → NOTHING is submitted.

# A human reviews the exact hash, then:
xrpl-sign --hash a2c72140d080ca0f --approve
# → policy checks → sign → submit_and_wait → validated ledger result → audit log
```

Without `--approve`, `xrpl-sign` only checks policy and prints the summary —
it never signs.

## Policy (`xrpl-sign init-policy` creates `~/.xrpl/policy.json`)

- `network_lock` — default `testnet`. Mainnet proposals **hard-fail** until
  you explicitly opt in. This is the emergency brake.
- **Approved pairs only** — token (currency, issuer) identities are extracted
  from the transaction JSON itself, so passing a raw issuer can't bypass the
  allowlist. Tickers mean nothing on XRPL; issuers are the identity.
- `max_fee_drops`, `per_tx_max_xrp`, `daily_max_xrp` — spend caps.
- `max_deviation_bps` — offer limit price must be near the live book mid
  (fail-closed when the book is empty).
- `destination_allowlist` — payments only to listed addresses (empty = no
  payments). Destination tags and X-addresses supported.
- Offers require an `Expiration` (default 1h, `--expires-in` to change).
- Proposals expire after 24h; the seed's derived address must match the
  proposal account, or signing is refused.

Every signed transaction is appended to `~/.xrpl/audit.log`
(hash, result, network — never secrets).

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
xrpl-trade setup            # address + network only (no seed prompt)
export XRPL_SEED='s…'       # the signer reads this, nothing else does
xrpl-sign init-policy       # writes ~/.xrpl/policy.json (testnet-locked)
```

Fund a testnet wallet: `xrpl-trade faucet --network testnet`.

## Safety rules for the operator

- Start on testnet. Opt into mainnet in the policy file deliberately.
- Trade from a dedicated limited-funds wallet.
- Always review the proposal hash yourself before `--approve`.
- `tesSUCCESS` from submission is provisional until the validated ledger
  confirms it — `xrpl-sign` waits and reports the validated result.
- See `SECURITY.md` for the disclosure policy and the
  pre-`c3273e59` buy/sell inversion advisory.

## Layout

- `bin/xrpl-trade` — proposer (builds + previews, never signs)
- `bin/xrpl-sign` — policy-gated signer
- `bin/xrpl_common.py` — shared helpers (hashing, policy, allowlist)
- `tests/test_v02.py` — 21 logic tests, no network needed
