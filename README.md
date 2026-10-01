# xrpl-muse-skill v0.14.1

Trade the XRP Ledger from the terminal — any token pair — with a hard safety
boundary between **proposing** a trade and **signing** it.

Built for AI agents (Muse, Grok, OpenClaw-style bots — anything with a
terminal).

## The idea

Most trading tools ask the agent to "ask the human first" and hope it does.
This skill splits the job in two:

- **`xrpl-trade`** builds the transaction, autofills it against the live
  network, shows you *everything* (account, network, assets + issuers,
  amounts, limit price, max spend, fee, expiry), seals it in a **hash-bound
  proposal envelope**, and stops. It never sees your seed. It cannot submit.
- **`xrpl-sign`** is the only program that touches the seed. It re-verifies
  the envelope, enforces the policy (spend caps, allowlisted pairs and
  destinations, fee cap), and signs **only** with explicit human approval
  of that exact proposal hash.

```bash
xrpl-trade buy --pair XRP/RLUSD --amount 10 --price 1.50
# → full proposal + hash. Nothing submitted.

xrpl-sign --profile main --approve <hash>
# → envelope verify → policy checks → sign → validated result
```

## Safety first: read-only by default

Fresh installs start **read-only**: every market read, balance check, token
safety screen, and proposal build works keyless — signing is refused until
you deliberately leave read-only mode:

```bash
xrpl-trade live       # prints what changes, then you TYPE "go live"
xrpl-trade read-only  # locks back down, no confirmation needed
```

There is no flag or environment variable that skips the typed ceremony —
a prompt injection can't quietly re-enable signing. `xrpl-sign --approve`
checks the flag independently and refuses (audit-logged) while read-only.

## Install

```bash
git clone https://github.com/terramike/xrpl-muse-skill
cd xrpl-muse-skill
pip install -r requirements-locked.txt
export PATH="$PWD/bin:$PATH"

xrpl-trade setup            # address + network (never the seed)
```

Try it with zero keys — all of these are read-only:

```bash
xrpl-trade validators       # signed validator-list health
xrpl-trade amendments        # live amendment votes + majority countdown
xrpl-trade stablecoin RLUSD  # supply by chain + price (via DefiLlama)
xrpl-trade oracle XRP USD    # on-ledger XLS-47 price feeds (Band + DIA)
```

## What's new in v0.14.1

**Security release** — a third-party audit of v0.14.0 raised seven findings;
all seven are fixed, with focused regression tests
(`tests/test_recovery.py`, `test_sanitize_display.py`,
`test_policy_strict.py`, `test_hash_approval.py`,
`test_cmd_sign_cleanup.py`):

- **Spend-state recovery** — a corrupt spend-state file fails closed as
  before, and `xrpl-sign recover-state` now rebuilds accounting from the
  audit log (latest outcome per transaction wins; failed transactions keep
  only their consumed fee, matching the live path). When nothing
  trustworthy can be rebuilt, signing stays **blocked** until the operator
  reconciles manually and attests — the attestation is audit-logged.
- **Approval-display sanitization** — every untrusted field on the ceremony
  screen is escaped to visible sequences (ANSI/OSC, control chars, bidi
  overrides can neither act on the terminal nor hide invisibly).
- **Strict policy validation** — `load_policy()` rejects unknown keys,
  wrong types (the string `"false"` is truthy), non-finite limits, bad
  addresses/tags, and invalid ranges before the policy is used;
  `spend_limits` is required.
- **Exact full proposal hashes** — `--approve` requires the complete
  64-hex hash matching the verified envelope; prefixes are
  inspection-only and can never select a signing target.
- **Forensic ledger ranges** — account-history scans use real pinned
  ledger ranges instead of bare `ledger_index: "validated"`.
- **Pinned NFT verification** — NFT reads pin to one validated ledger and
  the report shows **seller** (current owner) vs **issuer** (minter)
  separately, with a resale warning when they differ.
- **Delivered-value flows only** — forensic value flows count only
  `tesSUCCESS` transactions' `delivered_amount`, never requested amounts.
- **nft-trail holder fix** — a both-offers direct sale no longer
  misattributes the holder; the reported holder is verified against the
  validated ledger (unverified trails say so instead of naming the wrong
  account).

Also bundled: the **Farm Helper** (`xrpl-trade farm` — read-only Farmers
Union add-in: explainer, links, qualification check, treasury, dustings),
the **nft-new crash fix** (unreadable sell-offer amounts no longer crash the
scan) with a trimmed default window (7d→3d) and `--limit`, and
trusted-links registry updates.

## What's new in v0.12.0

- **`validators` / `amendments`** — watch the network upgrade itself:
  signed validator-list health and the live amendment vote count.
- **`stablecoin [SYMBOL]`** — stablecoin supply broken down by chain plus
  price, via DefiLlama (labeled aggregator-not-authority).
- **`oracle [BASE] [QUOTE]`** — prices straight from the ledger via XLS-47
  oracle objects (Band Protocol + DIA publisher feeds), with per-publisher
  prices, update ages, staleness warnings, and median/mean/trimmed-mean
  aggregates. Publisher-attested, never presented as ledger truth.
- **Onboarding wizard (spec)** — `references/onboarding-wizard.md`: a chat
  walkthrough that takes a new user from zero to their first on-chain read
  with no keys, then layers optionals (NFT minting, watch-only wallets) on
  as yes/no questions.
- **Hardening** — the `live` command's typed ceremony can no longer be
  skipped via CLI; amendment parsing accepts every known key spelling.

## Command map

**Network & market reads** (keyless): `balance`, `quote`, `plan-trade`,
`inspect-token`, `token-safety` (xrpl.to scam check + risk score),
`validators`, `amendments`, `stablecoin`, `oracle`, `reconcile`

**Trading proposals** (propose → approve → sign): `buy`, `sell`,
`trustline`, `cancel`, `send` — amounts in BASE units, `--price` in QUOTE
per BASE, pairs mapped to vetted issuer addresses (tickers mean nothing
on XRPL; the issuer is the identity)

**NFTs**: `nft-stage`, `nft-pin-and-propose` (your own Pinata key),
`nft-list` (XRP sell offers only), `nft-inventory`, `nft-buy` (ledger-
verified sell offers), `nft-bid`, `nft-send` (0-XRP gift transfers),
`collection`, `template`

**Watchlists & discovery** (keyless): `favorites`, `watch` (incoming NFT
offer reminders), `nft-new`, `incoming`, `xrpresso` (marketplace search),
`giveaway`

**Modes**: `setup`, `wallet`, `profile`, `live`, `read-only`.
Autonomous mode is local-only dry-run and is not shipped in this repo.

Every command documents itself: `xrpl-trade <command> --help`.

## For AI agents

Start with [`llms.txt`](llms.txt) — the curated entry point: what this is,
the files that matter, the safety invariants. [`AGENTS.md`](AGENTS.md) has
contributor guidance (tests, conventions, what never to touch).
[`SKILL.md`](SKILL.md) is the full operator manual (971 lines).

## Deployment profiles

Testnet-safe by default. Three profiles, pick one deliberately:

- **Muse vault signer** — the recommended mainnet path. The seed lives in
  the Muse vault and is injected into `xrpl-sign` only after genuine human
  approval of the exact proposal hash. Never exported, never pasted.
- **Xaman-human** — the human signs in Xaman; the agent only proposes.
- **Autonomous-experimental** — local-only, dry-run-only experiments.
  Excluded from public releases.

## What this does not do

The NFT safety checks verify on-ledger facts (issuer, seller, offer
terms). That layer does **not** protect market value, and says nothing
about who owns the underlying art — a token can be authentic
on-ledger and still be worthless or infringing.

## Security

See [SECURITY.md](SECURITY.md) — including the platform boundary:
`--approve` is an assertion, not evidence of human approval. Never request,
reveal, or record a seed.

## Tests

```bash
python3 -m unittest tests.test_readonly   # read-only ceremony (no network)
python3 -m unittest tests.test_eco        # ecosystem connectors (no network)
python3 -m unittest tests.test_v04        # 78 adversarial logic tests
```

## License

MIT — see [LICENSE](LICENSE).
