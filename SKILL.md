# xrpl-muse-skill

Keyless research and safety for the XRP Ledger, for any agent with a
terminal. Trading is the second job. Proposing a transaction and signing
it stay separate.

## HOL Guard coverage

HOL Guard publishes [XRPL Muse Skill protection](https://hol.org/guard/extensions/command.xrpl-muse-skill),
a command-coverage profile for this skill. It classifies signing approval and
gate-transition commands for review, proposal commands for review, and
read-only queries as inert. The listing documents that external Guard
coverage; it does not replace this skill's own policy checks or the
operator's exact-hash approval.

## Read-only mode: the default (v0.11.0)

Fresh installs start **read-only**: everything keyless works, nothing can
sign. Balances, token lookups with XRPL.to risk scores, market movers, top
collections, tx-explain, whale-watch, incoming NFT offer scans, the watchlist,
Koi market reads, the trusted-links registry — all of it, no keys anywhere.
`xrpl-trade` can even *build* proposals (terms + hash, fully keyless) so you
can rehearse the whole flow and stop one step short of the chain.

Going live is a deliberate ceremony, not a flag:

- `xrpl-trade live` — prints what changes, then requires typing `go live`
- `xrpl-trade read-only` — locks back down, no confirmation needed

The `read_only` bit lives in `~/.xrpl/config.json` and can **only** be flipped
by those two commands. No CLI flag or environment variable overrides it, so a
prompt injection can't quietly re-enable signing. `xrpl-sign --approve`
checks the flag independently and refuses (audit-logged) while read-only.
Existing installs that predate the flag are grandfathered — an upgrade never
silently changes signing behavior.

## Architecture: propose → approve → sign (v0.7)

Two programs. The agent only ever runs the first.

1. **`xrpl-trade` — the proposer.** Builds transactions, autofills them against
   the live network, prints the full ceremony (account, network, assets with
   issuers, amounts, limit price, max spend, fee, sequence, expiry), and saves
   a **hash-bound proposal envelope**. The propose path does not read a seed
   and does not submit. Other commands in this program can store a seed, and
   `wallet backup` or autopilot's backup ceremony can display one once.
2. **`xrpl-sign` — the policy-gated signer.** The only program that signs a
   proposal. On mainnet it reads the seed from a **named signing profile**
   (`~/.xrpl/profiles.json`, owner-only `0600`) that binds account + network +
   credential reference + policy digest + spend-state selection; the seed
   itself lives in the operator's vault (password manager) and is injected
   for the single signing operation. `xrpl-sign` verifies the proposal
   envelope, enforces the profile's policy, derives the summary from the
   transaction itself, and signs **only** when a human passes
   `--profile <name> --approve` for that exact hash.

### Signing profiles (v0.7)

A profile names the complete signing context so a proposal can't drift
across accounts, networks, policies, or wallets:

```json
{
  "schema_version": 1,
  "profiles": {
    "main": {
      "account": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
      "network": "mainnet",
      "credential_env": "XRPL_SEED",
      "policy_path": "/home/user/.xrpl/policy.json",
      "policy_sha256": "2d3aa5d2b830a43c…",
      "spend_state": "default"
    }
  }
}
```

- `xrpl-trade` records `profile` + `policy_sha256` in every mainnet proposal.
- `xrpl-sign --profile <name>` rejects proposals bound to another profile,
  a changed policy (digest mismatch → rebuild the proposal), or a different
  account/network — *before* touching the credential.
- One profile = one spend-state file, so the main wallet and the giveaway
  wallet can never share a budget.
- Manage with `xrpl-sign init-profiles` / `xrpl-sign sync-profile <name>`.

### Vault-only mainnet (v0.7)

- `wallet create --network mainnet` and `wallet backup --network mainnet`
  are refused. `wallet create` on testnet stores a seed and prints only the
  address. `wallet backup` displays that stored seed once when the selected
  network is not mainnet, and requires the typed backup phrase. A chat
  transcript of that backup then contains the seed.
- `setup` can store a seed for the network the operator types, including
  mainnet, and does not display it. A seed in `~/.xrpl/config.json` or
  `~/.xrpl/giveaway.json` blocks mainnet signing until `wallet forget-seed`
  removes it. Faucet files do not block. Adopting a config seed into
  autopilot does not clear that block.
- The faucet stores a testnet seed and does not print it. Giveaway setup
  writes the giveaway policy, stores a donation-wallet seed only when the
  operator pastes one, does not print it, and otherwise leaves that seed
  for vault injection.

### Autopilot — at your own risk (opt-in local mainnet signing)

Two signing modes, clearly labeled:

- **Vault (default).** The key stays outside the agent's environment; the
  vault injects it for one signing operation after genuine human approval.
  External wallets (Xaman via its payload API, or a WalletConnect wallet
  like Joey/Bifrost once the bridge lands) keep the key in a separate
  wallet entirely — the user approves there.
- **Autopilot (explicit opt-in).** `xrpl-trade autopilot enable` stores the
  wallet's seed in `~/.xrpl/autopilot.json` (owner-only 0600) after the
  operator types `ENABLE AUTOPILOT` under a plain-language risk disclosure.
  Seed sourcing, in order: (1) if `~/.xrpl/config.json` holds a seed for the
  account (e.g. from `xrpl-trade wallet create`), it is adopted directly —
  no pasting; (2) otherwise the operator may generate a fresh dedicated
  autopilot wallet on the spot, with a one-time backup ceremony (the seed
  is displayed exactly once; the operator types `I HAVE WRITTEN IT DOWN`
  to confirm); (3) otherwise paste at a hidden prompt. The signer then
  uses the local seed — but **only** for the exact account it was enabled
  for, and **everything else is unchanged**: the proposal envelope, the
  policy checks (spend caps, pairs, tx types, fee caps, expiries), the
  audit log, and the human Submit/Cancel on the proposal hash in chat.

What Autopilot does and does not protect against — say this plainly:

- It bounds the agent's *mistakes*: policy + proposal + human confirmation
  still gate every transaction.
- It does **not** defend against the agent's *compromise*: this is a
  same-user install, so any process running as this user can read the seed
  file. A prompt-injected agent or a rooted machine exposes the seed.
- So: use a dedicated limited-funds wallet for Autopilot (not the vault),
  keep spend caps tight, and run `xrpl-trade autopilot disable` (which
  deletes the seed from disk after you type the address to confirm) the
  moment you stop needing it.

Never paste a seed into chat to enable this. A pasted seed stays on a
hidden terminal prompt. Generating a wallet, or backing up an adopted seed,
prints the seed once and requires `I HAVE WRITTEN IT DOWN`, including on
mainnet. The audit log records `seed_source=autopilot` and never the seed.

### Autonomous mode

Autonomous mode is not included in this build (local-only, dry-run).
`xrpl-trade autonomous` exits with that sentence. This tree has no setup
guide for it.


### The envelope (what the hash binds)

A proposal is `format: xrpl-proposal/4` and the approval hash covers:

- `profile`, `policy_sha256`, `network`, `account`, `action`, `created_at`,
  `policy_version`
- the **canonical XRPL binary** of the complete transaction
  (`xrpl.core.binarycodec.encode`)

The signer re-verifies all of it and rejects anything tampered with —
including the envelope file itself. A proposal whose policy digest no
longer matches the profile's policy is rejected (rebuild it after reviewing
the policy change). Old-format proposals are rejected; rebuild them with the
current `xrpl-trade`.

### What the signer enforces

- **Envelope invariants**: envelope account == transaction `Account`,
  action matches transaction type, buy/sell orientation matches the actual
  `TakerPays`/`TakerGets` fields; `Account`, `Fee`, `Sequence`,
  `LastLedgerSequence` required; no `TxnSignature`/`SigningPubKey` in
  unsigned proposals; no far-future `created_at`.
- **Transaction-type allowlist**: `OfferCreate`, `OfferCancel`, `TrustSet`,
  `Payment` only. Anything else is rejected.
- **Strict per-type field schemas**: no `Paths`, `SendMax`, `DeliverMin`,
  `Memos`, partial-payment flags, or any other smuggled field.
- **Numeric sanity**: NaN/Infinity amounts, fees, and sequences are rejected
  before they can reach a limit comparison.
- **Derived, never stored**: the summary, pair, side, amounts, and price are
  computed from the transaction inside the signer. There is no summary or
  metadata field to tamper with.
- **Exact-pair enforcement**: offers must match an approved pair from
  `~/.xrpl/approved.json` exactly — token/token combinations that aren't
  listed are denied.
- **Per-asset spend limits**: per-transaction and true rolling-24h caps per
  asset (`spend_limits`), reserved atomically under a file lock so concurrent
  signers can't double-spend the daily budget. Assets with no configured
  limit are **blocked** (fail closed).
- **Ambiguity-safe reservations**: a reserved spend stays reserved (never
  double-spent, never released early) until the validated ledger result
  proves what happened. Unresolved liabilities are retained regardless of
  age — they never expire out of the rolling window. Proven non-inclusion
  (the node's complete history covers the full
  `[submit_ledger, LastLedgerSequence]` range) releases it; validated
  success confirms it; a validated *failure* releases the trade amount but
  retains the consumed fee as a confirmed XRP spend.
- **Strict accounting state**: spend state with negative, non-finite, or
  inconsistent entries fails closed (the signer refuses rather than silently
  resetting limits); `xrpl-sign recover-state` reconciles a damaged file
  without forgiving obligations.
- **Offer safety**: `Expiration` required and bounded by
  `max_offer_lifetime_seconds`; limit price within `max_deviation_bps` of a
  depth-weighted book reference (up to 10 levels per side) that requires
  both bid and ask sides, minimum depth (`min_book_depth`), and a maximum
  spread (`max_spread_bps`) — fail-closed on thin, one-sided, or wide
  books.
- **Destination policy**: payments only to allowlisted `(address,
  destination_tag)` combinations; conflicting X-address/CLI tags are
  rejected; destinations with `RequireDestTag` set refuse untagged payments
  (fail-closed on lookup errors).
- **Network lock**: default `testnet`. Mainnet proposals **hard-fail** until
  you explicitly opt in.
- **Protected files**: the signer refuses to run if the policy, allowlist,
  state, lock, audit, or autopilot files are not owner-only `0600`. This catches
  accidental exposure — it does not replace the privileged boundary below.
- **Crash-safe submission**: sign → bind the reservation to the signed hash
  and `LastLedgerSequence` → persist to the audit log → submit → wait for the
  validated result. A crash anywhere still leaves a reconciliation trail.
- **Seed-address match**: the seed's derived address must equal the
  transaction account's enabled master key or its validated on-ledger
  `RegularKey`, or signing is refused. Disabled master keys are rejected.
- **Offer liquidity on funded amounts**: the book reference uses
  `taker_gets_funded`/`taker_pays_funded` (not nominal offer sizes), with
  both sides read at one explicit validated ledger.

Every signed transaction is appended to `~/.xrpl/audit.log`
(hash, result, network — never secrets).

### The platform boundary (read this)

`--approve` is an *assertion*, not evidence of human approval. v0.5 is
mainnet-ready **only** when all of these hold:

- Muse requires real user confirmation for each signing use (a typed
  command is not consent by itself).
- The vault releases `XRPL_SEED` to the signer only on that genuine
  confirmation — the seed is never a hand-exported shell variable.
- The signer and the policy file sit behind a vault, separate OS identity,
  or privileged signing service the agent cannot rewrite.

A same-user local agent does **not** satisfy this boundary, even with
`0600` files: a same-UID process can read the signer's environment and
rewrite its policy and state. Same-user installs are testnet-only.

Without those platform guarantees, v0.5 is a hardened testnet tool — not
generically mainnet-safe. Three deployment profiles are documented in
`README.md` (Muse vault / Xaman-human / autonomous-experimental); the
design states all of this honestly in `SECURITY.md`.

## The ceremony (every write)

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → prints the full proposal + hash, e.g. a2c72140d080ca0f…
# → NOTHING is submitted.

# A human reviews the exact hash, then:
xrpl-sign --profile main --hash a2c72140d080ca0f --approve
# → profile + envelope verify → policy checks → sign → persist →
#   submit_and_wait → validated ledger result → audit log
```

Without `--approve`, `xrpl-sign` only checks policy and prints the
transaction-derived summary — it never signs. On mainnet `--profile`
is mandatory and must match the profile the proposal was built for.

## Policy (`xrpl-sign init-policy` creates `~/.xrpl/policy.json`, v4)

- `network_lock` — default `testnet`. The emergency brake.
- `spend_limits` — per-asset `{per_tx, per_day}` caps, e.g.
  `"XRP": {"per_tx": "25", "per_day": "100"}`,
  `"RLUSD.rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De": {"per_tx": "40", "per_day": "150"}`.
  Assets without an entry are blocked. (`xrpl-sign migrate-policy`
  upgrades an older file, keeping a `.v3.bak`.)
- `allowed_tx_types` — the safe trading types plus, for v0.5,
  `NFTokenMint`, `NFTokenCreateOffer`, and `NFTokenAcceptOffer` when the
  operator enables them.
- `destination_allowlist` — `[{address, destination_tag, added_at}]` pairs
  (empty = no payments). Entries added through the tooling are timestamped
  and every add/remove is written to the audit log. The signing ceremony
  flags Payments to destinations added within the last 24h with a loud
  **NEW DESTINATION** warning — a prompt-injected allowlist add followed by
  a quick-tapped proposal is the attack this catches.
- `max_fee_drops`, `max_deviation_bps`, `proposal_ttl_seconds`
  (proposals expire after 24h by default).
- `max_spread_bps` (default 1000), `min_book_depth` (default "5", in QUOTE
  units of funded depth per side), `max_offer_lifetime_seconds`
  (default 86400) — the book-quality and offer-lifetime bounds.
- `nft` — `{max_transfer_fee, max_mints_per_day, allowed_mint_flags,
  max_uri_bytes, allow_buy_offers, max_bid_xrp}` (defaults 10000 / 10 /
  [1, 8] / 256 / false / "10"). The **buy side** (`nft-buy` and `nft-bid`)
  is opt-in: set `nft.allow_buy_offers` to `true` deliberately, because
  accepting a sell offer spends XRP immediately and a bid locks XRP until
  it is accepted, cancelled, or expires. `max_bid_xrp` caps a single bid.
- Token (currency, issuer) identities are extracted from the transaction
  JSON itself, so passing a raw issuer can't bypass the allowlist. Tickers
  mean nothing on XRPL; issuers are the identity.
- `xrpl-sign migrate-policy` upgrades a v2 or v3 file (keeping a
  `.v3.bak`), filling in the new v0.4 fields with their defaults. v4 adds
  the `nft` section but does **not** widen `allowed_tx_types` — existing
  operators must deliberately add `NFTokenMint` / `NFTokenCreateOffer` /
  `NFTokenAcceptOffer` to enable NFTs (and set `nft.allow_buy_offers=true`
  for the buy side).

## NFTs

Mint, list, inventory, buy, and bid flows are in `references/nft-commands.md`.
The two-step mint is `nft-stage`, then `nft-pin-and-propose`.
Pinata credentials stay inside the approved action.

## Following artists

Favorites, what's new, and NFT Radar are in `references/favorites-and-radar.md`.

## Onboarding: the user profile

On first run — when `~/.xrpl/profile.json` doesn't exist — offer the
questionnaire before anything else. Ask conversationally, one or two
questions at a time, then save the answers with the `profile` commands.
`xrpl-trade profile init` also runs it in a terminal.

```bash
xrpl-trade profile init                 # interactive questionnaire
xrpl-trade profile show                 # review it anytime
xrpl-trade profile set display_name "Mike"
xrpl-trade profile set alerts.price_moves true
xrpl-trade profile set alerts.threshold_pct 3
xrpl-trade profile add-address r…       # WATCH-ONLY. Never a seed.
xrpl-trade profile add-membership xaodao
xrpl-trade profile add-interest trading
xrpl-trade profile remove-interest trading
xrpl-trade profile clear                # start over
```

What to ask: what to call them; watch-only XRPL addresses; DAO
memberships (open list — `xaodao`, whatever they hold); what they use
the skill for (`trading`, `nfts`, `dao-governance`, `discovery`, …);
whether they want to research Farmers Union ($FARM) — a yes tags the
`farmers-union` interest and points at `xrpl-trade farm about` (default
no, entirely local); whether they want price-move alerts and at what
threshold.

**The seed rule (non-negotiable):** NEVER ask for a seed, secret key,
or passphrase — ask for the watch-only classic address (starts with
`r`). If the user pastes anything seed-like, STOP: warn them loudly,
save nothing, and move on. The CLI enforces this too — `add-address`
refuses seed-shaped input with an explicit warning and never stores it.

- Stored in `~/.xrpl/profile.json`, owner-only `0600`, schema-versioned
  (`schema_version: 1`). Local only — it never leaves the machine.
- The profile drives personalization: `memberships` feeds reminders
  (e.g. `xaodao` → DAO proposal vote reminders), `alerts.*` feeds
  price-move alerts, `interests` shapes menus and suggestions.
- Keep the public skill generic: memberships and interests are open
  tag lists, never hardcoded to one DAO or one user.

## Onboarding wizard: the install after the install

After the profile questionnaire, offer the guided setup walkthrough —
one question at a time, buttons-first, custom per person. The full
script is `references/onboarding-wizard.md`; the shape:

1. **Phase 0 — the free tier** (statements, not questions): install,
   `xrpl-trade setup`, `xrpl-sign init-policy`, `profile init`, one
   first read. Zero keys; say so out loud.
2. **Phase 1 — the important question:** "Want to do anything on-chain?"
   Yes → the `xrpl-trade live` typed ceremony, signing profiles,
   exact-diff policy review, trade-pair setup (`approved.json`),
   destination allowlist, testnet trial trade before mainnet is ever
   discussed. No → read-only is a complete install.
3. **Phase 2 — the optionals, one yes/no each:** offer watching
   (read-only, no keys), NFT minting (Pinata JWT walkthrough, plus
   collections/templates/list/send power tools), NFT buying (offer
   acceptance + bidding, `allow_buy_offers` policy), xrpl.to key
   (nice-to-have — most endpoints work keyless), fiat on-ramp
   (changelly_buy handoff), then an advanced gate hiding
   human-in-the-loop bot signing, the autonomous bot, and giveaway
   setup.
4. **Phase 3 — your install:** a personalized checklist with only what
   they said yes to and the exact commands; saved resumable state.

State lives in `~/.xrpl/onboarding.json` (`0600`, `schema_version: 1`,
step states `pending`/`done`/`skipped`). While any step is pending, the
main menu shows "✨ Finish your setup (n/m)". Skipped steps never
re-prompt — skipped is skipped, no nagging. The seed rule is absolute
inside the wizard: credentials at hidden prompts or per-operation
injection only, never in chat.

## Friday community giveaway

The giveaway flow is in `references/giveaway.md`.
`giveaway setup` writes the narrow policy and stores a donation-wallet seed only when the operator pastes one. It does not print that seed.

## XRPresso discovery: marketplace search (read-only)

XRPresso (xrpresso.io) is a non-custodial P2P marketplace on XRPL —
goods, gigs, music, NFTs. Its free Discovery API v1 needs no key and
no signup; the skill searches it straight from chat.

```bash
xrpl-trade xrpresso listings --q "neon" --sort newest
xrpl-trade xrpresso listings --category art --currency XRP --limit 10
xrpl-trade xrpresso nfts --q "drift" --sort price_asc
xrpl-trade xrpresso auctions
xrpl-trade xrpresso listing <id>     # full detail for one listing
xrpl-trade xrpresso stats            # marketplace aggregates
xrpl-trade xrpresso categories       # category keys for --category
```

- Human-in-the-loop by design: the agent finds, the human buys.
  Every result prints its XRPresso deep link (with `?ref=api_v1`
  attribution preserved) — open it to buy/bid in XRPresso's UI and
  sign in your own wallet. The v1 API has no buy/mint/offer/escrow
  endpoints and the skill never recreates them.
- Deep links are validated before display: only `https` URLs on
  `xrpresso.io` (or a subdomain) are shown; anything else is withheld,
  never printed.
- Polite by construction: ≥3s between calls (well under the platform's
  30/min IP limit), 15s timeout, 1MB response cap. No policy changes,
  no approvals, no `~/.xrpl` writes — this feature cannot spend.
- Honest limits: the catalog is small and early-stage; XRPresso is a
  listings marketplace, not a trading venue — there are no swap
  endpoints. For token swaps the skill's own DEX flow is the tool.

## Community directory (reference)

`references/xrpl-community-directory.md` is a curator-maintained directory
of XRPL community members, projects, tools, wallets, media, XRP Café
creator profiles, and public account addresses — with per-entry
verification labels (curator-identified vs unverified association).

Consult it when the user asks "who is X", wants an X handle or project
website, or needs an XRP Café profile link. It also records the issuers
of the curator's approved trading-pair tokens.

Hard rules, from the file's own header — never weakened:

- Every entry is reference data, not an endorsement, allowlist, identity
  proof, or payment instruction.
- Never initiate, prepare, recommend, or auto-fill a transaction from an
  address in this directory alone. If the user wants to pay, tip, or
  gift someone named here, they paste or confirm the address themselves;
  the agent never fills it from the file.
- Before displaying an address as belonging to a person or project,
  confirm it from an official source or describe the association as
  unverified.

## Farmers Union ($FARM) helper

`xrpl-trade farm` is the skill's Farmers Union add-in — built so farmers can
research the system, check their standing, and draft posts from real numbers.
**Read-only, keyless, public** (in `--help`, unlike hidden commands). It never
builds proposals, never signs, never touches seeds.

- `references/farm.md` is the single source of truth for the explainer and
  the link bundle (`farm about`, `farm links` print it — no network).
- The trust anchor is the $FARM issuer `rPrAEfVATUNDTJm9CUa8tYeD7oJrVdEGhU`
  — tickers mean nothing; the address is the identity.
- Qualification threshold: **123,000 FARM** or LP equivalent (the Union's
  published figure — `farm qualify` re-checks it on-ledger, never trusts it).
- `farm dustings` mirrors the Union's cropdusting table with a lazy cache;
  every render prints "data as of". Their disclaimer stands: inclusion on the
  list is not an endorsement — the skill never recommends a dusting trustline
  without the `token-safety` screen, and trustline creation itself stays in
  the propose → approve → sign ceremony (a later phase, not this one).
- Attribute everything: site figures are labeled "site figure, <date>";
  aggregator numbers carry their source; live ledger reads say so.

## LuckyHash (reference)

`references/luckyhash.md` covers LuckyHash (luckyhash.win), the provably-fair
XRPL gaming platform in the trusted-links registry (Gaming): game list with
verified deep links, bet lifecycle, accepted tokens, and the gift system.
When the user says "luckyhash menu", reply with the labeled link menu from
that file.

Hard boundary, from the file's own header — never weakened: the assistant
cannot buy or play on the user's behalf. There is no public API; every bet
and every gift purchase is a payment the user signs in their own wallet
(Xaman/Joey). Never claim to have placed a bet, and never construct a
payment pretending it is a LuckyHash bet.

## Menu presentation

Say `menu` for the button menu. The rules are in `references/menu-presentation.md`.

## Commands

The command catalog is in `references/commands.md`.
The TrustLink checker is not part of this skill.

## Setup

```bash
pip install -r requirements-locked.txt
xrpl-trade setup            # onboarding: generate a wallet, or register an address
xrpl-sign init-policy       # writes ~/.xrpl/policy.json (testnet-locked)
```

`xrpl-sign` reads a seed from the signing profile's env var (often
`XRPL_SEED`), from a testnet file credential, from `~/.xrpl/autopilot.json`
after autopilot enable, or from `~/.xrpl/giveaway.json` for a giveaway seed
on testnet. It signs only with `--approve` of the exact hash and refuses
while read-only. Do not paste a seed into chat. Fund a testnet wallet:
`xrpl-trade faucet --network testnet`.

## Wallets (v0.7): vault-only mainnet, local testnet

`wallet create` and `wallet backup` refuse when the selected network is mainnet. `setup` can store a seed for the network the operator types, including mainnet, without displaying it, and that file then blocks mainnet signing until `wallet forget-seed`:

- `wallet create --network mainnet` → refused (use the vault).
- `wallet backup --network mainnet` → refused (the vault is the backup).
- The signer refuses mainnet while legacy seeds remain on disk
  (`wallet forget-seed` removes one only after you type the address to
  confirm the vault backup exists).

**Exception — Autopilot (explicit opt-in only):** `xrpl-trade autopilot
enable` deliberately stores one wallet's seed on disk (owner-only 0600)
after the operator types `ENABLE AUTOPILOT` under a plain-language risk
disclosure. See "Autopilot — at your own risk" above. This is the
documented weaker deployment mode for a dedicated limited-funds wallet —
never the main vault wallet.

Testnet keeps the convenient local flow: `wallet create` generates a fresh
ed25519 wallet (seed to `~/.xrpl/config.json`, 0600, atomic) and prints
only the address; the faucet writes its seed to a dedicated file, never to
the terminal. `setup` offers generation (default: no — silence is never
consent); `create` refuses to overwrite without `--force`. The audit log
records `wallet_create` / `wallet_backup` / `wallet_forget_seed` events
without seed material.
If a seed ever touches chat or a log, treat the wallet as burned and
generate a new one — exposure can't be undone.

## Funding a wallet (fiat on-ramp, optional)

If the wallet has no XRP yet — or the user wants to buy with a credit/debit
card — fund it first via the companion `changelly_buy` skill. See
`references/fiat-onramp.md` for the exact commands.

The on-ramp sits **outside** the propose → approve → sign boundary: it only
generates a buy link, does not read a wallet seed, and never submits ledger
transactions. The buyer completes KYC and payment on Changelly; once the XRP
lands, continue with the normal ceremony above.

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
- `tests/test_v04.py` — 78 adversarial logic tests, no network needed
- `tests/test_nft.py` — 104 NFT adversarial tests, no network needed
- `tests/test_favorites.py` — 67 favorites + nft-new unit tests, no network
- `tests/test_e2e_testnet.py` — 52 end-to-end checks on testnet
  (propose → approve → sign → persist → validated), fully isolated in a
  temporary HOME — never touches the operator's real `~/.xrpl`
