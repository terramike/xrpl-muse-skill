# Ecosystem connectors hub — Tier 1 spec

Keyless, read-only connectors for the XRPL skill. Every connector is
**advisory + fail-open**: a dead endpoint prints one line and the command
continues. Nothing here is authoritative over the validated ledger.

Global rules:
- Python stdlib only (`urllib`), `User-Agent: xrpl-muse-skill/1.0`.
- Timeouts 15–25s, max 3 attempts with 1s/2s/3s backoff.
- Polling budgets: validator lists daily (files change rarely — cache
  `sequence`); amendments daily; token metadata per-lookup; price data
  per-request. Never per-minute polling from chat commands.
- Label provenance on every line ("per XRPL Meta", "per validator list",
  "per rippled feature RPC"). Publisher-derived ratings are opinions,
  not ledger facts.

## 1. Validators — signed validator-list files

Endpoints (try in order, first success wins):
- `https://unl.xrplf.org` (XRPLF, sequence observed 2026070302)
- `https://vl.ripple.com` (Ripple; unreachable from some sandboxes —
  keep as fallback, do not hard-fail)

Format (XLS-0045): JSON `{public_key, manifest, version, signature,
blob}`; `blob` is base64 JSON `{sequence, expiration, validators:
[{validation_public_key, manifest}]}`. `expiration` is **ripple time**
(seconds since 2000-01-01) → unix = ripple + 946684800.

`xrpl-trade validators` prints:
- publisher (ripple / xrplf), sequence, validator count
- days until list expiration; WARN if < 30d
- membership-change note: compare count/sequence against the last cached
  read (`~/.xrpl/hidden_files/validators-seen.json`); first run seeds
  silently
- cross-check: UNL voter count currently 35 per livenet explorer

Note: the `validators` RPC method is admin-only on public servers — the
signed files are the canonical roster. Ephemeral keys resolvable via
public `manifest` RPC (not wired in v1).

## 2. Amendments — public rippled RPC

- `{"method":"feature"}` → `result.features` = `{amendmentID:
  {name, enabled, supported}}` (NOT a flat result — verified 2026-09-30:
  115 known, 94 enabled on mainnet).
- `{"method":"server_info"}` → `result.info.amendments.majorities[]`
  = `[{amendment, count, since-ledger}]` (absent/empty when nothing is
  in majority). Also gives `validated_ledger.seq` + `load_factor` for a
  future `network` read.

`xrpl-trade amendments` prints, grouped:
- **In voting** (`supported && !enabled`): name + id — these are the
  live protocol upgrades to watch
- **Enabled**: count + newest few by name
- **Majority countdown**: any entry in `majorities` with count/35 and
  since-ledger
- **Alert line** if any amendment is `enabled && !supported`
  (amendment-blocked risk on the connected server)

Public servers: `https://s1.ripple.com:51234` (verified), fallback
`https://xrplcluster.com`. The `vetoed` param is stripped (noPermission)
— never send it.

## 3. XRPL Meta — second risk/metadata source

Base `https://s1.xrplmeta.org`, no key observed (verify policy before
production volume).
- `GET /tokens` → `{count, tokens[], warnings}` (168k tokens observed)
- `GET /token/{currency}:{issuer}` → single record:
  `{currency, issuer, meta: {token: {name, desc, icon, trust_level,
  urls[]}, issuer: {name, kyc, trust_level, domain}}, metrics:
  {trustlines, holders, supply, marketcap, price, volume_24h, ...}}`

Wiring: `token-lookup` / `token-safety` gain an "XRPL Meta second
opinion" block — issuer name + domain match check (does the on-ledger
domain match the claimed issuer?), `kyc` flag, `trust_level` (1–5,
publisher-derived — label as opinion), holder/trustline counts.
Disagreement with the xrpl.to score is shown, never resolved by us.

Currency encoding: 3-char ASCII codes pass as-is; longer names must be
160-bit hex (uppercase, zero-padded) — reuse the skill's existing
currency-hex helper.

## 4. OnTheDEX — ledger-native price data

Base `https://api.onthedex.live/public/v1`, no key, fair use.
**STATUS 2026-09-30: entire API returning `ERROR_MAINTENANCE`.**
Response shapes are UNVERIFIED — the wiring below is defensive and every
parse is guarded; re-verify shapes on the first live run after
maintenance ends.

Planned endpoints (per their public spec):
- `GET /ticker` — live ticker map
- `GET /top100` (params TBD) — daily top tokens
- WebSocket per-ledger-close — NOT wired in v1 (chat commands are
  request/response)

Wiring: `movers` tries OnTheDEX first for 24h change/volume, falls back
to the existing source on any failure. `quote` may show an OnTheDEX
cross-check line. Illiquid pairs get a volume-staleness label.

## Tier 2 (spec'd later, not built)

- **xrpscan API** (`api.xrpscan.com/api/v1`): keyless, 10k/day, AI-native
  docs — but **CC BY-NC-SA 4.0 (non-commercial)**. Fallback only for
  account history / NFT / AMM reads.
- **DefiLlama** (`api.llama.fi`, `stablecoins.llama.fi`, `coins.llama.fi`):
  RLUSD supply/peg, XRP DeFi TVL. No key. Label cross-chain vs
  XRPL-native precisely.
- **DEX Screener**: XRPL website pages confirmed; public-API chain
  coverage UNVERIFIED — verify before wiring.

## Parked

Bithomp (key wall), Sologenic (API docs 404 as of 2026-09-30),
Evernode (compute, not a read API), XLS-65/66 lending (not live),
on-chain oracles (need verified publisher IDs).

## Wizard tie-in

Phase 0 power-reads try-list gains `xrpl-trade validators` and
`xrpl-trade amendments` ("watch the network upgrade itself — still
zero keys").
