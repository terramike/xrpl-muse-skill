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

Currency encoding: the `/token/{currency}:{issuer}` route takes the
**plain** currency code (`RLUSD`), NOT hex — verified 2026-09-30 (hex
form returns 400). The `currency_to_hex` helper in `xrpl_eco.py` remains
for any future route that needs it.

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

## Tier 2 (building 2026-09-30)

### 5. xrpscan API — fallback cross-checks (NON-COMMERCIAL LICENSE)

- Base `https://api.xrpscan.com/api/v1`, keyless, 10k/day free, AI-native
  docs (`docs.xrpscan.com`, llms.txt + .md pages).
- **LICENSE: CC BY-NC-SA 4.0 — non-commercial.** Every xrpscan line
  carries "(per api.xrpscan.com — CC BY-NC-SA 4.0, non-commercial)".
- Verified 2026-09-30: `GET /validators` → 200 array of
  `{master_key, chain, domain, ephemeral_key, ...}`;
  `GET /validator/registry` → literal `"Error"` (do NOT use);
  `GET /amendments` → 113 entries `{amendment_id, enabled, majority
  (ledger), name, supported, introduced, count, threshold, validations}`.
  No `/health` endpoint (404).
- Wiring: one-line cross-checks — `format_validators` gains "xrpscan
  sees N validators (agrees/disagrees)"; `format_amendments` gains
  "xrpscan: M in voting". Silent on failure. Never primary.

### 6. DefiLlama — stablecoin reads

- Bases `https://stablecoins.llama.fi`, `https://api.llama.fi`,
  `https://coins.llama.fi`. No key, soft ~500 req/min free.
- Verified 2026-09-30: `GET /stablecoins?includePrices=true` →
  `{peggedAssets[], chains[]}`; RLUSD = id 250, chains
  `[Ethereum, XRPL]`; fields `price`, `pegDeviation`,
  `chainCirculating{chain: {current: {peggedUSD}}}`.
  Chart `GET /stablecoincharts/all?stablecoin=250` → 749 points
  (response shape unverified — not parsed in v1).
- Wiring: `xrpl-trade stablecoin [SYMBOL]` (default RLUSD) prints total
  circulating, per-chain table, XRPL share %, price. Labels: "per
  DefiLlama (aggregator, not ledger authority) — XRPL-native supply
  should be verified on-ledger." Cross-chain supply ≠ XRPL-native
  supply — label precisely.
- Observed 2026-09-30 (do not hardcode as current): RLUSD ~$2.52B
  total, XRPL ~$1.124B, Ethereum ~$1.396B, price 1.00007.

### 7. DEX Screener — XRPL pair cross-check

- Verified 2026-09-30: `GET /latest/dex/search?q={symbol}` returns
  pairs including `chainId: "xrpl"`. `GET
  /token-pairs/v1/xrpl/{currency-hex}` returned `[]` — do NOT use that
  route for XRPL tokens.
- Pair shape: `{dexId, pairAddress: "{HEX}.{issuer}_{quote}",
  baseToken: {name, symbol, address}, priceUsd, liquidity: {usd},
  volume: {h24}, txns: {h24: {buys, sells}}, priceChange: {h24}, fdv,
  marketCap}`.
- Wiring: `token-safety` gains a DEX Screener block — top XRPL pair by
  liquidity: priceUsd, liquidity, vol24, buys/sells, 24h change. Match
  rule: `chainId == "xrpl"` AND (`baseToken.symbol == currency` OR
  issuer in `pairAddress`). Silent on failure. Label "per DEX Screener
  (aggregator, not ledger authority)".
- Rate: occasional lookups only.

## Tier 2 backlog (not built)

- Bithomp (key wall), Sologenic (API docs 404 as of 2026-09-30),
  Evernode (compute, not a read API), XLS-65/66 lending (not live),
  on-chain oracles (need verified publisher IDs).

## Wizard tie-in

Phase 0 power-reads try-list gains `xrpl-trade validators` and
`xrpl-trade amendments` ("watch the network upgrade itself — still
zero keys").
