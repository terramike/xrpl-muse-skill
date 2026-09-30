# Onboarding wizard: the install after the install

A chat walkthrough for new users. Buttons first, one question at a time,
custom-built per person: every integration is offered as a yes/no, skipped
items vanish without nagging, and the important step is marked as such.

The wizard is run by the assistant in chat — this file is the script.
State lives in `~/.xrpl/onboarding.json` (owner-only `0600`,
`schema_version: 1`) so the walkthrough is resumable across sessions.

## Triggers

- **First run:** when `~/.xrpl/onboarding.json` doesn't exist, offer the
  walkthrough after the profile questionnaire — never force it. Wording:
  "Want the guided setup? I'll walk you through each piece one question
  at a time, and skip anything you don't want."
- **Menu:** while any step is `pending`, the main menu shows
  "✨ Finish your setup (n/m)" which resumes where they left off.
- **Manual:** "run the setup wizard" / "onboarding" anytime.

## State schema

```json
{
  "schema_version": 1,
  "started_at": "2026-09-30T05:00:00Z",
  "steps": {
    "install": "done",
    "setup": "done",
    "init_policy": "done",
    "profile": "done",
    "first_read": "done",
    "onchain": "pending",
    "watch_offers": "pending",
    "nft_minting": "pending",
    "nft_buying": "pending",
    "xrplto_key": "pending",
    "fiat_onramp": "pending",
    "autopilot": "pending",
    "autonomous": "pending",
    "giveaway": "pending"
  }
}
```

Step states: `pending` → `done` | `skipped`. A skipped step never
re-prompts. Write the file temp-file + atomic rename, mode `0600`.

## Phase 0 — the free tier (statements, not questions)

Walk them through these in order; everything here needs zero keys:

1. **Install** — `pip install -r requirements.txt`
   (from https://github.com/terramike/xrpl-muse-skill)
2. **Wallet** — `xrpl-trade setup`: generate a fresh wallet or register
   an existing watch-only address.
3. **Policy** — `xrpl-sign init-policy`: writes `~/.xrpl/policy.json`,
   testnet-locked.
4. **Profile** — `xrpl-trade profile init`: the questionnaire
   (name, watch addresses, interests, alerts).
5. **First read** — pick one: `xrpl-trade movers`, `xrpl-trade balance`,
   or `xrpl-trade token-lookup --issuer r… --currency …`.

Then say it plainly: "Everything you just did needed zero keys. Reads,
risk scores, whale-watching, the watchlist — all free forever."

Power reads to try next: `tx-explain --hash …` (what happened on-ledger),
`whale-watch --issuer r… --currency …` (who's trading a token),
`token-safety` (scam screen + risk score), `top-collections` (ranked NFT
collections), `xrpresso listings --q …` (the XRPresso marketplace),
`validators` + `amendments` (watch the network upgrade itself — the
signed validator lists and the live amendment vote count, each with an
xrpscan cross-check), `stablecoin [SYMBOL]` (RLUSD supply by chain +
price via DefiLlama), `oracle [BASE] [QUOTE]` (prices straight from the
ledger — Band Protocol + DIA on-ledger feeds, no exchange API). And
the trusted-links registry (`references/trusted-links.md`) is the answer
for "is this link legit" — never a search result.

Mark each `done` as completed.

## Phase 1 — the important question

**Q1: "Want to do anything on-chain — trade, buy NFTs, send XRP?"**
Marked **IMPORTANT** — this is the only step that unlocks writes.
Buttons: `[Yes, set it up]` `[No, I'm good reading]`

- **Yes** → the live walkthrough, in order:
  1. `xrpl-trade live` — prints what changes, then they type `go live`.
     Say what it does: flips the `read_only` bit, nothing else.
  2. Explain signing profiles in one breath: a profile binds account +
     network + policy + spend budget so a proposal can't drift.
  3. `xrpl-sign init-profiles` — create the profile. The seed stays in
     their vault/password manager and is injected for one signing
     operation at a time — never pasted into chat, never stored by us.
  4. Show the exact policy diff for any mainnet/spend-limit change and
     get an explicit yes (standing rule — never silent policy edits).
  5. **Trade pairs:** `buy`/`sell` resolve through
     `~/.xrpl/approved.json` — empty by default. Copy
     `approved.example.json` there and add one vetted issuer. Say it
     plainly: tickers mean nothing on XRPL; issuers are the identity.
  6. **Destination allowlist:** `send`/payments only go to allowlisted
     (address, destination_tag) entries. Explain the 24h NEW DESTINATION
     ceremony warning — a payment to a destination added within the last
     24h gets flagged loud at signing time, and that's the point.
  7. **Testnet first:** fund via `xrpl-trade faucet --network testnet`,
     run one tiny trade through propose → approve → sign, verify on
     the validated ledger. Mainnet only when they say the words.
- **No** → `onchain: skipped`. "Staying read-only is a perfectly good
  install — everything keyless keeps working."

## Phase 2 — the optionals (one question each)

**Q2: "Watch for NFT offers on any wallet?"** — marked *read-only, no
keys*: some people install the skill just for this.
Buttons: `[Yes]` `[No]`

- **Yes** → the watch walkthrough:
  1. `xrpl-trade watch add <name> <r-address> --label "Studio Vault"` —
     addresses only. A seed can never pass the address checksum, so one
     can never be stored here.
  2. `xrpl-trade watch list` to review; `xrpl-trade watch check` sweeps
     for NEW open offers — it diffs against a local watermark and prints
     only what's new (the first run per wallet seeds the baseline
     silently).
  3. An hourly reminder pings chat only when new offers appear.
  4. Say it plainly: the watch never proposes, signs, or submits —
     acting on an offer is still the manual `nft-buy` ceremony.
  5. Bonus, same zero-key family: `xrpl-trade favorites add <name> r…`
     follows an artist wallet; `xrpl-trade nft-new` shows their new mints
     since your last check, with listing prices and xrp.cafe links.
- **No** → `watch_offers: skipped`.

**Q3: "Mint NFTs?"**
Buttons: `[Yes]` `[No]`

- **Yes** → Pinata walkthrough:
  1. Free Pinata account at pinata.cloud → copy a JWT.
  2. `PINATA_JWT` is injected for the single pin operation only
     (`PINATA_JWT="$(vault read …)" xrpl-trade nft-pin-and-propose …`)
     — never exported, never stored, never logged.
  3. `xrpl-trade nft-stage --file art.png --name …` then review, then
     pin-and-propose. Show the exact policy diff enabling the `nft`
     section and get an explicit yes.
  4. Point at `references/nft-pinata.md` for the full flow.
  5. Power tools, same ceremony: `collection create` + `template create`
     for reusable drops, `nft-list` to sell an owned NFT, `nft-send` to
     gift one (a 0-XRP transfer offer — the recipient must accept).
- **No** → `nft_minting: skipped`. Never mention minting again.

**Q4: "Buy NFTs — accept offers, place bids?"**
Buttons: `[Yes]` `[No]`

- **Yes** → the buy-side walkthrough:
  1. Show the exact policy diff setting `nft.allow_buy_offers` to `true`
     and get an explicit yes — accepting a sell offer spends XRP
     immediately, and a bid locks XRP until it is accepted, cancelled,
     or expires.
  2. `xrpl-trade nft-buy --offer-index <64-hex>` verifies the SELL offer
     from the ledger (seller, issuer, URI, taxon) before proposing;
     `xrpl-trade nft-bid --token-id <64-hex> --seller r… --price-xrp 5`
     places a bid (capped by `nft.max_bid_xrp`).
  3. Every buy/bid proposal carries the advisory xrpl.to safety section
     (issuer screen, collection floor, asking × floor multiple, approx
     last sale) — advisory only; the on-ledger verification stays the
     authority. Anyone can mint the same artwork: check the issuer is
     the artist you expect.
- **No** → `nft_buying: skipped`.

**Q5: "Want higher XRPL.to rate limits?"** — marked *nice-to-have*:
most endpoints work fine with no key.
Buttons: `[Yes]` `[No]`

- **Yes** → `xrpl_to.py keys create --yes`: a wallet-signed login-style
  message (nothing submitted on-chain), free tier, key stored `0600` at
  `~/.xrpl/xrplto.json`. Say plainly: creating it accepts xrpl.to's API
  terms. Mention `keys list` / `keys revoke` for rotation.
- **No** → `xrplto_key: skipped`.

**Q6: "Want to buy XRP with a card?"**
Buttons: `[Yes]` `[No]`

- **Yes** → hand off to the companion `changelly_buy` skill: it quotes
  via CoinGecko spot and generates the buy link. KYC + payment happen
  on Changelly; once the XRP lands, continue with the normal ceremony.
  Full flow: `references/fiat-onramp.md`.
- **No** → `fiat_onramp: skipped`.

**Q7 (advanced gate): "Show advanced setup — autopilot, trading bot, giveaways?"**
Buttons: `[Show advanced]` `[Skip]`

- **Skip** → mark `autopilot`, `autonomous`, `giveaway` all `skipped`.
  Normies never see these.
- **Show** → one question each, each with its honest framing:
  - **Bot signing with a human in the loop** (local-seed convenience):
    question: "Enable bot signing with a human in the loop?"
    Plain-language risk disclosure first — it bounds our *mistakes*,
    not our *compromise* (same-user install). Your wallet's seed stays
    on this machine (owner-only file) so signing doesn't need the vault
    each time — but every transaction still needs your explicit approval
    of the exact proposal hash. Dedicated limited-funds wallet only,
    never the main vault wallet. Enable: `xrpl-trade autopilot enable`,
    typing `ENABLE AUTOPILOT`. Seed at a hidden terminal prompt, never
    in chat.
  - **Autonomous bot**: separate wallet, dry-run only until P1,
    approval is per-plan not per-trade. `xrpl-trade autonomous setup`
    (they run it themselves), then the plan-hash approval ceremony.
    Full guide: `references/autonomous-setup.md`.
  - **Giveaways**: community leaders only — their own donation wallet,
    `giveaway setup` writes the narrow giveaway policy. Every gift stays
    human-approved, one at a time, no auto-send ever.

## Phase 3 — your install (the personalized checklist)

Print only what they said **yes** to, with exact commands, grouped:

```
YOUR INSTALL
Done:
  ✓ Read-only explorer (movers, lookups, watchlist)
  ✓ …
To finish:
  ○ Going live — run: xrpl-trade live
  ○ NFT minting — next: create a free Pinata account
Skipped (say the word anytime to revisit):
  – offer watch, nft buying, xrpl.to key, fiat on-ramp, autopilot, bot, giveaways
```

Save the state file. Remind them: "Say 'finish my setup' anytime to
resume — or never. Skipped stays skipped."

## Hard rules

- **Never ask for a seed, secret, or JWT in chat.** Credentials are
  entered at hidden terminal prompts or injected per-operation from
  their vault. If they paste anything seed-like: STOP, warn loudly,
  save nothing.
- **Buttons first.** Every question gets tappable options; terminal
  commands are second, printed as exact copy-pasteable commands.
- **No nagging.** Skipped is skipped. The menu badge counts pending,
  never skipped.
- **Exact diffs + explicit yes** for every policy/registry write
  (policy.json, approved.json, collections, templates) — the standing
  rule applies inside the wizard too.
- **Testnet before mainnet.** The on-chain walkthrough does a testnet
  trial trade before mainnet is even discussed.
- **Talk to the normies, but speak to the devs.** Plain-English outcome
  first, exact commands underneath.
