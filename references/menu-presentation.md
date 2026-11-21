## Menu presentation (standard)

When presenting this skill in chat, **always use clickable button menus
by default** — not raw command lists. The user navigates by tapping,
not by typing commands.

**Main menu buttons:**
- XRPL Actions
- NFT
- XRP News
- 🤝 Community

**XRPL Actions submenu** (tappable; Markets also as `xrpl_to.py` CLI), in ABC order:
- 💰 Balances (`balance [address]` — XRP + trustline balances)
- 🔎 Forensics (read-only, keyless, budgeted; `references/forensic-mode.md`):
  - 🧬 Trace (`xrpl-trade trace r… [--depth N]` — funding-origin chain)
  - 🔗 Links (`xrpl-trade links r… r… [--window N]` — shared counterparties,
    issuers, tokens, control overlap)
  - 🌊 Flow (`xrpl-trade flow r… [--window N]` — top counterparties by volume)
  - 🖼️ NFT Trail (`xrpl-trade nft-trail <token-id>` — mint → offers → held by)
  - 🪙 Token Trail (`xrpl-trade token-trail --issuer r… --currency CODE` —
    issuer profile, holders, issuer-involved movers)
  - Output discipline: `LINK:` = on-ledger fact, `NOTE:` = caveat; never
    claims common ownership without control overlap. Known addresses render
    `LABEL: r… — "Name" (verified)`; service-wallet links get the loud
    false-positive caveat.
- 📈 Markets → 📊 Market Movers (`movers --view gainers|losers|volume|trending`),
  🔍 Token Lookup (`token-lookup --issuer … --currency …`), 🧾 Explain a
  Transaction (`tx-explain --hash …`), 🐋 Whale Watch
  (`whale-watch --issuer r… --currency … [--limit 10]`)
- 👛 Wallets (local-only, explicit opt-in):
  - `wallet create` — generate a fresh wallet; seed stored 0600, never displayed
  - `wallet backup` — ONE-TIME seed display for write-down
  - `setup` — onboarding: new wallet or address+network

**🤝 Community submenu** (in ABC order; each opens its own focused submenu):
- 🎨 Artists — following artists (`favorites` add/list/rename/remove,
  `nft-new` — new mints from followed artists; entirely read-only).
  📡 NFT Radar (`xrpl-trade nft-radar [--days N] [--limit N] [--json]` —
  new mints across all 307 curated artists, signal-only; read-only).
  Curated reference: `references/artist-directory.json` (307 artists —
  Mike's xrp.cafe follow list, 2026-10-05) and
  `references/xrpcafe-collections.json` (39 xrp.cafe collections
  with slugs, URLs, and cover images)
- ☕ Coffee & Crypto (see **Coffee & Crypto submenu** below)
- 🎙️ Dip a Toe — Melissa's XRP community YouTube show (@dipatoe;
  X @worldbefree888)
- 🌾 Farmers Union (`xrpl-trade farm` — $FARM community helper: about, links,
  qualification check, treasury, cropdusting board; read-only)
- 🐻 Fuzzy (see **🐻 Fuzzy submenu** below)
- 🔭 ShadowWatch (https://shadowwatch.xyz/ — XRP Man's XRPL whale-tracking
  dashboard: live ledger stream, wallet graph, bubble map, HVT watchlist,
  wallet identity resolver)
- ⚡ xBoost (X Spaces tipping and engagement layer on XRPL)
- 🏛️ XRPLF (XRPL Foundation)

**Coffee & Crypto submenu:**
- 🎰 LuckyHash (`references/luckyhash.md`; trigger "luckyhash menu") —
  labeled deep links for Dice, Plinko, Slots, Scratchcards, Moonshot,
  Fireworks, Hex Wheel, ODJ jackpot, Gifts (buy/redeem), Leaderboard,
  How it works. Hard boundary: the assistant cannot buy or play — no public
  API; every bet and gift purchase is a payment the user signs in their own
  wallet (Xaman/Joey). Never claim to have placed a bet.

**🐻 Fuzzy submenu:**
- 🔍 FUZZY Deals (`xrpl-trade fuzzy-deals [--threshold 20]` — FUZZY NFTs
  listed below the trimmed median ask across the fuzzybears + fuzzy-bars
  collections; read-only, buying stays the separate `nft-buy` ceremony)
- 📖 FUZZY Lore (https://fuzzylore.com/ — community-built lore site)
- 🃏 FUZZY TCG Club (https://fuzzytcg.club/ — free-to-play community
  trading card game: multiplayer duels, tower climbs, tournaments)
- 🏪 $FUZZY Card Shop (https://fuzzycardshop.com/ — community-run shop,
  hosts the TCG club)
- 🛒 XRPresso physicals (`xrpl-trade xrpresso listings --q fuzzy
  --sort price_asc` — FUZZY physicals on XRPresso, cheapest first)

**NFT submenu** adds:
- Top Collections (`top-collections [--sort vol24h|trendingScore]`)
- 🐻 FUZZY Deals (`xrpl-trade fuzzy-deals [--threshold 20]` — FUZZY NFTs
  listed below the sample median ask; read-only, buying stays the
  separate `nft-buy` ceremony)
- 📥 Incoming (`xrpl-trade incoming` — bids on your NFTs, sell/gift
  offers to you, recent ledger receipts; per-row issuer screens;
  flagged offers hidden by default; friend labels on counterparties)

Market data is read-only and carries a "Data by xrpl.to" credit on every
surface. Movers print volume + market cap on each row — a +1300%
micro-cap reads as what it is; discovery, not advice, no trade buttons
on mover rows. `tx-explain` shows ledger-derived facts and only prints a
plain-English summary when xrpl.to actually returns one. Whale Watch is
flow discovery, not advice — 24h volumes are wash-tradable, and rows
show trade counts + P&L so thin activity reads as thin. Incoming offers
can be cancelled: the validated ledger is authoritative before acting,
and accepting an offer is always the separate `nft-buy` ceremony.

Each button opens its own focused submenu of tappable exact-command
buttons. After showing command results, attach a fresh set of the most
useful follow-up commands as buttons.

The `xrpl-trade menu` command provides the same navigation in a
terminal (arrow-key navigable). But in chat, buttons are the standard.

