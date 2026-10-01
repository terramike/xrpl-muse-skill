# LuckyHash (reference)

LuckyHash (https://luckyhash.win/) is a provably-fair crypto gaming platform.
Game outcomes are derived from fresh XRPL ledger hashes — no house server
decides results. Listed in the trusted-links registry under Gaming (verified
by direct open 2026-09-30). This file is reference data: game list, mechanics,
and deep links. It is not an endorsement and not a payment instruction.

## Capability boundary (hard rule)

The assistant **cannot buy or play on the user's behalf.** There is no public
API, no bot endpoint, and no automation surface (verified 2026-09-30 via full
nav/footer/how-it-works read; the only "auto" feature is Slots' in-game
auto-spin, which is manual auto-play, not programmable).

Every bet batch and every gift purchase is a fresh on-ledger XRPL Payment
that the **user signs in their own wallet** — the site's "Pay N \<token\>"
button opens a Xaman/Joey signing modal in the user's browser. Never claim to
have placed a bet, and never construct a payment pretending it is a LuckyHash
bet: the payment is only recognized as a bet inside a session the site itself
generated.

What the assistant CAN do: deep links, explain mechanics/odds/RTP, talk
through bet sizing before the user signs anything.

## Bet lifecycle (fund → bet → settle)

1. **Fund:** there is no on-site balance and no pre-funding. Each round batch
   is bought individually: set amount-per-bet, number of bets, token → "Pay N
   \<token\>" → sign in Xaman or Joey. No signup required; reconnecting the
   same wallet resumes sessions. Moonshot also accepts SOL/USDC-SOL via
   Phantom.
2. **Bet:** after payment, each bet waits for the next XRPL ledger close
   (~3–5 s), then the outcome derives from
   `SHA256(payment/redeem ID : fresh ledger hash : bet index)`. Every result
   has an on-page verifier showing hashes, ledger refs, and math.
3. **Settle:** automatic on-ledger payout to the player's wallet — no manual
   claim. Wins over 1000 XRP require manual verification (up to 24h).
   Interruptions: ~24h resume window; after that, recorded wins are queued as
   one wallet payout and unplayed rounds become a wallet-restricted gift.
   The "Missing Play" tool recovers paid-but-missing XRPL sessions by tx hash.

## Games (URLs verified verbatim 2026-09-30)

- Dice — https://luckyhash.win/dice — roll-under 1–99, up to 100 bets per
  payment, multipliers up to ~99×
- Plinko — https://luckyhash.win/plinko — up to 50 drops per payment,
  8/16 rows
- Slots — https://luckyhash.win/slots — 10 machines, ~95%+ RTP (Classic 5×3
  paylines + 7×7 Cluster tumbles)
- Scratchcards — https://luckyhash.win/cards — ~50 cards, each priced in its
  own token
- Moonshot — https://luckyhash.win/moonshot — cash-out timing, 96% RTP, pilot
  ranks unlock multipliers
- Fireworks — https://luckyhash.win/fireworks — inverted Plinko
- Hex Wheel — https://luckyhash.win/hexwheel — 16 segments, pick 1–15 per spin
- ODJ jackpot — https://luckyhash.win/odj — Dopamine / Pro Trader modes
- Leaderboard — https://luckyhash.win/leaderboard
- How it works — https://luckyhash.win/how-it-works

Dead URLs (404 — never use): `/hex-wheel`, `/scratchcards`, `/redeem-gift`.

## Tokens

Same selector on all games: XRP, LHT, PHNIX, xSPECTAR, ATM, OPM, SOL, nuked,
$666, $CamelToe (plus CSC per how-it-works). Moonshot labels SOL as
Solana/Phantom.

## Gifts

Bought via 3-step wizard at https://luckyhash.win/gifts: choose game/card →
pay via wallet → share a 12-character code (e.g. `LCKY-HASH-RCKS`). All 8
games are giftable. Redeem at https://luckyhash.win/gift/redeem-code — anyone
with the code can redeem; a wallet is needed to receive automatic winnings.
Gifts are shareable redeem links, NOT wallet-to-wallet transfers. Unplayed
rounds from interrupted sessions become wallet-restricted recovery gifts.

## Chat trigger

When the user says "luckyhash menu", reply with the labeled link menu above
(games + gifts + community). Keep the user's own NFT prize flow
(mint → nft-send) separate — it needs no LuckyHash.
