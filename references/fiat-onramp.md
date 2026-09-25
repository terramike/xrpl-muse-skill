# Fiat on-ramp (optional companion)

Uses the `changelly_buy` skill (`~/workspace/skills/changelly-buy/`) to fund
a wallet with card-bought XRP before trading.

## Commands

```bash
~/workspace/skills/changelly-buy/bin/changelly-buy quote --crypto xrp --fiat usd --fiat-amount 100
# → spot-price estimate (before provider fees and spread)

~/workspace/skills/changelly-buy/bin/changelly-buy link --crypto xrp --fiat usd --fiat-amount 100
# → prefilled buy link; attributed when CHANGELLY_REF_URL is set
```

With `CHANGELLY_REF_URL` set (affiliate link from the Changelly dashboard),
the buy link carries attribution; without it, a plain
`https://changelly.com/buy` link is emitted and the skill says so.

## Boundaries

- The on-ramp never touches `XRPL_SEED`, never builds proposals, and never
  submits transactions. It is link generation only — outside the
  propose → approve → sign boundary.
- The buyer completes identity verification and card payment on Changelly
  (18+, availability varies by country). The quote is a spot estimate; final
  price and fees are shown on Changelly before payment.
- If the destination wallet is an exchange account, the buyer must enter the
  destination tag / memo, or funds can be lost.
- If `changelly_buy` is not installed, skip this step or hand the user a
  plain `https://changelly.com/buy` link.
