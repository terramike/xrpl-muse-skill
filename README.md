# xrpl-muse-skill v0.2

Trade the XRP Ledger from the terminal — any token pair — with a hard safety
boundary between **proposing** a trade and **signing** it.

Built for AI agents (Muse, Grok, OpenClaw-style bots — anything with a
terminal), but safe for humans too.

## The idea

Most trading tools ask the agent to "ask the human first" and hope it does.
This skill splits the job in two:

- **`xrpl-trade`** builds the transaction, autofills it against the live
  network, shows you *everything* (account, network, assets + issuers,
  amounts, limit price, max spend, fee, expiry), hashes the exact bytes, and
  stops. It never sees your seed. It cannot submit.
- **`xrpl-sign`** is the only program that touches the seed (from the
  `XRPL_SEED` env var). It re-verifies the proposal hash, enforces a policy
  file (network lock, approved issuers, spend caps, fee caps, price-deviation
  checks, destination allowlist), and signs **only** with explicit human
  `--approve` of that exact hash.

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → full proposal + hash. Nothing submitted.

xrpl-sign --hash a2c72140d080ca0f --approve
# → policy checks → sign → validated ledger result → audit log
```

## Why the allowlist matters

Tickers mean nothing on the XRP Ledger — anyone can mint a fake "ARMY".
This skill trades **pair names mapped to vetted issuer addresses**, and the
signer extracts token identities from the transaction JSON itself, so raw
issuer arguments can't bypass it.

Live at launch: `XRP/RLUSD, BTC/XRP, XLM/XRP, ARMY/XRP, PHNIX/XRP, BCHAMP/XRP,
FUZZY/XRP`

## Install

```bash
pip install -r requirements.txt
xrpl-trade setup            # address + network (no seed stored)
export XRPL_SEED='s…'       # only the signer reads this
xrpl-sign init-policy       # policy file, testnet-locked by default
```

Testnet funds: `xrpl-trade faucet --network testnet`

## What it does

- **Read:** balances, order books for any pair, open offers, issuer risk
  inspection (domain, transfer fees, freeze flags), trade planning
  (estimated fill, price impact, max spend), transaction reconciliation.
- **Write (all gated):** limit buys/sells, trustlines, offer cancels, payments
  with destination-tag and X-address support.

## Security

See [SECURITY.md](SECURITY.md) — including the advisory that versions before
commit `c3273e59` shipped inverted buy/sell and must not be used for trading.

## License

MIT — see [LICENSE](LICENSE).
