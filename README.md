# xrpl-muse-skill v0.3

Trade the XRP Ledger from the terminal — any token pair — with a hard safety
boundary between **proposing** a trade and **signing** it.

Built for AI agents (Muse, Grok, OpenClaw-style bots — anything with a
terminal), but safe for humans too.

## The idea

Most trading tools ask the agent to "ask the human first" and hope it does.
This skill splits the job in two:

- **`xrpl-trade`** builds the transaction, autofills it against the live
  network, shows you *everything* (account, network, assets + issuers,
  amounts, limit price, max spend, fee, expiry), seals it in a **hash-bound
  proposal envelope**, and stops. It never sees your seed. It cannot submit.
- **`xrpl-sign`** is the only program that touches the seed (from the
  `XRPL_SEED` env var — never from a config file). It re-verifies the
  envelope, derives the summary from the transaction itself (nothing stored
  is trusted), enforces the policy file, and signs **only** with explicit
  human `--approve` of that exact hash.

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → full proposal + hash. Nothing submitted.

xrpl-sign --hash a2c72140d080ca0f --approve
# → envelope verify → policy checks → sign → persist → validated result
```

## What v0.3 hardens

- **Hash-bound envelope** (`xrpl-proposal/3`): the approval hash covers the
  network, account, action, creation time, policy version, and the canonical
  XRPL binary of the complete transaction. Tampering with any of it —
  including the proposal file — voids the approval.
- **Strict transaction schemas**: only `OfferCreate`, `OfferCancel`,
  `TrustSet`, `Payment` are signable, and every field is allowlisted per
  type. No smuggled `Paths`, `SendMax`, memos, or partial-payment flags.
- **Derived, never stored**: pair, side, amounts, and price are computed
  from the transaction inside the signer.
- **Per-asset spend limits**: per-transaction and rolling-24h caps per asset,
  reserved atomically. Assets with no configured limit are blocked.
- **Exact-pair enforcement**: offers must match an approved pair exactly —
  unlisted token/token combinations are denied.
- **Destination policy**: payments only to allowlisted `(address,
  destination_tag)` pairs; conflicting X-address/CLI tags rejected;
  `RequireDestTag` destinations refuse untagged payments.
- **Crash-safe submission**: sign → persist the signed hash and
  `LastLedgerSequence` → submit → wait for the validated ledger result.

## Why the allowlist matters

Tickers mean nothing on the XRP Ledger — anyone can mint a fake "ARMY".
This skill trades **pair names mapped to vetted issuer addresses**, and the
signer extracts token identities from the transaction JSON itself, so raw
issuer arguments can't bypass it.

Live at launch: `XRP/RLUSD, BTC/XRP, XLM/XRP, ARMY/XRP, PHNIX/XRP, BCHAMP/XRP,
FUZZY/XRP`

The shipped `approved.example.json` contains two template pairs
(`XRP/RLUSD`, `ARMY/XRP`) — copy it to `~/.xrpl/approved.json` and add
only pairs whose issuers you have personally vetted. Tickers mean nothing
on XRPL; the issuer address is the identity.

## Install

```bash
pip install -r requirements.txt
xrpl-trade setup            # address + network (never the seed)
xrpl-sign init-policy       # policy file v3, testnet-locked by default
```

The signer reads the seed **only** from `XRPL_SEED`, provided by your secret
manager or agent vault after human approval. Testnet funds:
`xrpl-trade faucet --network testnet`

## What it does

- **Read:** balances, order books for any pair, open offers, issuer risk
  inspection (domain, transfer fees, freeze flags), trade planning
  (estimated fill, price impact, max spend), transaction reconciliation.
- **Write (all gated):** limit buys/sells, trustlines, offer cancels, payments
  with destination-tag and X-address support.

## Security

See [SECURITY.md](SECURITY.md) — including the platform boundary: `--approve`
is an assertion, not evidence of human approval, and the advisory that
versions before commit `c3273e59` shipped inverted buy/sell and must not be
used for trading.

## Tests

```bash
python3 tests/test_v03.py          # 40 adversarial logic tests, no network
python3 tests/test_e2e_testnet.py  # 17 end-to-end checks on testnet
```

## License

MIT — see [LICENSE](LICENSE).
