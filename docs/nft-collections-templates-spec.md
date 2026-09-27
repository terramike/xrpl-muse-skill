# NFT Collections, Templates & Attribution — Spec (v1)

Status: spec approved by Mike 2026-09-26. Not yet implemented.

## Goal

Turn `nft-mint` from a CLI invocation into a guided conversational flow:
"mint an nft" → assistant asks the right questions → NFT lands in the intended
collection with the intended metadata → offer to save the field shape as a
reusable template. Every mint carries XRPL-Muse attribution by default.

## 1. Collections registry

XRPL has no on-ledger collection object. A collection is the pair
**issuer + NFTokenTaxon** (taxon alone is not unique across issuers).

- File: `~/.xrpl/collections.json`, mode 0600.
- Entry: `{name: {issuer, taxon, description?, royalty_bps?, created_at}}`
- `collection create --name --taxon [--issuer] [--description] [--royalty-bps]`
  - `--issuer` defaults to the signing account.
  - This is **local bookkeeping only** — no ledger transaction. UX must say so.
  - Registry writes follow the policy.json rule: show the exact diff, require
    explicit yes. (Prompt injection could otherwise point a collection name at
    a wrong issuer/taxon.)
- `collection list`, `collection inspect <name>`, `collection remove <name>`
  - `inspect` is read-only, no approval: resolves issuer+taxon, counts tokens
    via `account_nfts` with client-side taxon filtering, shows recent tokens.
- `nft-mint --collection <name>` resolves issuer + taxon (+ default royalty).
  `--taxon` remains as a one-off escape hatch.
- **Mint-time verification (fail closed):** the signing account must equal the
  registered issuer OR be the issuer's on-ledger authorized `NFTokenMinter`.
  Otherwise refuse — this is what stops a tampered registry entry from
  minting into someone else's collection identity.
- Collection `royalty_bps` is a default transfer fee applied to mints in that
  collection (XRPL has no collection-level royalties; the per-NFT fee already
  exists in the mint flow). Explicit `--royalty-bps` on the mint overrides it.

## 2. Templates

A template is a named metadata field schema — labels only, no values.

- File: `~/.xrpl/nft-templates.json`, mode 0600.
- Entry: `{name: {fields: [{label, required}], created_at}}`
- v1: string fields only, each marked required or optional.
- **Templates are NOT bound to a collection.** Artists reuse one template
  across collections; the collection is picked fresh at each mint.
  (Mike's decision 2026-09-26.)
- Commands: `template create` (interactive or args), `template list`,
  `template show <name>`, `template remove <name>`.
- After any mint completes, the assistant offers: "save this field shape as
  a template?" with a name. Template writes follow the same exact-diff +
  explicit-yes rule as the collections registry.
- Example: "XRPixel Jets" template →
  fields: name*, description*, attack*, speed*, defense*, gun1, gun2
  (* = required)

## 3. Conversational builder (assistant-driven, in chat)

Trigger: user says "mint an nft" (or equivalent).

1. Which collection? List collections the signing account owns or is
   authorized minter for (verified on-ledger). Offer to create one.
2. Which template? List saved templates, or build fields ad-hoc.
3. Artwork file (user uploads), NFT name.
4. Ask for each template field value, in order, skipping optional ones on
   request.
5. Full review of everything (collection, taxon, name, all metadata incl.
   attribution block) → then the existing pipeline unchanged:
   stage → pin to IPFS → propose → approve → sign.
6. After completion, offer to save the field shape as a template.

The builder only collects answers; all signing still goes through
propose → approve → sign with the exact-hash Submit tap.

## 4. Attribution (growth loop)

Every mint's metadata JSON includes, by default:

```json
"minted_with": "XRPL-Muse",
"minted_with_url": "https://github.com/terramike/xrpl-muse-skill"
```

- Stable key names so indexers/marketplaces can recognize them later.
- Default-on, with an explicit `--no-attribution` escape hatch.
  (Mike's decision 2026-09-26.)
- The attribution block is shown in the proposal review — transparent,
  never silently injected.

## 5. Security notes

- Registry + template files are agent-writable local state: exact diff +
  explicit approval for every write (extends the standing policy.json rule).
- Mint-time issuer / authorized-minter check is the backstop; it must pass
  even if the registry was tampered with.
- No change to the propose → approve → sign boundary. Autopilot still
  requires the per-transaction Submit tap.
- A template can never change *where* funds or NFTs go — only metadata
  labels. Collection choice is always confirmed in the review step.

## 6. Deferred (not v1)

- Per-collection auto-numbering ("Jet #483"): the ledger's token sequence is
  per-issuer, not per-collection; per-collection numbering needs a local
  counter with ledger resync. Explicit names in v1.
- Typed metadata fields (numbers, dropdowns): strings are enough for v1.
- Base-URI / shared metadata templates per collection.
