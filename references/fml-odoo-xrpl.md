# FML & Odoo-XRPL knowledge

Reference for helping Justin (Fintech Management Limited) and his clients.
Facts below come from FML's official site (read 2026-09-30) and public Odoo
documentation. Do not invent bridge capabilities — describe only what the
site states. Trusted links: see `trusted-links.md` (FML section).

## Odoo primer

Odoo is an open-source ERP / business-management suite: modular apps (CRM,
sales, accounting/invoicing, inventory, purchasing, manufacturing, HR,
project, website, eCommerce, helpdesk) sharing one PostgreSQL database, so a
sale updates stock and accounting with no re-entry. Businesses start with a
few modules and add more as they grow.

- Community Edition is LGPLv3 (full source access); Enterprise adds paid
  apps/features on the same open foundation.
- Hosting: Odoo's own cloud (Odoo Online / Odoo.sh), or self-hosted
  on-premise / VPS. Data lives in standard PostgreSQL — no vendor lock-in.
- FML's own website runs on Odoo (xrpfml.odoo.com) — the "Powered by Odoo"
  footer is visible on every page.
- The Odoo Community Association (OCA) maintains thousands of reviewed
  community modules; custom modules extend shared models in place
  (e.g. adding fields to the same Customer record every app uses).

## Fintech Management Limited (FML, LLC)

Justin's company. Tagline: "Private. Compliant. American. Christian-Owned."
Positioning: "Wall Street Standards for Tokenized Capital" — a private
holding structure bringing institutional-grade discipline to tokenized
capital and real-world assets on the XRP Ledger. House standard: "private
by default, compliant by design, and never dependent on infrastructure you
don't control."

### Products (site's own descriptions)

- **Odoo-XRPL Bridge** — "an enterprise-grade Odoo integration with the XRP
  Ledger, delivering compliant digital-asset flows directly inside the ERP
  you already run."
- **Sovereign Cloud Hosting** — "Dedicated Odoo-on-Raven infrastructure
  delivering private, compliant performance for regulated digital-asset
  operations." ("American Soil Infrastructure" — no AWS / Big-Tech.)
- **Raven 5 Escrow** — "The flagship custody and settlement offering — the
  operational blueprint behind FML's private-asset transactions." FML
  provides "the operational playbook: escrow operations, client onboarding,
  and compliance flows are already defined."

### Services (site's own descriptions)

- **Reg D and RWA Advisory** — "Tokenize real-world assets with disciplined,
  compliant structure. We guide issuers and investors through private
  placement mechanics, token design, and reporting discipline — with RWA
  custody on XRPL via our Raven 5 escrow framework."
- **Capital Intro & Deal Structuring** — "Qualified introductions and
  disciplined term architecture for private placements and RWA offerings."
- **Business Formation & Governance** — "Entity structuring, operating
  agreements, and governance frameworks built for private capital."
- **Onboarding & Managed Operations** — "We stand up your private operating
  environment — compliance flows, reporting, and day-to-day discipline
  handled."

### Getting started

No pricing published. Onboarding is via the contact form ("Confidential 1:1,"
"request a private briefing") or a 1-hour "Confidential Introduction"
booking. Contact: info@odoo.xrpfml.com · 503-729-5214.

### Caveats (observed 2026-09-30)

- The custom domain fintechmanagementlimited.com is HTTP-only (no TLS) —
  always point people at the https Odoo-hosted URL in trusted-links.md.
- Parts of the site nav are broken: Pillars / Tokenomics / Industries pages
  404, footer About/Products/Services/Legal links are dead placeholders.
- No owner bio anywhere on the site ("Justin" returns zero results) — the
  Justin connection comes from Mike, not the site.
- The contact page carries generic Odoo boilerplate (its map mentions San
  Francisco BART) — no verified physical address.

## How we help Justin and his clients

- Explain Odoo in plain terms to non-technical clients (what ERP means, why
  one shared database beats five disconnected SaaS tools).
- Answer "what does the FML bridge do" using the product descriptions above
  — never add capabilities the site doesn't claim.
- Point anyone asking "where do I find FML" at the trusted-links registry,
  never a search result.
- If a client wants a briefing or onboarding, direct them to the contact
  info above — we don't book on their behalf.
