#!/bin/bash
# Install the XRPL trading skill into this Muse workspace.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/workspace/skills/xrpl"
mkdir -p "$DEST"
cp -r "$SRC/SKILL.md" "$SRC/README.md" "$SRC/SECURITY.md" \
      "$SRC/requirements.txt" "$SRC/requirements-locked.txt" \
      "$SRC/approved.example.json" \
      "$SRC/policy.example.json" "$SRC/bin" "$SRC/tests" "$DEST/"
pip install -r "$DEST/requirements-locked.txt"
echo ""
echo "Installed to $DEST"
echo ""
echo "SECURITY NOTICE — read before mainnet:"
echo "  This is a local, same-user install. A same-user agent process can"
echo "  read the signer's environment and rewrite its policy/state files —"
echo "  0600 permissions do NOT stop a same-UID process. Treat this install"
echo "  as TESTNET-ONLY unless the signer runs behind a real protected"
echo "  boundary (vault + separate OS identity or privileged signing"
echo "  service) with per-transaction human approval."
echo "  See SECURITY.md \"Deployment profiles\"."
echo ""
echo "Next: run  $DEST/bin/xrpl-trade setup   (start with testnet)"
echo "Then:      $DEST/bin/xrpl-sign init-policy"
echo "Or tell your Muse: 'set up my XRPL wallet on testnet'"
