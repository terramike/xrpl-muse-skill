#!/usr/bin/env python3
"""xrpl_pin v0.5: Pinata IPFS pinning for the XRPL NFT skill.

Bring-your-own-key design: the ONLY credential is the PINATA_JWT
environment variable. This module never stores keys, never logs them,
and the repository ships no credentials — every skill operator pins
with their OWN Pinata account, so each operator hosts their own media.
See references/nft-pinata.md for setup.

No xrpl-py dependency here (stdlib only) so the pinner stays tiny.
"""
import json
import os
import sys
import urllib.request

PINATA_PIN_FILE = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_PIN_JSON = "https://api.pinata.cloud/pinning/pinJSONToIPFS"


def _jwt():
    jwt = os.environ.get("PINATA_JWT")
    if not jwt:
        sys.exit(
            "PINATA_JWT is not set. Create a (free) Pinata account, "
            "mint an API key with pinning scope, and export PINATA_JWT — "
            "see references/nft-pinata.md. The key is never stored or logged.")
    return jwt


def _post(url, body: bytes, content_type: str, filename: str = None) -> dict:
    """POST to Pinata. Returns the decoded JSON response."""
    if filename is not None:
        # minimal multipart/form-data for a single file field
        boundary = "----xrplpinboundary"
        head = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        body = head + body + tail
        content_type = f"multipart/form-data; boundary={boundary}"
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": f"Bearer {_jwt()}",
                 "Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        sys.exit(f"Pinata request failed ({e.code}): {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"Pinata unreachable: {e.reason}")


def pin_file(path: str) -> str:
    """Pin a local file to IPFS. Returns the CID (no ipfs:// prefix)."""
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        sys.exit(f"refusing to pin empty file: {path}")
    resp = _post(PINATA_PIN_FILE, data, "application/octet-stream",
                 filename=os.path.basename(path))
    cid = resp.get("IpfsHash")
    if not cid:
        sys.exit(f"Pinata returned no IpfsHash: {resp!r}"[:200])
    return cid


def pin_json(obj: dict, name: str = "metadata.json") -> str:
    """Pin a JSON object to IPFS. Returns the CID (no ipfs:// prefix)."""
    blob = json.dumps(obj, separators=(",", ":")).encode()
    resp = _post(PINATA_PIN_JSON, blob, "application/json")
    cid = resp.get("IpfsHash")
    if not cid:
        sys.exit(f"Pinata returned no IpfsHash: {resp!r}"[:200])
    return cid


def build_metadata(name: str, description: str, image_cid: str) -> dict:
    """XLS-24d-style metadata: the token URI points at this document,
    and it points at the art. CIDs are content hashes, so the metadata
    is immutable once pinned."""
    return {
        "name": name,
        "description": description,
        "image": f"ipfs://{image_cid}",
    }


def pin_artwork(path: str, name: str, description: str):
    """Pin art + metadata. Returns (image_cid, metadata_cid).

    Two pins, one for the art and one for the metadata JSON — the ledger
    URI points at the metadata CID, marketplaces resolve image from it.
    """
    image_cid = pin_file(path)
    meta = build_metadata(name, description, image_cid)
    metadata_cid = pin_json(meta, name=f"{name}-metadata.json")
    return image_cid, metadata_cid


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Pin a file or JSON to IPFS via your own Pinata key.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("file", help="pin a local file, print its CID")
    p.add_argument("path")
    p = sub.add_parser("json", help="pin a JSON file, print its CID")
    p.add_argument("path")
    args = ap.parse_args()
    if args.cmd == "file":
        print(pin_file(args.path))
    else:
        with open(args.path) as f:
            print(pin_json(json.load(f),
                           name=os.path.basename(args.path)))


if __name__ == "__main__":
    main()
