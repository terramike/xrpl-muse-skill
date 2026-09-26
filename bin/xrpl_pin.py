#!/usr/bin/env python3
"""xrpl_pin: Pinata IPFS pinning for the XRPL NFT skill.

Bring-your-own-key design: the ONLY credential is the PINATA_JWT
environment variable. This module never stores keys, never logs them,
and the repository ships no credentials — every skill operator pins
with their OWN Pinata account, so each operator hosts their own media.
See references/nft-pinata.md for setup.

P1-4 hardening:
- Artwork may only come from the protected NFT media directory
  (~/.xrpl/media by default, overridable via the "media_dir" key in
  ~/.xrpl/config.json — never via an environment variable, which an
  agent could set). Symlink escapes and path traversal are refused.
- read_validated_source() reads the file ONCE (O_NOFOLLOW) and returns
  its bytes; pin_data() uploads those SAME bytes. The pin step never
  reopens the file between hashing and uploading (no TOCTOU).

No xrpl-py dependency here (stdlib only) so the pinner stays tiny.
"""
import hashlib
import json
import os
import stat
import sys
import urllib.request

PINATA_PIN_FILE = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_PIN_JSON = "https://api.pinata.cloud/pinning/pinJSONToIPFS"


# ---------- pin sources: validated local files only ----------

# Artwork size cap: 10 MiB. NFT art bigger than this is a mistake, and the
# cap bounds what a misclick can exfiltrate in one pin.
NFT_MAX_BYTES = 10 * 1024 * 1024

# Conservative allowlist: raster images only. No SVG (scriptable XML), no
# HTML, no executables — the pinner is not a general file host.
ALLOWED_MIME = {"image/png", "image/jpeg", "image/gif", "image/webp"}

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".xrpl", "pin-policy.json")
DEFAULT_MEDIA_DIR = os.path.join(os.path.expanduser("~"), ".xrpl", "media")


def protected_media_dir():
    """Read explicit upload policy; deployment must isolate it from the agent."""
    if os.name != "posix":
        sys.exit("Protected uploads require the POSIX Muse signing deployment")
    try:
        st = os.lstat(CONFIG_PATH)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            sys.exit("Pin policy must be a signer-owned regular 0600 file")
        parent = os.stat(os.path.dirname(CONFIG_PATH))
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            sys.exit("Pin policy directory must not be writable by other users")
        with open(CONFIG_PATH) as source:
            policy = json.load(source)
        if not isinstance(policy, dict) or set(policy) != {"media_dir"}:
            sys.exit("Pin policy must contain only media_dir")
        path = policy["media_dir"]
        if not isinstance(path, str) or not os.path.isabs(path) or not os.path.isdir(path):
            sys.exit("Pin media_dir must be an existing absolute directory")
        return os.path.realpath(path)
    except (OSError, ValueError) as ex:
        sys.exit("Protected pin policy unavailable; configure pin-policy.json through the operator: " + str(ex))



def _sniff_mime(head: bytes):
    """MIME from magic bytes (not the file extension). None if unknown."""
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if head[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


def read_validated_source(path, media_dir=None):
    """Read a pin source after strict validation. Zero network calls.

    The file is opened ONCE (O_NOFOLLOW) and its bytes are returned, so a
    caller can hash and then upload those exact bytes without reopening
    the file (no TOCTOU window).

    Returns (data, info) where info = {path, bytes, mime, sha256,
    media_dir}. media_dir defaults to the protected media directory;
    production callers must pass protected_media_dir() (or leave the
    default) — the permitted directory lives in protected config, never
    in a stage record or an environment variable.

    Refuses (SystemExit): missing/non-regular files, paths resolving
    outside the media directory (symlink escape / traversal), symlinks at
    open time (O_NOFOLLOW), empty or oversized files, and MIME types
    outside ALLOWED_MIME (sniffed from magic bytes, never the extension).
    """
    mdir = os.path.realpath(media_dir or protected_media_dir())
    if not os.path.isdir(mdir):
        sys.exit(
            f"NFT media directory not found: {mdir}\n"
            f"Create it and put the artwork inside, or set \"media_dir\" in "
            f"{CONFIG_PATH}.")
    try:
        real = os.path.realpath(path)
    except (TypeError, ValueError):
        real = ""
    try:
        inside = os.path.commonpath([real, mdir]) == mdir and real != mdir
    except ValueError:
        inside = False
    if not inside:
        sys.exit(f"refusing: source is outside the NFT media directory\n"
                 f"  source:    {path}\n"
                 f"  media dir: {mdir}")
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        sys.exit(f"refusing: source not found: {path}")
    except IsADirectoryError:
        sys.exit(f"refusing: source is a directory: {path}")
    except OSError as e:
        # ELOOP here means a symlink appeared at open time (TOCTOU swap).
        sys.exit(f"refusing to open source: {path} ({e.strerror or e})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            sys.exit(f"refusing: not a regular file: {path}")
        size = st.st_size
        if size == 0:
            sys.exit(f"refusing to pin empty file: {path}")
        if size > NFT_MAX_BYTES:
            sys.exit(f"refusing: {size} bytes exceeds the "
                     f"{NFT_MAX_BYTES}-byte artwork limit")
        mime = _sniff_mime(os.read(fd, 16))
        if mime not in ALLOWED_MIME:
            sys.exit(
                f"refusing: {mime or 'unrecognized'} content is not allowed "
                f"artwork (allowed: {', '.join(sorted(ALLOWED_MIME))})")
        h = hashlib.sha256()
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            h.update(chunk)
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != size:
            sys.exit("refusing: file changed while reading — re-run")
        return data, {"path": real, "bytes": size, "mime": mime,
                      "sha256": h.hexdigest(), "media_dir": mdir}
    finally:
        os.close(fd)


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


def pin_data(data: bytes, filename: str) -> str:
    """Pin bytes already read+validated to IPFS. Returns the CID.

    Takes the exact bytes (e.g. from read_validated_source) — the file is
    NOT reopened, so the uploaded bytes are provably the hashed bytes.
    This is the TOCTOU-safe upload path; prefer it over pin_file whenever
    the bytes were already read for hashing.
    """
    if not data:
        sys.exit(f"refusing to pin empty data: {filename}")
    resp = _post(PINATA_PIN_FILE, data, "application/octet-stream",
                 filename=os.path.basename(filename))
    cid = resp.get("IpfsHash")
    if not cid:
        sys.exit(f"Pinata returned no IpfsHash: {resp!r}"[:200])
    return cid


def pin_file(path: str, media_dir=None) -> str:
    """Pin a local file to IPFS. Returns the CID (no ipfs:// prefix).

    The source is strictly validated (protected media directory,
    O_NOFOLLOW, size, MIME) and the validated bytes are uploaded without
    reopening the file.
    """
    data, info = read_validated_source(path, media_dir=media_dir)
    return pin_data(data, info["path"])


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


def pin_artwork(path: str, name: str, description: str, media_dir=None):
    """Pin art + metadata. Returns (image_cid, metadata_cid).

    Two pins, one for the art and one for the metadata JSON — the ledger
    URI points at the metadata CID, marketplaces resolve image from it.
    """
    image_cid = pin_file(path, media_dir=media_dir)
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
