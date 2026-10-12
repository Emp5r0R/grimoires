"""Fetch a hosted copy, hash it, and classify it against the manifest record."""

from __future__ import annotations

import dataclasses
import hashlib
import urllib.parse
from typing import Any, Optional

from .hosts import Host
from .media import dhash, hamming_hex, sniff_mime
from .net import Client
from .util import MiB, human_size, iso, now_utc, parse_iso

DEAD_STATES = {"removed", "expired", "blocked"}
OK_STATES = {"intact", "reencoded", "alive"}
CHECK_HISTORY = 20


@dataclasses.dataclass
class FetchOutcome:
    http_status: int
    final_url: str
    content_type: str
    size: int
    hashes: Optional[dict[str, str]]
    dhash: Optional[str]
    truncated: bool
    location: Optional[str] = None
    head_text: str = ""  # start of the body for HTML/text responses (soft-404 detection)


async def fetch_and_hash(c: Client, url: str, *, max_bytes: int, quick: bool, ua: Optional[str] = None,
                         method: str = "GET", follow: bool = True) -> FetchOutcome:
    headers = {"Accept": "*/*"}
    if ua:
        headers["User-Agent"] = ua
    if quick:
        headers["Range"] = "bytes=0-1023"
    async with c.request(method, url, headers=headers, allow_redirects=follow) as r:
        ctype = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        keep = bytearray()
        size = 0
        truncated = False
        async for chunk in r.content.iter_chunked(64 * 1024):
            size += len(chunk)
            if quick:
                keep.extend(chunk)
                if size >= 1024:
                    break
                continue
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            if len(keep) < 32 * MiB:
                keep.extend(chunk)
            if size > max_bytes:
                truncated = True
                break
        hashes = None
        dh = None
        if not quick and not truncated:
            hashes = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
            if ctype.startswith("image/") or sniff_mime(bytes(keep[:64])).startswith("image/"):
                dh = dhash(bytes(keep))
        if ctype in ("", "application/octet-stream") and keep:
            ctype = sniff_mime(bytes(keep[:2048]))
        head_text = bytes(keep[:65536]).decode("utf-8", "replace") if ctype.startswith("text/") or "html" in ctype else ""
        return FetchOutcome(r.status, str(r.url), ctype, size, hashes, dh, truncated, r.headers.get("Location"), head_text)


def classify(rec: dict[str, Any], out: FetchOutcome, host: Optional[Host], dh_threshold: int) -> tuple[str, str]:
    f = rec.get("file", {})
    expected_mime = f.get("mime", "")
    expires = parse_iso(rec.get("expires_at"))
    past_expiry = bool(expires and now_utc() > expires)
    gone = "expired" if past_expiry else "removed"
    if host:
        verdict = host.interpret(rec, out)
        if verdict:
            status, detail = verdict
            return (gone if status == "removed" else status), detail
    st = out.http_status
    if st in (404, 410):
        return gone, f"HTTP {st}"
    if host and host.soft_removed(out.final_url, out.content_type):
        return gone, "host serves its 'removed' placeholder"
    if st == 451:
        return "blocked", "HTTP 451 (legal block)"
    if st in (401, 403):
        return "error", f"HTTP {st} (forbidden; may be the proxy/IP)"
    if st >= 400:
        return "error", f"HTTP {st}"
    final_path = urllib.parse.urlsplit(out.final_url).path
    if final_path in ("", "/") and urllib.parse.urlsplit(rec.get("url", "")).path not in ("", "/"):
        return gone, "redirected to homepage"
    is_html = out.content_type in ("text/html", "application/xhtml+xml")
    if is_html and expected_mime not in ("text/html", "application/xhtml+xml"):
        return "alive", "page reachable but serves HTML (not the raw file); content not verified"
    if out.truncated:
        return "alive", f"larger than --max-download; content not verified ({human_size(out.size)}+)"
    if out.hashes is None:
        return "alive", f"HTTP {st} (quick check)"
    remote = rec.get("remote") or {}
    baseline = remote.get("sha256") if remote.get("status") in ("intact", "reencoded", "changed") else None
    if out.hashes["sha256"] == f.get("sha256"):
        return "intact", "byte-identical to the uploaded file"
    if baseline and out.hashes["sha256"] == baseline:
        return "intact", "identical to the copy verified right after upload (host re-encoded on upload)"
    original = (f.get("original") or {}).get("sha256")
    if original and out.hashes["sha256"] == original:
        return "reencoded", "host removed the hash-change marker (matches the original file)"
    dist = hamming_hex(out.dhash, f.get("dhash"))
    if dist is not None and dist <= dh_threshold:
        return "reencoded", f"bytes differ but image is visually the same (dHash distance {dist})"
    if dist is not None:
        return "changed", f"different image (dHash distance {dist})"
    if not f.get("sha256"):
        return "alive", "reachable (no expected hash to compare)"
    return "changed", "content hash differs"


def check_entry(rec: dict[str, Any], out: Optional[FetchOutcome], status: str, detail: str, via: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"at": iso(now_utc()), "status": status, "detail": detail, "via": via}
    if out:
        entry.update({"http_status": out.http_status, "final_url": out.final_url, "content_type": out.content_type, "size": out.size})
        if out.hashes:
            entry.update(out.hashes)
            entry["matches_local"] = out.hashes["sha256"] == rec.get("file", {}).get("sha256")
        if out.dhash:
            entry["dhash"] = out.dhash
    return entry


def host_hash_matches(reported: Optional[dict[str, str]], local: dict[str, str]) -> Optional[bool]:
    """Compare a hash the host itself returned (md5/sha1) with the local one."""
    if not reported:
        return None
    for algo, value in reported.items():
        if algo in local:
            return value.lower() == local[algo]
    return None
