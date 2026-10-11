#!/usr/bin/env python3
"""
media_drop.py

Upload images/media to free public hosts through rotating free proxies, keep a
hash manifest of every upload per host, and later re-check that the uploaded
media is still online and unmodified.

Modes:
  upload    Upload one or more files (or directories) to one or many hosts,
            failing over between hosts and rotating proxies on every failure.
            --save-hashes records MD5/SHA-1/SHA-256 (+ perceptual dHash when
            Pillow is installed) for each host the file landed on.
  check     Re-visit every URL in a manifest (or ad-hoc URLs) and classify it:
            intact / reencoded / changed / alive / removed / expired / blocked
            / error. Results are written back into the manifest history.
  list      Print the manifest as a table, CSV or JSON.
  hosts     Show supported hosts, limits, retention and availability.
  proxies   Fetch, validate and cache the free proxy pool; export it.

Design goals:
  * No hard-coded paid proxy credentials or scraped auth tokens: per-session
    tokens are pulled live from the host page, free proxies are pulled live
    from ~30 public lists and validated before use.
  * TLS verification is ALWAYS on. Free proxies are untrusted; a proxy that
    tries to MITM the connection fails validation and is discarded.
  * Proxies whose exit IP equals your real IP are discarded (leak check).
  * Uploaded filenames are randomised by default (--keep-name to opt out),
    optional EXIF/metadata stripping before upload (--strip-metadata).
  * Every host failure is classified (proxy fault / host rejection / file
    too large / transient) so retries rotate proxies only when it helps.
  * Manifest writes are atomic; Ctrl-C never corrupts the hash file.

Requirements:
  Python 3.9+
  aiohttp                  (python -m pip install aiohttp)
  aiohttp-socks  optional  SOCKS4/5 proxies and Tor
  Pillow         optional  --strip-metadata and perceptual hashes (dHash)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import dataclasses
import datetime as dt
import hashlib
import io
import json
import logging
import mimetypes
import os
import random
import re
import secrets
import ssl
import string
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None  # type: ignore

try:
    from aiohttp_socks import ProxyConnector  # type: ignore

    try:
        from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError  # type: ignore

        SOCKS_ERRORS: tuple = (ProxyConnectionError, ProxyError, ProxyTimeoutError)
    except ImportError:  # pragma: no cover - very old aiohttp-socks
        SOCKS_ERRORS = ()
except ImportError:
    ProxyConnector = None  # type: ignore
    SOCKS_ERRORS = ()

try:
    from PIL import Image, ImageOps  # type: ignore
except ImportError:
    Image = None  # type: ignore
    ImageOps = None  # type: ignore


VERSION = "1.0.0"
TOOL = "media_drop"
DEFAULT_MANIFEST = "media_hashes.json"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "media-drop"
MANIFEST_SCHEMA = 1
CHECK_HISTORY = 20
MiB = 1024 * 1024

log = logging.getLogger(TOOL)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
]

# (name, url, scheme to assume when a line has no scheme, format)
FREE_PROXY_SOURCES: list[tuple[str, str, str, str]] = [
    ("proxyscrape", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text", "http", "text"),
    ("proxyscrape-v2", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", "http", "text"),
    ("geonode", "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc", "http", "geonode"),
    ("proxifly-http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "http", "text"),
    ("proxifly-socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "socks5", "text"),
    ("thespeedx-http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http", "text"),
    ("thespeedx-socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4", "text"),
    ("thespeedx-socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5", "text"),
    ("monosans-http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http", "text"),
    ("monosans-socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5", "text"),
    ("jetkai-https", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "http", "text"),
    ("roosterkid-https", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "http", "text"),
    ("roosterkid-socks5", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "socks5", "text"),
    ("hookzof-socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5", "text"),
    ("mmpx12-https", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt", "http", "text"),
    ("vakhov-https", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt", "http", "text"),
    ("vakhov-socks5", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt", "socks5", "text"),
    ("ercindedeoglu-https", "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt", "http", "text"),
    ("zloi-user-https", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt", "http", "text"),
    ("zaeem20-https", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt", "http", "text"),
    ("murongpig-http", "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt", "http", "text"),
    ("sunny9577", "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", "http", "text"),
    ("aliilapro-http", "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", "http", "text"),
    ("r00tee-https", "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt", "http", "text"),
    ("dpangestuw-http", "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt", "http", "text"),
    ("clarketm", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "http", "text"),
    ("openproxylist", "https://openproxylist.xyz/http.txt", "http", "text"),
    ("spys.me", "https://spys.me/proxy.txt", "http", "text"),
]

# Endpoints that echo the caller's IP; they double as a TLS + CONNECT test.
IP_JUDGES = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
    "https://ifconfig.co/json",
]

PROXY_RE = re.compile(
    r"(?:(?P<scheme>https?|socks4a?|socks5h?)://)?"
    r"(?:(?P<user>[^:@\s/]+):(?P<pw>[^@\s/]+)@)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{2,5})\b",
    re.I,
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
BLOCK_MARKERS = (
    "cf-chl", "challenge-platform", "Just a moment...", "Attention Required!",
    "cf-browser-verification", "captcha", "Access denied", "DDoS protection", "bunkerweb",
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class ToolError(Exception):
    """Fatal, user-facing error."""


class UploadError(Exception):
    """A classified upload/check failure.

    retry        another attempt may succeed
    proxy_fault  the failure is attributable to the proxy (rotate it out)
    fatal        stop trying this host for this file
    """

    def __init__(self, msg: str, *, retry: bool = True, proxy_fault: bool = False, fatal: bool = False):
        super().__init__(msg)
        self.retry = retry and not fatal
        self.proxy_fault = proxy_fault
        self.fatal = fatal


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(ts: Optional[dt.datetime]) -> Optional[str]:
    return ts.isoformat().replace("+00:00", "Z") if ts else None


def parse_iso(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        v = value.strip().replace("Z", "+00:00").replace(" ", "T")
        d = dt.datetime.fromisoformat(v)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def human_size(n: Optional[int]) -> str:
    if n is None:
        return "-"
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdwy]?)\s*$", re.I)


def parse_duration(text: Optional[str]) -> Optional[dt.timedelta]:
    """'90m', '12h', '3d', '2w', '1y' -> timedelta. Bare numbers are hours."""
    if not text:
        return None
    m = DURATION_RE.match(text)
    if not m:
        raise ToolError(f"bad duration {text!r} (examples: 30m, 12h, 3d, 2w)")
    value, unit = float(m.group(1)), (m.group(2) or "h").lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}[unit]
    return dt.timedelta(seconds=value * mult)


def duration_arg(text: str) -> dt.timedelta:
    try:
        td = parse_duration(text)
    except ToolError as exc:
        raise argparse.ArgumentTypeError(str(exc))
    if td is None:
        raise argparse.ArgumentTypeError("empty duration")
    return td


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def looks_blocked(text: str) -> bool:
    head = text[:6000]
    return any(marker.lower() in head.lower() for marker in BLOCK_MARKERS)


def snippet(text: str, n: int = 160) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:n] + ("..." if len(text) > n else "")


def print_table(rows: Sequence[Sequence[Any]], headers: Sequence[str], out=sys.stdout) -> None:
    cells = [[str(h) for h in headers]] + [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    for idx, row in enumerate(cells):
        out.write("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip() + "\n")
        if idx == 0:
            out.write("  ".join("-" * w for w in widths) + "\n")


def random_token(n: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# Media inspection, hashing, metadata stripping
# ---------------------------------------------------------------------------


MIME_EXT = {
    "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp",
    "image/bmp": "bmp", "image/tiff": "tiff", "image/x-icon": "ico", "image/heic": "heic",
    "image/avif": "avif", "image/svg+xml": "svg", "video/mp4": "mp4", "video/quicktime": "mov",
    "video/webm": "webm", "video/x-matroska": "mkv", "video/x-msvideo": "avi", "video/3gpp": "3gp",
    "audio/mpeg": "mp3", "audio/flac": "flac", "audio/wav": "wav", "application/ogg": "ogg",
}
MEDIA_SUFFIXES = {"." + e for e in MIME_EXT.values()} | {".jpeg", ".tif", ".m4v", ".heif", ".jfif"}


def sniff_mime(data: bytes, name: str = "") -> str:
    """Identify media by magic bytes; fall back to the file extension."""
    h = data[:64]
    if h[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return "image/webp"
    if h[:4] == b"RIFF" and h[8:12] == b"AVI ":
        return "video/x-msvideo"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return "audio/wav"
    if h[:2] == b"BM":
        return "image/bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if h[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"avif", b"avis"):
            return "image/avif"
        if brand in (b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"hevc"):
            return "image/heic"
        if brand == b"qt  ":
            return "video/quicktime"
        if brand.startswith(b"3g"):
            return "video/3gpp"
        return "video/mp4"
    if h[:4] == b"\x1aE\xdf\xa3":
        return "video/webm" if b"webm" in data[:256] else "video/x-matroska"
    if h[:4] == b"OggS":
        return "application/ogg"
    if h[:4] == b"fLaC":
        return "audio/flac"
    if h[:3] == b"ID3" or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mpeg"
    text_head = data[:512].lstrip().lower()
    if text_head.startswith(b"<svg") or (text_head.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return "image/svg+xml"
    guess, _ = mimetypes.guess_type(name)
    return guess or "application/octet-stream"


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def dhash(data: bytes, size: int = 8) -> Optional[str]:
    """64-bit difference hash; survives re-encoding/resizing. Needs Pillow."""
    if Image is None:
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.seek(0)
            resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
            small = im.convert("L").resize((size + 1, size), resample)
            px = small.tobytes()
    except Exception:
        return None
    bits = 0
    for row in range(size):
        for col in range(size):
            left = px[row * (size + 1) + col]
            right = px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{size * size // 4}x}"


def hamming_hex(a: Optional[str], b: Optional[str]) -> Optional[int]:
    if not a or not b or len(a) != len(b):
        return None
    return bin(int(a, 16) ^ int(b, 16)).count("1")


STRIPPABLE = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP", "image/tiff": "TIFF", "image/bmp": "BMP"}


def strip_metadata(data: bytes, mime: str) -> Optional[bytes]:
    """Re-save a still image without EXIF/XMP/text chunks (GPS, camera, etc).

    Orientation is baked into the pixels so the image still displays upright.
    Returns None when the format is not strippable (video, animation, svg...).
    """
    if Image is None:
        raise ToolError("--strip-metadata needs Pillow: python -m pip install Pillow")
    fmt = STRIPPABLE.get(mime)
    if not fmt:
        return None
    with Image.open(io.BytesIO(data)) as im:
        if getattr(im, "is_animated", False) and getattr(im, "n_frames", 1) > 1:
            return None
        icc = im.info.get("icc_profile")
        orientation = im.getexif().get(0x0112, 1)
        out = io.BytesIO()
        kwargs: dict[str, Any] = {}
        if icc:
            kwargs["icc_profile"] = icc
        if orientation in (None, 1):
            target = im
            if fmt == "JPEG":
                kwargs["quality"] = "keep"
        else:
            target = ImageOps.exif_transpose(im)
            if fmt == "JPEG":
                kwargs["quality"] = 95
        if fmt == "WEBP":
            kwargs["quality"] = 95
        if fmt == "JPEG" and target.mode not in ("RGB", "L", "CMYK"):
            target = target.convert("RGB")
        target.save(out, format=fmt, **kwargs)
        return out.getvalue()


@dataclasses.dataclass
class MediaFile:
    path: Path
    data: bytes
    mime: str
    upload_name: str
    hashes: dict[str, str]
    dhash: Optional[str]
    original_hashes: Optional[dict[str, str]] = None  # before metadata strip

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def is_image(self) -> bool:
        return self.mime.startswith("image/")

    def describe(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "path": str(self.path),
            "name": self.path.name,
            "upload_name": self.upload_name,
            "size": self.size,
            "mime": self.mime,
            **self.hashes,
        }
        if self.dhash:
            info["dhash"] = self.dhash
        if self.original_hashes:
            info["original"] = self.original_hashes
            info["metadata_stripped"] = True
        return info


def load_media(path: Path, *, strip: bool, keep_name: bool) -> MediaFile:
    data = path.read_bytes()
    if not data:
        raise ToolError(f"{path}: file is empty")
    mime = sniff_mime(data, path.name)
    original = None
    if strip:
        stripped = strip_metadata(data, mime)
        if stripped is None:
            log.warning("%s: metadata stripping not supported for %s, uploading as-is", path.name, mime)
        else:
            original = file_hashes(data)
            original["size"] = str(len(data))
            data = stripped
    ext = MIME_EXT.get(mime) or path.suffix.lstrip(".").lower() or "bin"
    if keep_name:
        name = path.name if path.suffix else f"{path.name}.{ext}"
    else:
        name = f"{random_token(12)}.{ext}"
    return MediaFile(
        path=path,
        data=data,
        mime=mime,
        upload_name=name,
        hashes=file_hashes(data),
        dhash=dhash(data) if mime.startswith("image/") else None,
        original_hashes=original,
    )


def expand_inputs(items: Sequence[str], recursive: bool) -> list[Path]:
    out: list[Path] = []
    for item in items:
        p = Path(item).expanduser()
        if p.is_dir():
            walker = p.rglob("*") if recursive else p.glob("*")
            found = sorted(f for f in walker if f.is_file() and f.suffix.lower() in MEDIA_SUFFIXES)
            if not found:
                log.warning("%s: no media files found%s", p, "" if recursive else " (try --recursive)")
            out.extend(found)
        elif p.is_file():
            out.append(p)
        else:
            raise ToolError(f"input not found: {item}")
    return out


# ---------------------------------------------------------------------------
# Networking: proxies, clients
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Proxy:
    scheme: str  # http | socks4 | socks5
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    source: str = ""
    latency: Optional[float] = None
    exit_ip: Optional[str] = None
    ok: int = 0
    fail: int = 0
    checked_at: float = 0.0
    custom: bool = False
    isolate: bool = False  # Tor: random SOCKS creds per client = new circuit
    rdns: bool = True

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def label(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def url(self) -> str:
        user, pw = self.username, self.password
        if self.isolate:
            user, pw = random_token(8), random_token(8)
        auth = ""
        if user:
            auth = urllib.parse.quote(user, safe="") + ":" + urllib.parse.quote(pw or "", safe="") + "@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def score(self) -> float:
        return (self.latency or 10.0) + self.fail * 4.0 - min(self.ok, 10) * 0.5

    def to_json(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme, "host": self.host, "port": self.port, "source": self.source,
            "latency": self.latency, "exit_ip": self.exit_ip, "ok": self.ok, "fail": self.fail,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Proxy":
        return cls(
            scheme=d["scheme"], host=d["host"], port=int(d["port"]), source=d.get("source", ""),
            latency=d.get("latency"), exit_ip=d.get("exit_ip"), ok=int(d.get("ok", 0)),
            fail=int(d.get("fail", 0)), checked_at=float(d.get("checked_at", 0)),
            rdns=d["scheme"] != "socks4",
        )


def normalize_scheme(scheme: str) -> tuple[str, bool]:
    """Map list/user schemes to (connector scheme, remote DNS)."""
    s = scheme.lower()
    if s in ("http", "https"):
        return "http", True  # "https proxy" in lists = HTTP proxy that supports CONNECT
    if s in ("socks5", "socks5h"):
        return "socks5", True
    if s == "socks4a":
        return "socks4", True
    if s == "socks4":
        return "socks4", False
    raise ToolError(f"unsupported proxy scheme {scheme!r}")


def parse_proxy(text: str, default_scheme: str = "http", source: str = "user") -> Optional[Proxy]:
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    u = urllib.parse.urlsplit(text)
    if not u.hostname or not u.port:
        return None
    scheme, rdns = normalize_scheme(u.scheme)
    return Proxy(
        scheme=scheme, host=u.hostname, port=u.port,
        username=urllib.parse.unquote(u.username) if u.username else None,
        password=urllib.parse.unquote(u.password) if u.password else None,
        source=source, custom=True, rdns=rdns,
    )


def parse_proxy_list(text: str, default_scheme: str, source: str, fmt: str) -> list[Proxy]:
    found: list[Proxy] = []
    if fmt == "geonode":
        try:
            for row in json.loads(text).get("data", []):
                for proto in row.get("protocols") or [default_scheme]:
                    with contextlib.suppress(Exception):
                        scheme, rdns = normalize_scheme(proto)
                        found.append(Proxy(scheme, row["ip"], int(row["port"]), source=source, rdns=rdns))
        except (ValueError, AttributeError):
            pass
        return found
    for m in PROXY_RE.finditer(text):
        port = int(m.group("port"))
        if not 0 < port < 65536:
            continue
        try:
            scheme, rdns = normalize_scheme(m.group("scheme") or default_scheme)
        except ToolError:
            continue
        found.append(Proxy(scheme, m.group("host"), port, source=source, rdns=rdns))
    return found


def build_ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("SSL_CERT_FILE")
    if not cafile:
        with contextlib.suppress(ImportError):
            import certifi  # type: ignore

            cafile = certifi.where()
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    return ctx


class Client:
    """Thin wrapper that routes every request through the chosen proxy."""

    def __init__(self, session: "aiohttp.ClientSession", proxy: Optional[Proxy], http_proxy_url: Optional[str]):
        self.session = session
        self.proxy = proxy
        self._http_proxy_url = http_proxy_url

    @property
    def via(self) -> str:
        return self.proxy.label if self.proxy else "direct"

    def _kw(self, kw: dict[str, Any]) -> dict[str, Any]:
        if self._http_proxy_url:
            kw.setdefault("proxy", self._http_proxy_url)
        return kw

    def get(self, url: str, **kw: Any):
        return self.session.get(url, **self._kw(kw))

    def post(self, url: str, **kw: Any):
        return self.session.post(url, **self._kw(kw))

    def request(self, method: str, url: str, **kw: Any):
        return self.session.request(method, url, **self._kw(kw))


class Net:
    def __init__(self, *, timeout: float, connect_timeout: float, user_agent: Optional[str]):
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.fixed_ua = user_agent
        self.ssl = build_ssl_context()

    def user_agent(self) -> str:
        return self.fixed_ua or random.choice(USER_AGENTS)

    @contextlib.asynccontextmanager
    async def client(self, proxy: Optional[Proxy], *, total: Optional[float] = None, ua: Optional[str] = None):
        timeout = aiohttp.ClientTimeout(total=total or self.timeout, sock_connect=self.connect_timeout)
        headers = {"User-Agent": ua or self.user_agent(), "Accept-Language": "en-US,en;q=0.9"}
        http_proxy_url = None
        if proxy is None:
            connector = aiohttp.TCPConnector(ssl=self.ssl, limit=8)
            trust_env = True  # honour HTTP(S)_PROXY for --direct
        elif proxy.scheme == "http":
            connector = aiohttp.TCPConnector(ssl=self.ssl, limit=8)
            http_proxy_url = proxy.url()
            trust_env = False
        else:
            if ProxyConnector is None:
                raise ToolError("SOCKS proxies need aiohttp-socks: python -m pip install aiohttp-socks")
            connector = ProxyConnector.from_url(proxy.url(), rdns=proxy.rdns, ssl=self.ssl, limit=8)
            trust_env = False
        session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers, trust_env=trust_env,
            cookie_jar=aiohttp.CookieJar(),
        )
        try:
            yield Client(session, proxy, http_proxy_url)
        finally:
            await session.close()


def classify_exception(exc: BaseException, via_proxy: bool) -> UploadError:
    if isinstance(exc, UploadError):
        return exc
    if isinstance(exc, ToolError):
        return UploadError(str(exc), fatal=True)
    cert_err = getattr(aiohttp, "ClientConnectorCertificateError", ())
    if isinstance(exc, cert_err) or isinstance(exc, ssl.SSLCertVerificationError):
        return UploadError("TLS verification failed (proxy may be tampering with traffic)", proxy_fault=via_proxy)
    if isinstance(exc, asyncio.TimeoutError):
        return UploadError("timed out", proxy_fault=via_proxy)
    if isinstance(exc, getattr(aiohttp, "ClientHttpProxyError", ())):
        return UploadError(f"proxy refused CONNECT: {exc}", proxy_fault=True)
    if SOCKS_ERRORS and isinstance(exc, SOCKS_ERRORS):
        return UploadError(f"socks proxy error: {exc}", proxy_fault=True)
    if isinstance(exc, (aiohttp.ClientError, OSError, ssl.SSLError)):
        name = type(exc).__name__
        return UploadError(f"{name}: {exc}".strip(), proxy_fault=via_proxy)
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        return UploadError(f"unexpected response ({type(exc).__name__}: {exc})", proxy_fault=via_proxy)
    return UploadError(f"{type(exc).__name__}: {exc}", fatal=True)


# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ProxySettings:
    mode: str  # free | custom | direct
    custom: list[Proxy]
    protocols: set[str]
    pool_size: int
    test_timeout: float
    test_concurrency: int
    max_test: int
    cache_ttl: float
    use_cache: bool
    leak_check: bool
    allow_direct_fallback: bool
    extra_sources: list[tuple[str, str, str, str]]


class NoProxyAvailable(Exception):
    pass


class ProxyPool:
    def __init__(self, net: Net, cfg: ProxySettings):
        self.net = net
        self.cfg = cfg
        self.good: list[Proxy] = []
        self.bad: dict[str, float] = {}
        self.candidates: Optional[list[Proxy]] = None
        self.real_ip: Optional[str] = None
        self._real_ip_tried = False
        self._lock = asyncio.Lock()
        self._rr = 0
        self.cache_path = CACHE_DIR / "proxies.json"
        if cfg.mode == "free" and cfg.use_cache:
            self._load_cache()

    # -- cache -------------------------------------------------------------

    def _load_cache(self) -> None:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        cutoff = time.time() - self.cfg.cache_ttl
        self.bad = {k: t for k, t in data.get("bad", {}).items() if t > cutoff}
        for d in data.get("good", []):
            with contextlib.suppress(Exception):
                p = Proxy.from_json(d)
                if p.checked_at > cutoff and p.scheme in self.cfg.protocols and p.key not in self.bad:
                    self.good.append(p)
        self.real_ip = data.get("real_ip") if data.get("saved_at", 0) > cutoff else None
        if self.good:
            log.info("loaded %d cached proxies (cache age < %dm)", len(self.good), self.cfg.cache_ttl // 60)

    def save_cache(self) -> None:
        if self.cfg.mode != "free" or not self.cfg.use_cache:
            return
        payload = {
            "saved_at": time.time(),
            "real_ip": self.real_ip,
            "good": [p.to_json() for p in self.good],
            "bad": self.bad,
        }
        with contextlib.suppress(OSError):
            atomic_write(self.cache_path, json.dumps(payload, indent=1))

    # -- discovery ---------------------------------------------------------

    async def _fetch_source(self, name: str, url: str, scheme: str, fmt: str) -> list[Proxy]:
        try:
            async with self.net.client(None, total=25) as c:
                async with c.get(url) as r:
                    if r.status != 200:
                        log.debug("source %s: HTTP %s", name, r.status)
                        return []
                    text = await r.text(errors="replace")
        except Exception as exc:
            log.debug("source %s failed: %s", name, classify_exception(exc, False))
            return []
        proxies = parse_proxy_list(text, scheme, name, fmt)
        log.debug("source %s: %d entries", name, len(proxies))
        return proxies

    async def fetch_candidates(self) -> list[Proxy]:
        sources = FREE_PROXY_SOURCES + self.cfg.extra_sources
        results = await asyncio.gather(*(self._fetch_source(*s) for s in sources))
        per_source: list[list[Proxy]] = []
        seen: set[str] = set(p.key for p in self.good) | set(self.bad)
        total = 0
        for batch in results:
            uniq = []
            for p in batch:
                if p.scheme not in self.cfg.protocols or p.key in seen:
                    continue
                seen.add(p.key)
                uniq.append(p)
            random.shuffle(uniq)
            total += len(uniq)
            per_source.append(uniq)
        # Round-robin across sources so one huge stale list cannot dominate.
        ordered: list[Proxy] = []
        while any(per_source):
            for lst in per_source:
                if lst:
                    ordered.append(lst.pop())
        ordered.reverse()  # refill() pops from the end
        log.info("collected %d unique candidate proxies from %d sources", total, sum(1 for r in results if r))
        return ordered

    async def _detect_real_ip(self) -> None:
        if self._real_ip_tried or not self.cfg.leak_check:
            return
        self._real_ip_tried = True
        if self.real_ip:
            return
        for judge in IP_JUDGES:
            try:
                async with self.net.client(None, total=10) as c:
                    async with c.get(judge) as r:
                        ip = IP_RE.search(await r.text())
                        if ip:
                            self.real_ip = ip.group(0)
                            log.debug("real IP for leak check: %s", self.real_ip)
                            return
            except Exception:
                continue

    async def test_proxy(self, p: Proxy) -> bool:
        judge = random.choice(IP_JUDGES[:2])
        t0 = time.monotonic()
        try:
            async with self.net.client(p, total=self.cfg.test_timeout) as c:
                async with c.get(judge, headers={"Accept": "application/json"}) as r:
                    if r.status != 200:
                        return False
                    body = await r.text()
        except Exception:
            return False
        m = IP_RE.search(body)
        if not m:
            return False
        if self.real_ip and m.group(0) == self.real_ip:
            log.debug("discarding %s: exit IP equals real IP", p.label)
            return False
        p.latency = round(time.monotonic() - t0, 3)
        p.exit_ip = m.group(0)
        p.checked_at = time.time()
        return True

    async def refill(self, want: Optional[int] = None) -> int:
        want = want or self.cfg.pool_size
        await self._detect_real_ip()
        if self.candidates is None:
            self.candidates = await self.fetch_candidates()
        need = max(0, want - len(self.good))
        if need == 0:
            return 0
        tested = 0
        added = 0
        start = time.monotonic()
        queue = self.candidates

        async def worker() -> None:
            nonlocal tested, added
            while queue and added < need and tested < self.cfg.max_test:
                p = queue.pop()
                tested += 1
                if await self.test_proxy(p):
                    self.good.append(p)
                    added += 1
                    log.debug("proxy ok %s (%.2fs, exit %s, %s)", p.label, p.latency, p.exit_ip, p.source)
                else:
                    self.bad[p.key] = time.time()
                if tested % 250 == 0:
                    log.info("  tested %d proxies, %d working ...", tested, added)

        log.info("validating free proxies (need %d, timeout %.0fs, %d parallel) ...", need, self.cfg.test_timeout, self.cfg.test_concurrency)
        await asyncio.gather(*(worker() for _ in range(self.cfg.test_concurrency)))
        log.info("proxy pool: +%d working (%d tested in %.0fs), pool size %d", added, tested, time.monotonic() - start, len(self.good))
        self.save_cache()
        return added

    # -- selection ---------------------------------------------------------

    async def acquire(self) -> Optional[Proxy]:
        if self.cfg.mode == "direct":
            return None
        if self.cfg.mode == "custom":
            live = [p for p in self.cfg.custom if p.key not in self.bad or p.isolate]
            if not live:
                if self.cfg.allow_direct_fallback:
                    return None
                raise NoProxyAvailable("all custom proxies failed")
            self._rr = (self._rr + 1) % len(live)
            return live[self._rr]
        async with self._lock:
            if len(self.good) < max(3, self.cfg.pool_size // 4):
                await self.refill()
            if not self.good:
                if self.cfg.allow_direct_fallback:
                    log.warning("no working free proxy found; falling back to a DIRECT connection")
                    return None
                raise NoProxyAvailable("no working free proxy found (try --pool-size, --proxy-timeout, --protocols or --tor)")
            ranked = sorted(self.good, key=Proxy.score)
            top = ranked[: max(4, len(ranked) // 3)]
            return random.choice(top)

    def release(self, p: Optional[Proxy], ok: bool, *, hard: bool = False) -> None:
        if p is None:
            return
        if ok:
            p.ok += 1
            return
        p.fail += 1
        if p.isolate:  # Tor: a new circuit is used next time anyway
            return
        if p.custom:
            live = [q for q in self.cfg.custom if q.key not in self.bad]
            if not hard and (p.fail < 5 or len(live) <= 1):
                return  # user-supplied proxies get more slack; never drop the last one
        elif not hard and p.fail < 2:
            return
        self.bad[p.key] = time.time()
        if p in self.good:
            self.good.remove(p)
        log.debug("dropped proxy %s", p.label)


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class UploadResult:
    host: str
    url: str
    page_url: Optional[str] = None
    delete_url: Optional[str] = None
    delete_token: Optional[str] = None
    manage_note: Optional[str] = None
    expires_at: Optional[dt.datetime] = None
    remote_hash: Optional[dict[str, str]] = None  # hash reported by the host itself
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class UploadOptions:
    expire: Optional[dt.timedelta]
    nsfw: bool
    secret_urls: bool


async def read_body(resp: "aiohttp.ClientResponse", limit: int = 4 * MiB) -> str:
    raw = bytearray()
    async for chunk in resp.content.iter_chunked(64 * 1024):
        raw.extend(chunk)
        if len(raw) >= limit:
            break
    return bytes(raw).decode(resp.charset or "utf-8", errors="replace")


def check_http(status: int, text: str, via_proxy: bool, host: str) -> None:
    if 200 <= status < 300 and not (via_proxy and looks_blocked(text) and "<html" in text[:500].lower()):
        return
    detail = snippet(text)
    if status == 407:
        raise UploadError("proxy requires authentication", proxy_fault=True)
    if status == 413:
        raise UploadError(f"{host}: file too large (HTTP 413)", fatal=True)
    if looks_blocked(text) or status in (403, 429, 503, 520, 521, 522, 523, 524, 525, 526):
        raise UploadError(f"{host}: blocked/rate-limited (HTTP {status}) {detail}", proxy_fault=via_proxy)
    if status >= 500:
        raise UploadError(f"{host}: server error HTTP {status} {detail}")
    raise UploadError(f"{host}: rejected (HTTP {status}) {detail}", fatal=True)


def media_form(field: str, media: MediaFile, fields: Optional[dict[str, str]] = None) -> "aiohttp.FormData":
    fd = aiohttp.FormData()
    for k, v in (fields or {}).items():
        fd.add_field(k, v)
    fd.add_field(field, media.data, filename=media.upload_name, content_type=media.mime)
    return fd


def upload_timeout(net: Net, media: MediaFile) -> float:
    # Free proxies are slow: allow ~64 KiB/s on top of the base timeout.
    return net.timeout + media.size / (64 * 1024)


class Host:
    name = ""
    label = ""
    site = ""
    max_size: Optional[int] = None
    images_only = False
    temporary = False
    retention = "permanent"
    env_key: Optional[str] = None  # host is only usable when this env var is set
    notes = ""
    check_ua: Optional[str] = None
    download_method = "GET"
    domains: tuple[str, ...] = ()

    def available(self) -> tuple[bool, str]:
        if self.env_key and not os.environ.get(self.env_key):
            return False, f"set {self.env_key}"
        return True, ""

    def accepts(self, media: MediaFile) -> tuple[bool, str]:
        if self.images_only and not media.is_image:
            return False, "images only"
        if self.images_only and media.mime in ("image/svg+xml", "image/heic", "image/x-icon"):
            return False, f"{media.mime} not supported"
        if self.max_size and media.size > self.max_size:
            return False, f"file larger than {human_size(self.max_size)}"
        return True, ""

    def expiry(self, media: MediaFile, opts: UploadOptions) -> Optional[dt.datetime]:
        return None

    async def upload(self, net: Net, c: Client, media: MediaFile, opts: UploadOptions) -> UploadResult:
        raise NotImplementedError

    def soft_removed(self, final_url: str, content_type: str) -> bool:
        """Host-specific 'removed' placeholder detection for liveness checks."""
        return False


def nearest_choice(td: Optional[dt.timedelta], choices: Sequence[tuple[float, Any]], default: Any) -> Any:
    """Pick the smallest option >= requested seconds (or the largest one)."""
    if td is None:
        return default
    secs = td.total_seconds()
    for limit, value in choices:
        if secs <= limit:
            return value
    return choices[-1][1]


class Catbox(Host):
    name, label, site = "catbox", "catbox.moe", "https://catbox.moe"
    max_size = 200 * MiB
    notes = "set CATBOX_USERHASH to own/delete uploads"
    domains = ("catbox.moe",)

    async def upload(self, net, c, media, opts):
        fields = {"reqtype": "fileupload"}
        if os.environ.get("CATBOX_USERHASH"):
            fields["userhash"] = os.environ["CATBOX_USERHASH"]
        async with c.post("https://catbox.moe/user/api.php", data=media_form("fileToUpload", media, fields)) as r:
            text = (await read_body(r)).strip()
            check_http(r.status, text, c.proxy is not None, self.name)
        if not text.startswith("https://"):
            raise UploadError(f"catbox: {snippet(text)}", proxy_fault=c.proxy is not None)
        return UploadResult(self.name, text)


class Litterbox(Host):
    name, label, site = "litterbox", "litterbox.catbox.moe", "https://litterbox.catbox.moe"
    max_size = 1024 * MiB
    temporary = True
    retention = "1h-72h (--expire, default 72h)"
    domains = ("litter.catbox.moe", "litterbox.catbox.moe")
    CHOICES = [(3600, "1h"), (12 * 3600, "12h"), (24 * 3600, "24h"), (72 * 3600, "72h")]

    def expiry(self, media, opts):
        hours = int(nearest_choice(opts.expire, self.CHOICES, "72h")[:-1])
        return now_utc() + dt.timedelta(hours=hours)

    async def upload(self, net, c, media, opts):
        t = nearest_choice(opts.expire, self.CHOICES, "72h")
        fields = {"reqtype": "fileupload", "time": t}
        async with c.post("https://litterbox.catbox.moe/resources/internals/api.php", data=media_form("fileToUpload", media, fields)) as r:
            text = (await read_body(r)).strip()
            check_http(r.status, text, c.proxy is not None, self.name)
        if not text.startswith("https://"):
            raise UploadError(f"litterbox: {snippet(text)}", proxy_fault=c.proxy is not None)
        return UploadResult(self.name, text, expires_at=self.expiry(media, opts))


class ZeroX0(Host):
    name, label, site = "0x0", "0x0.st", "https://0x0.st"
    max_size = 512 * MiB
    retention = "30d-1y by size (--expire to shorten)"
    notes = "blocks many VPN/proxy ranges; returns a delete token"
    domains = ("0x0.st",)

    def expiry(self, media, opts):
        if opts.expire:
            return now_utc() + opts.expire
        min_age, max_age = 30, 365
        days = min_age + (min_age - max_age) * pow(media.size / self.max_size - 1, 3)
        return now_utc() + dt.timedelta(days=days)

    async def upload(self, net, c, media, opts):
        fields: dict[str, str] = {}
        if opts.expire:
            fields["expires"] = str(max(1, int(opts.expire.total_seconds() // 3600)))
        if opts.secret_urls:
            fields["secret"] = ""
        async with c.post("https://0x0.st", data=media_form("file", media, fields)) as r:
            text = (await read_body(r)).strip()
            check_http(r.status, text, c.proxy is not None, self.name)
            token = r.headers.get("X-Token")
        if not text.startswith("http"):
            raise UploadError(f"0x0: {snippet(text)}", proxy_fault=c.proxy is not None)
        note = f"curl -Ftoken={token} -Fdelete= {text}" if token else None
        return UploadResult(self.name, text, delete_token=token, manage_note=note, expires_at=self.expiry(media, opts))


class X0At(Host):
    name, label, site = "x0", "x0.at", "https://x0.at"
    max_size = 1024 * MiB
    retention = "3d-100d by size"
    domains = ("x0.at",)

    def expiry(self, media, opts):
        days = 3 + (100 - 3) * pow(1 - media.size / self.max_size, 2)
        return now_utc() + dt.timedelta(days=days)

    async def upload(self, net, c, media, opts):
        fields = {"id_length": "24"} if opts.secret_urls else {}
        async with c.post("https://x0.at/", data=media_form("file", media, fields)) as r:
            text = (await read_body(r)).strip()
            check_http(r.status, text, c.proxy is not None, self.name)
        if not text.startswith("http"):
            raise UploadError(f"x0: {snippet(text)}", proxy_fault=c.proxy is not None)
        return UploadResult(self.name, text, expires_at=self.expiry(media, opts))


class Pomf(Host):
    """pomf-compatible hosts: POST files[] -> {"success":true,"files":[{"url":..}]}."""

    endpoint = ""
    extra_fields: dict[str, str] = {}

    def fields(self, opts: UploadOptions) -> dict[str, str]:
        return dict(self.extra_fields)

    async def upload(self, net, c, media, opts):
        async with c.post(self.endpoint, data=media_form("files[]", media, self.fields(opts)), headers={"Accept": "application/json"}) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        try:
            data = json.loads(text)
        except ValueError:
            if text.strip().startswith("https://"):
                return UploadResult(self.name, text.strip().splitlines()[0], expires_at=self.expiry(media, opts))
            raise UploadError(f"{self.name}: non-JSON reply {snippet(text)}", proxy_fault=c.proxy is not None)
        if not data.get("success") or not data.get("files"):
            msg = data.get("description") or data.get("error") or snippet(text)
            raise UploadError(f"{self.name}: {msg}", fatal=True)
        f = data["files"][0]
        remote = {"sha1": f["hash"]} if isinstance(f.get("hash"), str) and len(f["hash"]) == 40 else None
        return UploadResult(self.name, f["url"], expires_at=self.expiry(media, opts), remote_hash=remote)


class Uguu(Pomf):
    name, label, site = "uguu", "uguu.se", "https://uguu.se"
    endpoint = "https://uguu.se/upload?output=json"
    max_size = 128 * MiB
    temporary = True
    retention = "3 hours"
    domains = ("uguu.se",)

    def expiry(self, media, opts):
        return now_utc() + dt.timedelta(hours=3)


class QuAx(Pomf):
    name, label, site = "quax", "qu.ax", "https://qu.ax"
    endpoint = "https://qu.ax/upload"
    retention = "1d/7d/30d/365d/never (--expire, default 30d)"
    domains = ("qu.ax",)
    CHOICES = [(86400, "1"), (7 * 86400, "7"), (30 * 86400, "30"), (365 * 86400, "365")]

    def _days(self, opts: UploadOptions) -> str:
        return nearest_choice(opts.expire, self.CHOICES, "30")

    def fields(self, opts):
        return {"expiry": self._days(opts)}

    def expiry(self, media, opts):
        return now_utc() + dt.timedelta(days=int(self._days(opts)))


class LainPomf(Pomf):
    name, label, site = "lain", "pomf.lain.la", "https://pomf.lain.la"
    endpoint = "https://pomf.lain.la/upload.php"
    max_size = 1024 * MiB
    domains = ("pomf.lain.la", "pomf2.lain.la")


class Tmpfiles(Host):
    name, label, site = "tmpfiles", "tmpfiles.org", "https://tmpfiles.org"
    max_size = 100 * MiB
    temporary = True
    retention = "60 minutes"
    domains = ("tmpfiles.org",)

    def expiry(self, media, opts):
        return now_utc() + dt.timedelta(minutes=60)

    async def upload(self, net, c, media, opts):
        async with c.post("https://tmpfiles.org/api/v1/upload", data=media_form("file", media)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        data = json.loads(text)
        page = data.get("data", {}).get("url")
        if data.get("status") != "success" or not page:
            raise UploadError(f"tmpfiles: {snippet(text)}", fatal=True)
        page = re.sub(r"^http://", "https://", page)
        direct = re.sub(r"^(https://tmpfiles\.org)/(?!dl/)", r"\1/dl/", page)
        return UploadResult(self.name, direct, page_url=page, expires_at=self.expiry(media, opts))


class TempSh(Host):
    name, label, site = "tempsh", "temp.sh", "https://temp.sh"
    max_size = 4096 * MiB
    temporary = True
    retention = "3 days"
    download_method = "POST"  # GET shows a download page, POST returns the file
    domains = ("temp.sh",)

    def expiry(self, media, opts):
        return now_utc() + dt.timedelta(days=3)

    async def upload(self, net, c, media, opts):
        async with c.post("https://temp.sh/upload", data=media_form("file", media)) as r:
            text = (await read_body(r)).strip()
            check_http(r.status, text, c.proxy is not None, self.name)
        if not text.startswith("http"):
            raise UploadError(f"temp.sh: {snippet(text)}", proxy_fault=c.proxy is not None)
        return UploadResult(self.name, text, expires_at=self.expiry(media, opts))


class Filebin(Host):
    name, label, site = "filebin", "filebin.net", "https://filebin.net"
    temporary = True
    retention = "6 days"
    notes = "anyone with the bin URL can delete it"
    check_ua = "curl/8.10.1"
    domains = ("filebin.net",)

    def expiry(self, media, opts):
        return now_utc() + dt.timedelta(days=6)

    async def upload(self, net, c, media, opts):
        bin_id = random_token(16)
        url = f"https://filebin.net/{bin_id}/{urllib.parse.quote(media.upload_name)}"
        headers = {"Content-Type": media.mime, "Accept": "application/json", "User-Agent": self.check_ua}
        async with c.post(url, data=media.data, headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        return UploadResult(
            self.name, url, page_url=f"https://filebin.net/{bin_id}",
            manage_note=f"curl -X DELETE {url}", expires_at=self.expiry(media, opts),
        )


class Pixhost(Host):
    name, label, site = "pixhost", "pixhost.cc", "https://pixhost.cc"
    max_size = 10 * MiB
    images_only = True
    notes = "official API v2; supports batch status checks"
    domains = ("pixhost.to", "pixhost.cc", "pixho.st")

    async def upload(self, net, c, media, opts):
        fields = {"content_type": "1" if opts.nsfw else "0", "max_th_size": "420", "include_manage_url": "1"}
        async with c.post("https://api.pixhost.cc/images", data=media_form("img", media, fields), headers={"Accept": "application/json"}) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        data = json.loads(text)
        show, thumb = data.get("show_url"), data.get("th_url")
        if not show:
            raise UploadError(f"pixhost: {snippet(text)}", fatal=True)
        direct = show
        if thumb:
            direct = re.sub(r"//t(\d+)\.", r"//img\1.", thumb).replace("/thumbs/", "/images/")
        return UploadResult(self.name, direct, page_url=show, delete_url=data.get("manage_url"), extra={"thumb_url": thumb})


CHEVERETO_TOKEN_RE = re.compile(r"auth_token\s*=\s*[\"']([0-9a-f]{16,})[\"']", re.I)
CHEVERETO_EXPIRY = [
    (300, "PT5M"), (900, "PT15M"), (1800, "PT30M"), (3600, "PT1H"), (3 * 3600, "PT3H"),
    (6 * 3600, "PT6H"), (12 * 3600, "PT12H"), (86400, "P1D"), (2 * 86400, "P2D"), (3 * 86400, "P3D"),
    (7 * 86400, "P1W"), (14 * 86400, "P2W"), (30 * 86400, "P1M"), (60 * 86400, "P2M"),
    (90 * 86400, "P3M"), (180 * 86400, "P6M"),
]


def chevereto_result(host: str, text: str, via_proxy: bool) -> UploadResult:
    try:
        data = json.loads(text)
    except ValueError:
        raise UploadError(f"{host}: non-JSON reply {snippet(text)}", proxy_fault=via_proxy)
    if int(data.get("status_code", 0)) != 200 or "image" not in data:
        err = data.get("error") or {}
        msg = err.get("message") if isinstance(err, dict) else err
        raise UploadError(f"{host}: {msg or snippet(text)}", fatal=True)
    img = data["image"]
    url = img.get("url") or (img.get("image") or {}).get("url")
    if not url:
        raise UploadError(f"{host}: no URL in reply", fatal=True)
    remote = {"md5": img["md5"]} if isinstance(img.get("md5"), str) and len(img["md5"]) == 32 else None
    return UploadResult(
        host, url, page_url=img.get("url_viewer"), delete_url=img.get("delete_url"),
        expires_at=parse_iso(img.get("expiration_date_gmt")), remote_hash=remote,
    )


class CheveretoWeb(Host):
    """Chevereto-powered sites: fetch homepage for PHPSESSID + auth_token, POST /json."""

    images_only = True

    async def upload(self, net, c, media, opts):
        via = c.proxy is not None
        async with c.get(self.site + "/", headers={"Accept": "text/html"}) as r:
            html = await read_body(r)
            check_http(r.status, html, via, self.name)
        m = CHEVERETO_TOKEN_RE.search(html)
        if not m:
            raise UploadError(f"{self.name}: auth_token not found on page", proxy_fault=via)
        fields = {
            "type": "file", "action": "upload", "timestamp": str(int(time.time() * 1000)),
            "auth_token": m.group(1), "nsfw": "1" if opts.nsfw else "0",
        }
        if opts.expire:
            fields["expiration"] = nearest_choice(opts.expire, CHEVERETO_EXPIRY, "P6M")
        headers = {
            "Accept": "application/json", "Origin": self.site, "Referer": self.site + "/",
            "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        }
        async with c.post(self.site + "/json", data=media_form("source", media, fields), headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, via, self.name)
        return chevereto_result(self.name, text, via)


class ImgBB(CheveretoWeb):
    name, label, site = "imgbb", "imgbb.com", "https://imgbb.com"
    max_size = 32 * 1000 * 1000
    notes = "web flow (no key); set IMGBB_API_KEY to use the official API"
    domains = ("ibb.co", "imgbb.com", "i.ibb.co")

    async def upload(self, net, c, media, opts):
        key = os.environ.get("IMGBB_API_KEY")
        if not key:
            return await super().upload(net, c, media, opts)
        params = {"key": key}
        if opts.expire:
            params["expiration"] = str(int(min(max(opts.expire.total_seconds(), 60), 15552000)))
        async with c.post("https://api.imgbb.com/1/upload", params=params, data=media_form("image", media)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        d = json.loads(text).get("data") or {}
        if not d.get("url"):
            raise UploadError(f"imgbb api: {snippet(text)}", fatal=True)
        exp = None
        if d.get("expiration") and str(d.get("expiration")) != "0" and d.get("time"):
            exp = dt.datetime.fromtimestamp(int(d["time"]) + int(d["expiration"]), dt.timezone.utc)
        return UploadResult(self.name, d["url"], page_url=d.get("url_viewer"), delete_url=d.get("delete_url"), expires_at=exp)


class Freeimage(Host):
    name, label, site = "freeimage", "freeimage.host", "https://freeimage.host"
    max_size = 64 * MiB
    images_only = True
    notes = "public guest API key (override with FREEIMAGE_API_KEY)"
    domains = ("freeimage.host", "iili.io")
    PUBLIC_KEY = "6d207e02198a847aa98d0a2a901485a5"  # published on freeimage.host/page/api

    async def upload(self, net, c, media, opts):
        fields = {"key": os.environ.get("FREEIMAGE_API_KEY", self.PUBLIC_KEY), "action": "upload", "format": "json"}
        async with c.post("https://freeimage.host/api/1/upload", data=media_form("source", media, fields)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        return chevereto_result(self.name, text, c.proxy is not None)


class ImgInTh(CheveretoWeb):
    name, label, site = "imgin", "img.in.th", "https://img.in.th"
    max_size = 50 * MiB
    domains = ("img.in.th",)


class Lensdump(CheveretoWeb):
    name, label, site = "lensdump", "lensdump.com", "https://lensdump.com"
    max_size = 50 * MiB
    notes = "Cloudflare-fronted; many free proxies get challenged"
    domains = ("lensdump.com", "i.lensdump.com")


class Imgur(Host):
    name, label, site = "imgur", "imgur.com", "https://imgur.com"
    max_size = 200 * MiB
    env_key = "IMGUR_CLIENT_ID"
    notes = "official API, needs IMGUR_CLIENT_ID; blocks many proxies"
    domains = ("imgur.com", "i.imgur.com")

    def accepts(self, media):
        if not (media.is_image or media.mime in ("video/mp4", "video/quicktime", "video/webm")):
            return False, "images and mp4/mov/webm only"
        if media.is_image and media.size > 20 * MiB:
            return False, "images larger than 20 MiB"
        return super().accepts(media)

    async def upload(self, net, c, media, opts):
        field = "image" if media.is_image else "video"
        headers = {"Authorization": f"Client-ID {os.environ[self.env_key]}"}
        async with c.post("https://api.imgur.com/3/image", data=media_form(field, media, {"type": "file"}), headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        d = json.loads(text).get("data") or {}
        if not d.get("link"):
            raise UploadError(f"imgur: {snippet(text)}", fatal=True)
        token = d.get("deletehash")
        note = f"curl -X DELETE -H 'Authorization: Client-ID ...' https://api.imgur.com/3/image/{token}" if token else None
        return UploadResult(self.name, d["link"], page_url=f"https://imgur.com/{d.get('id')}", delete_token=token, manage_note=note)

    def soft_removed(self, final_url, content_type):
        return final_url.rstrip("/").endswith("removed.png")


HOSTS: dict[str, Host] = {
    h.name: h
    for h in (
        Catbox(), ImgBB(), Freeimage(), Pixhost(), ImgInTh(), LainPomf(), QuAx(), X0At(), ZeroX0(),
        Lensdump(), Imgur(), Litterbox(), Uguu(), Tmpfiles(), TempSh(), Filebin(),
    )
}
HOST_GROUPS = {
    "permanent": [n for n, h in HOSTS.items() if not h.temporary],
    "temporary": [n for n, h in HOSTS.items() if h.temporary],
    "images": [n for n, h in HOSTS.items() if h.images_only],
    "all": list(HOSTS),
}


def resolve_hosts(spec: str) -> list[Host]:
    names: list[str] = []
    for part in [p.strip().lower() for p in spec.split(",") if p.strip()]:
        if part in HOST_GROUPS:
            names.extend(HOST_GROUPS[part])
        elif part in HOSTS:
            names.append(part)
        else:
            raise ToolError(f"unknown host or group {part!r}; see `hosts`")
    seen: list[str] = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return [HOSTS[n] for n in seen]


def host_for_url(url: str) -> Optional[Host]:
    netloc = urllib.parse.urlsplit(url).netloc.lower()
    for h in HOSTS.values():
        if any(netloc == d or netloc.endswith("." + d) for d in h.domains):
            return h
    return None


# ---------------------------------------------------------------------------
# Manifest (hash file)
# ---------------------------------------------------------------------------


class Manifest:
    def __init__(self, path: Path):
        self.path = path
        self.lock = asyncio.Lock()
        if path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise ToolError(f"{path}: not valid JSON ({exc})")
            if not isinstance(self.data, dict) or "records" not in self.data:
                raise ToolError(f"{path}: not a {TOOL} manifest")
        else:
            self.data = {"tool": TOOL, "schema": MANIFEST_SCHEMA, "created_at": iso(now_utc()), "records": []}

    @property
    def records(self) -> list[dict[str, Any]]:
        return self.data["records"]

    def find(self, sha256: str, host: str) -> Optional[dict[str, Any]]:
        for rec in self.records:
            if rec.get("host") == host and rec.get("file", {}).get("sha256") == sha256 and rec.get("status") not in DEAD_STATES:
                return rec
        return None

    def save(self) -> None:
        self.data["updated_at"] = iso(now_utc())
        atomic_write(self.path, json.dumps(self.data, indent=2, ensure_ascii=False) + "\n")

    async def add(self, rec: dict[str, Any]) -> None:
        async with self.lock:
            self.records.append(rec)
            self.save()


def make_record(media: MediaFile, res: UploadResult, via: str, verify: Optional[dict[str, Any]]) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "host": res.host,
        "url": res.url,
        "page_url": res.page_url,
        "delete_url": res.delete_url,
        "delete_token": res.delete_token,
        "manage": res.manage_note,
        "uploaded_at": iso(now_utc()),
        "expires_at": iso(res.expires_at),
        "via": via,
        "file": media.describe(),
        "host_reported_hash": res.remote_hash,
        "remote": verify,
        "status": (verify or {}).get("status", "uploaded"),
        "last_checked": (verify or {}).get("at"),
        "checks": [verify] if verify else [],
    }
    if res.extra:
        rec["extra"] = res.extra
    return {k: v for k, v in rec.items() if v is not None}


# ---------------------------------------------------------------------------
# Fetch + verify (shared by upload --verify and check)
# ---------------------------------------------------------------------------


DEAD_STATES = {"removed", "expired", "blocked"}
OK_STATES = {"intact", "reencoded", "alive"}


@dataclasses.dataclass
class FetchOutcome:
    http_status: int
    final_url: str
    content_type: str
    size: int
    hashes: Optional[dict[str, str]]
    dhash: Optional[str]
    truncated: bool


async def fetch_and_hash(c: Client, url: str, *, max_bytes: int, quick: bool, ua: Optional[str] = None, method: str = "GET") -> FetchOutcome:
    headers = {"Accept": "*/*"}
    if ua:
        headers["User-Agent"] = ua
    if quick:
        headers["Range"] = "bytes=0-1023"
    async with c.request(method, url, headers=headers, allow_redirects=True) as r:
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
        return FetchOutcome(r.status, str(r.url), ctype, size, hashes, dh, truncated)


def classify(rec: dict[str, Any], out: FetchOutcome, host: Optional[Host], dh_threshold: int) -> tuple[str, str]:
    f = rec.get("file", {})
    expected_mime = f.get("mime", "")
    expires = parse_iso(rec.get("expires_at"))
    past_expiry = bool(expires and now_utc() > expires)
    st = out.http_status
    if st in (404, 410):
        return ("expired" if past_expiry else "removed"), f"HTTP {st}"
    if host and host.soft_removed(out.final_url, out.content_type):
        return ("expired" if past_expiry else "removed"), "host serves its 'removed' placeholder"
    if st == 451:
        return "blocked", "HTTP 451 (legal block)"
    if st in (401, 403):
        return "error", f"HTTP {st} (forbidden; may be the proxy/IP)"
    if st == 429 or st >= 500:
        return "error", f"HTTP {st}"
    if st >= 400:
        return "error", f"HTTP {st}"
    final_path = urllib.parse.urlsplit(out.final_url).path
    if final_path in ("", "/") and urllib.parse.urlsplit(rec.get("url", "")).path not in ("", "/"):
        return ("expired" if past_expiry else "removed"), "redirected to homepage"
    is_html = out.content_type in ("text/html", "application/xhtml+xml")
    if is_html and not expected_mime.startswith("text/"):
        return "alive", "page reachable but serves HTML (not the raw file); content not verified"
    if out.truncated:
        return "alive", f"larger than --max-download; content not verified ({human_size(out.size)}+)"
    if out.hashes is None:
        return "alive", f"HTTP {st} (quick check)"
    remote = rec.get("remote") or {}
    baseline = remote.get("sha256") if remote.get("status") in ("intact", "reencoded", "changed") else None
    if out.hashes["sha256"] == f.get("sha256"):
        return "intact", "byte-identical to the local file"
    if baseline and out.hashes["sha256"] == baseline:
        return "intact", "identical to the copy verified right after upload (host re-encoded on upload)"
    dist = hamming_hex(out.dhash, f.get("dhash"))
    if dist is not None and dist <= dh_threshold:
        return "reencoded", f"bytes differ but image is visually the same (dHash distance {dist})"
    if dist is not None:
        return "changed", f"different image (dHash distance {dist})"
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


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class Engine:
    def __init__(self, net: Net, pool: ProxyPool, retries: int):
        self.net = net
        self.pool = pool
        self.retries = retries

    async def _attempts(self, what: str, fn: Callable[[Client], Any], *, total: Optional[float] = None, ua: Optional[str] = None):
        """Run fn(client) with proxy rotation + exponential backoff."""
        last: Optional[UploadError] = None
        for attempt in range(1, self.retries + 1):
            try:
                proxy = await self.pool.acquire()
            except NoProxyAvailable as exc:
                raise UploadError(str(exc), fatal=True)
            via = proxy.label if proxy else "direct"
            t0 = time.monotonic()
            try:
                async with self.net.client(proxy, total=total, ua=ua) as c:
                    result = await fn(c)
                self.pool.release(proxy, True)
                log.debug("%s ok via %s in %.1fs", what, via, time.monotonic() - t0)
                return result, via
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - classified below
                err = classify_exception(exc, proxy is not None)
                last = err
                if err.proxy_fault:
                    self.pool.release(proxy, False, hard="TLS" in str(err))
                log.info("%s attempt %d/%d via %s failed: %s", what, attempt, self.retries, via, err)
                if not err.retry:
                    break
                await asyncio.sleep(min(8.0, 0.5 * 2 ** (attempt - 1)) + random.random() * 0.5)
        raise last or UploadError(f"{what}: all attempts failed")

    async def upload_one(self, host: Host, media: MediaFile, opts: UploadOptions) -> tuple[UploadResult, str]:
        total = upload_timeout(self.net, media)
        return await self._attempts(f"[{host.name}] {media.path.name}", lambda c: host.upload(self.net, c, media, opts), total=total)

    async def fetch(self, url: str, *, max_bytes: int, quick: bool, host: Optional[Host], label: str) -> tuple[FetchOutcome, str]:
        ua = host.check_ua if host else None
        method = host.download_method if host else "GET"
        return await self._attempts(
            label, lambda c: fetch_and_hash(c, url, max_bytes=max_bytes, quick=quick, ua=ua, method=method),
            total=self.net.timeout + max_bytes / (128 * 1024),
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def verify_upload(engine: Engine, rec_like: dict[str, Any], res: UploadResult, max_bytes: int, dh_threshold: int) -> dict[str, Any]:
    host = HOSTS.get(res.host)
    await asyncio.sleep(1.0)  # let CDNs settle
    try:
        out, via = await engine.fetch(res.url, max_bytes=max_bytes, quick=False, host=host, label=f"[{res.host}] verify")
    except UploadError as exc:
        return {"at": iso(now_utc()), "status": "unverified", "detail": str(exc), "via": "-"}
    status, detail = classify(rec_like, out, host, dh_threshold)
    entry = check_entry(rec_like, out, status, detail, via)
    entry["kind"] = "post-upload-verify"
    return entry


async def cmd_upload(args: argparse.Namespace, engine: Engine) -> int:
    paths = expand_inputs(args.inputs, args.recursive)
    if not paths:
        raise ToolError("nothing to upload")
    hosts = resolve_hosts(args.hosts)
    usable: list[Host] = []
    for h in hosts:
        ok, why = h.available()
        if ok:
            usable.append(h)
        elif args.hosts not in ("permanent", "all", "temporary", "images"):
            log.warning("%s skipped: %s", h.name, why)
    if not usable:
        raise ToolError("no usable hosts selected")
    opts = UploadOptions(expire=args.expire, nsfw=args.nsfw, secret_urls=args.secret_urls)
    manifest = Manifest(Path(args.save_hashes)) if args.save_hashes else None
    want = len(usable) if args.all else max(1, args.mirror)
    sem = asyncio.Semaphore(max(1, args.concurrency))
    results: list[dict[str, Any]] = []
    failures = 0

    async def handle_host(host: Host, media: MediaFile) -> Optional[dict[str, Any]]:
        if manifest and not args.force:
            prev = manifest.find(media.hashes["sha256"], host.name)
            if prev:
                log.info("[%s] %s already uploaded (%s) - use --force to re-upload", host.name, media.path.name, prev["url"])
                return {"host": host.name, "url": prev["url"], "file": str(media.path), "reused": True, "record_id": prev["id"]}
        try:
            res, via = await engine.upload_one(host, media, opts)
        except UploadError as exc:
            log.warning("[%s] %s: giving up: %s", host.name, media.path.name, exc)
            return None
        log.info("[%s] %s -> %s (via %s)", host.name, media.path.name, res.url, via)
        verify = None
        stub = {"url": res.url, "file": media.describe(), "expires_at": iso(res.expires_at)}
        if manifest and not args.no_verify:
            verify = await verify_upload(engine, stub, res, args.max_download * MiB, args.dhash_threshold)
            log.info("[%s] verify: %s - %s", host.name, verify.get("status"), verify.get("detail"))
        out = {
            "host": host.name, "url": res.url, "page_url": res.page_url, "delete_url": res.delete_url,
            "delete_token": res.delete_token, "expires_at": iso(res.expires_at), "file": str(media.path),
            "sha256": media.hashes["sha256"], "via": via,
        }
        if manifest:
            rec = make_record(media, res, via, verify)
            await manifest.add(rec)
            out["record_id"] = rec["id"]
        return {k: v for k, v in out.items() if v is not None}

    async def handle_file(path: Path) -> None:
        nonlocal failures
        async with sem:
            try:
                media = load_media(path, strip=args.strip_metadata, keep_name=args.keep_name)
            except (ToolError, OSError) as exc:
                log.error("%s: %s", path, exc)
                failures += 1
                if not args.json:
                    print(f"FAILED {path}", flush=True)
                return
            eligible = []
            for h in usable:
                ok, why = h.accepts(media)
                if ok:
                    eligible.append(h)
                else:
                    log.debug("[%s] skip %s: %s", h.name, path.name, why)
            if not eligible:
                log.error("%s (%s, %s): no selected host accepts this file", path.name, media.mime, human_size(media.size))
                failures += 1
                if not args.json:
                    print(f"FAILED {path}", flush=True)
                return
            log.info("%s: %s, %s, sha256 %s", path.name, media.mime, human_size(media.size), media.hashes["sha256"][:16])
            done: list[dict[str, Any]] = []
            queue = list(eligible)
            target = min(want, len(eligible))
            while queue and len(done) < target:
                batch = [queue.pop(0) for _ in range(min(target - len(done), len(queue)))]
                for r in await asyncio.gather(*(handle_host(h, media) for h in batch)):
                    if r:
                        done.append(r)
                        if not args.json:
                            print(r["url"], flush=True)
            if not done:
                failures += 1
                if not args.json:
                    print(f"FAILED {path}", flush=True)
            results.extend(done)

    try:
        await asyncio.gather(*(handle_file(p) for p in paths))
    finally:
        engine.pool.save_cache()
    if args.json:
        print(json.dumps({"uploads": results, "failed_files": failures}, indent=2))
    if manifest:
        log.info("hashes saved to %s (%d records)", manifest.path, len(manifest.records))
    return 1 if failures and not results else (3 if failures else 0)


async def pixhost_status(engine: Engine, page_urls: list[str]) -> dict[str, str]:
    """Batch-ask the Pixhost API which show pages still exist."""
    statuses: dict[str, str] = {}
    for i in range(0, len(page_urls), 100):
        chunk = page_urls[i : i + 100]

        async def call(c: Client, chunk=chunk) -> dict[str, Any]:
            async with c.post("https://api.pixhost.cc/images/status", json={"urls": chunk}, headers={"Accept": "application/json"}) as r:
                text = await read_body(r)
                check_http(r.status, text, c.proxy is not None, "pixhost")
                return json.loads(text)

        try:
            data, _ = await engine._attempts("[pixhost] status api", call)
        except UploadError as exc:
            log.warning("pixhost status API failed: %s", exc)
            continue
        for item in data.get("results", []):
            statuses[item.get("url")] = item.get("status")
    return statuses


async def cmd_check(args: argparse.Namespace, engine: Engine) -> int:
    manifest: Optional[Manifest] = None
    records: list[dict[str, Any]] = []
    if args.urls:
        for u in args.urls:
            h = host_for_url(u)
            rec: dict[str, Any] = {"id": "-", "host": h.name if h else urllib.parse.urlsplit(u).netloc, "url": u, "file": {}}
            if args.expect_sha256:
                rec["file"]["sha256"] = args.expect_sha256.lower()
            records.append(rec)
    else:
        path = Path(args.manifest)
        if not path.exists():
            raise ToolError(f"manifest {path} not found (upload with --save-hashes first, or pass URLs)")
        manifest = Manifest(path)
        records = list(manifest.records)
    if args.host:
        wanted = {h.name for h in resolve_hosts(args.host)}
        records = [r for r in records if r.get("host") in wanted]
    if args.status:
        wanted_status = {s.strip() for s in args.status.split(",")}
        records = [r for r in records if r.get("status", "uploaded") in wanted_status]
    if args.id:
        records = [r for r in records if r.get("id") in set(args.id)]
    if not records:
        log.warning("no records to check")
        return 0

    pix_pages = [r["page_url"] for r in records if r.get("host") == "pixhost" and r.get("page_url")]
    pix = await pixhost_status(engine, pix_pages) if pix_pages and not args.no_host_api else {}
    sem = asyncio.Semaphore(max(1, args.concurrency))
    max_bytes = args.max_download * MiB
    rows: list[dict[str, Any]] = []

    async def one(rec: dict[str, Any]) -> None:
        async with sem:
            host = HOSTS.get(rec.get("host", ""))
            api_state = pix.get(rec.get("page_url", "")) if rec.get("host") == "pixhost" else None
            if api_state in ("deleted", "not_found"):
                entry = check_entry(rec, None, "removed", f"pixhost API: {api_state}", "api")
            else:
                url = rec.get("url") or rec.get("page_url")
                try:
                    out, via = await engine.fetch(url, max_bytes=max_bytes, quick=args.quick, host=host, label=f"[{rec.get('host')}] check")
                    status, detail = classify(rec, out, host, args.dhash_threshold)
                    if api_state == "available" and status == "removed":
                        status, detail = "alive", "pixhost API says available; direct file not reachable"
                    entry = check_entry(rec, out, status, detail, via)
                except UploadError as exc:
                    entry = check_entry(rec, None, "error", str(exc), "-")
            prev = rec.get("status")
            rec["status"] = entry["status"]
            rec["last_checked"] = entry["at"]
            if entry["status"] in DEAD_STATES and not rec.get("first_seen_dead"):
                rec["first_seen_dead"] = entry["at"]
            rec.setdefault("checks", []).append(entry)
            rec["checks"] = rec["checks"][-CHECK_HISTORY:]
            rows.append({"id": rec.get("id"), "host": rec.get("host"), "status": entry["status"], "previous": prev, "url": rec.get("url"), "detail": entry["detail"]})
            log.info("[%s] %s %s - %s", rec.get("host"), entry["status"].upper(), rec.get("url"), entry["detail"])
            if manifest and not args.no_update:
                async with manifest.lock:
                    manifest.save()

    try:
        await asyncio.gather(*(one(r) for r in records))
    finally:
        engine.pool.save_cache()
    order = {r.get("url"): i for i, r in enumerate(records)}
    rows.sort(key=lambda r: order.get(r["url"], 0))
    if args.json:
        print(json.dumps({"checked": len(rows), "results": rows}, indent=2))
    else:
        print_table([(r["id"], r["host"], r["status"], r["url"], r["detail"][:70]) for r in rows], ["id", "host", "status", "url", "detail"])
        summary: dict[str, int] = {}
        for r in rows:
            summary[r["status"]] = summary.get(r["status"], 0) + 1
        print("\n" + ", ".join(f"{k}: {v}" for k, v in sorted(summary.items())))
    bad = [r for r in rows if r["status"] in DEAD_STATES or r["status"] == "changed"]
    return 2 if bad else 0


def cmd_list(args: argparse.Namespace) -> int:
    path = Path(args.manifest)
    if not path.exists():
        raise ToolError(f"manifest {path} not found")
    m = Manifest(path)
    recs = m.records
    if args.host:
        wanted = {h.name for h in resolve_hosts(args.host)}
        recs = [r for r in recs if r.get("host") in wanted]
    if args.json:
        print(json.dumps(recs, indent=2, ensure_ascii=False))
        return 0
    cols = ["id", "host", "status", "uploaded_at", "expires_at", "last_checked", "file", "size", "md5", "sha1", "sha256", "dhash", "url", "page_url", "delete_url"]
    flat = []
    for r in recs:
        f = r.get("file", {})
        flat.append({
            "id": r.get("id"), "host": r.get("host"), "status": r.get("status"), "uploaded_at": r.get("uploaded_at"),
            "expires_at": r.get("expires_at"), "last_checked": r.get("last_checked"), "file": f.get("name"),
            "size": f.get("size"), "md5": f.get("md5"), "sha1": f.get("sha1"), "sha256": f.get("sha256"),
            "dhash": f.get("dhash"), "url": r.get("url"), "page_url": r.get("page_url"), "delete_url": r.get("delete_url"),
        })
    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=cols)
        w.writeheader()
        w.writerows(flat)
        return 0
    print_table([(r["id"], r["host"], r["status"], r["file"], (r["sha256"] or "")[:16], r["url"]) for r in flat], ["id", "host", "status", "file", "sha256", "url"])
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    rows = []
    for h in HOSTS.values():
        ok, why = h.available()
        rows.append((
            h.name, h.label, "temp" if h.temporary else "perm", "images" if h.images_only else "any media",
            human_size(h.max_size) if h.max_size else "?", h.retention, "yes" if ok else f"no ({why})", h.notes,
        ))
    print_table(rows, ["name", "site", "type", "accepts", "max", "retention", "usable", "notes"])
    print("\ngroups: " + ", ".join(f"{g} ({len(v)})" for g, v in HOST_GROUPS.items()))
    return 0


async def cmd_proxies(args: argparse.Namespace, engine: Engine) -> int:
    pool = engine.pool
    if pool.cfg.mode != "free":
        raise ToolError("`proxies` works with the free proxy pool (drop --direct/--tor/--proxy)")
    if args.list_sources:
        print_table([(n, s, u) for n, u, s, _ in FREE_PROXY_SOURCES + pool.cfg.extra_sources], ["name", "default", "url"])
        return 0
    if args.refresh:
        pool.good = []
    if args.retest and pool.good:
        log.info("re-testing %d cached proxies ...", len(pool.good))
        results = await asyncio.gather(*(pool.test_proxy(p) for p in pool.good))
        pool.good = [p for p, ok in zip(pool.good, results) if ok]
    await pool.refill(args.count or pool.cfg.pool_size)
    ranked = sorted(pool.good, key=Proxy.score)
    if args.export:
        Path(args.export).write_text("\n".join(p.label for p in ranked) + "\n", encoding="utf-8")
        log.info("exported %d proxies to %s", len(ranked), args.export)
    if args.json:
        print(json.dumps([p.to_json() for p in ranked], indent=2))
    else:
        print_table([(p.label, f"{p.latency:.2f}s" if p.latency else "-", p.exit_ip, p.source, p.ok, p.fail) for p in ranked], ["proxy", "latency", "exit ip", "source", "ok", "fail"])
    return 0 if ranked else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    net = argparse.ArgumentParser(add_help=False)
    g = net.add_argument_group("network / proxy")
    g.add_argument("--direct", action="store_true", help="no proxy (system HTTP(S)_PROXY is still honoured)")
    g.add_argument("--tor", nargs="?", const="127.0.0.1:9050", metavar="HOST:PORT", help="route through Tor SOCKS (new circuit per attempt); default 127.0.0.1:9050")
    g.add_argument("--proxy", action="append", default=[], metavar="URL", help="use your own proxy (http://, socks5://user:pass@...); repeatable")
    g.add_argument("--proxy-file", metavar="FILE", help="file with one proxy per line")
    g.add_argument("--proxy-source", action="append", default=[], metavar="[SCHEME=]URL", help="extra free-proxy list URL, e.g. socks5=https://.../list.txt")
    g.add_argument("--protocols", default=None, help="free proxy protocols to use: http,socks4,socks5 (default: http,socks5 when aiohttp-socks is installed, else http)")
    g.add_argument("--pool-size", type=int, default=20, help="working free proxies to keep (default 20)")
    g.add_argument("--proxy-timeout", type=float, default=8.0, help="seconds per proxy validation (default 8)")
    g.add_argument("--test-concurrency", type=int, default=150, help="parallel proxy validations (default 150)")
    g.add_argument("--max-test", type=int, default=6000, help="max candidates to test per refill (default 6000)")
    g.add_argument("--cache-ttl", type=duration_arg, default=dt.timedelta(minutes=30), help="reuse validated proxies for this long (default 30m)")
    g.add_argument("--no-cache", action="store_true", help="ignore and do not write the proxy cache")
    g.add_argument("--no-leak-check", action="store_true", help="skip discarding proxies whose exit IP equals yours")
    g.add_argument("--allow-direct-fallback", action="store_true", help="go direct when no proxy works (off by default)")
    g.add_argument("--timeout", type=float, default=45.0, help="base request timeout in seconds (default 45)")
    g.add_argument("--connect-timeout", type=float, default=12.0, help="TCP/proxy connect timeout (default 12)")
    g.add_argument("--retries", type=int, default=6, help="attempts per host / per check, rotating proxies (default 6)")
    g.add_argument("--user-agent", help="fixed User-Agent instead of rotating")
    g.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    g.add_argument("-q", "--quiet", action="store_true", help="only errors on stderr")

    p = argparse.ArgumentParser(
        prog="media_drop.py",
        description="Upload media to free hosts through rotating free proxies, save per-host hashes, and check links later.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
        "  media_drop.py upload cat.jpg\n"
        "  media_drop.py upload cat.jpg --all --save-hashes\n"
        "  media_drop.py upload ./pics -r --hosts catbox,imgbb,pixhost --mirror 2 --strip-metadata --save-hashes my.json\n"
        "  media_drop.py check --manifest my.json\n"
        "  media_drop.py check https://files.catbox.moe/abc123.jpg --expect-sha256 <hash> --direct\n"
        "  media_drop.py proxies --count 40 --export good.txt\n",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("upload", parents=[net], help="upload files")
    up.add_argument("inputs", nargs="+", help="files or directories")
    up.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    up.add_argument("--hosts", default="permanent", help="comma list of hosts/groups (permanent, temporary, images, all); order = failover order (default: permanent)")
    up.add_argument("--mirror", type=int, default=1, help="upload each file to N different hosts (default 1 = first that works)")
    up.add_argument("--all", action="store_true", help="upload each file to every selected host")
    up.add_argument("--save-hashes", nargs="?", const=DEFAULT_MANIFEST, metavar="FILE", help=f"record hashes + URLs per host into a manifest (default {DEFAULT_MANIFEST})")
    up.add_argument("--no-verify", action="store_true", help="with --save-hashes: skip re-downloading to record the hosted copy's hash")
    up.add_argument("--force", action="store_true", help="re-upload even if the manifest has a live copy on that host")
    up.add_argument("--strip-metadata", action="store_true", help="remove EXIF/GPS/XMP from still images before upload (needs Pillow)")
    up.add_argument("--keep-name", action="store_true", help="keep the original filename (default: random name)")
    up.add_argument("--expire", type=duration_arg, metavar="DURATION", help="ask hosts that support it to delete after e.g. 1h, 3d, 30d")
    up.add_argument("--secret-urls", action="store_true", help="longer unguessable URLs where supported (0x0, x0)")
    up.add_argument("--nsfw", action="store_true", help="flag content as adult on hosts that require it")
    up.add_argument("--concurrency", type=int, default=3, help="files uploaded in parallel (default 3)")
    up.add_argument("--max-download", type=int, default=64, metavar="MiB", help="verify downloads up to this size (default 64)")
    up.add_argument("--dhash-threshold", type=int, default=6, help="max dHash bit distance counted as 'same image' (default 6)")
    up.add_argument("--json", action="store_true", help="JSON output on stdout")

    ck = sub.add_parser("check", parents=[net], help="check uploaded media is still online and unmodified")
    ck.add_argument("urls", nargs="*", help="ad-hoc URLs instead of a manifest")
    ck.add_argument("--manifest", default=DEFAULT_MANIFEST, help=f"manifest to check and update (default {DEFAULT_MANIFEST})")
    ck.add_argument("--expect-sha256", help="for ad-hoc URLs: expected SHA-256")
    ck.add_argument("--host", help="only these hosts/groups")
    ck.add_argument("--status", help="only records whose last status is in this comma list (e.g. intact,alive,error)")
    ck.add_argument("--id", action="append", help="only this record id (repeatable)")
    ck.add_argument("--quick", action="store_true", help="status-only check (first 1 KiB), no hash comparison")
    ck.add_argument("--no-update", action="store_true", help="do not write results back to the manifest")
    ck.add_argument("--no-host-api", action="store_true", help="skip host status APIs (pixhost)")
    ck.add_argument("--concurrency", type=int, default=6, help="parallel checks (default 6)")
    ck.add_argument("--max-download", type=int, default=64, metavar="MiB", help="hash files up to this size (default 64)")
    ck.add_argument("--dhash-threshold", type=int, default=6, help="max dHash bit distance counted as 'same image' (default 6)")
    ck.add_argument("--json", action="store_true", help="JSON output on stdout")

    ls = sub.add_parser("list", help="show manifest records")
    ls.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ls.add_argument("--host", help="only these hosts/groups")
    out = ls.add_mutually_exclusive_group()
    out.add_argument("--csv", action="store_true", help="CSV with all hashes on stdout")
    out.add_argument("--json", action="store_true", help="raw JSON records")
    ls.add_argument("-v", "--verbose", action="count", default=0)
    ls.add_argument("-q", "--quiet", action="store_true")

    hs = sub.add_parser("hosts", help="list supported hosts")
    hs.add_argument("-v", "--verbose", action="count", default=0)
    hs.add_argument("-q", "--quiet", action="store_true")

    px = sub.add_parser("proxies", parents=[net], help="fetch/validate/export the free proxy pool")
    px.add_argument("--count", type=int, help="how many working proxies to find (default --pool-size)")
    px.add_argument("--refresh", action="store_true", help="ignore cached proxies and validate fresh ones")
    px.add_argument("--retest", action="store_true", help="re-test cached proxies before topping up")
    px.add_argument("--export", metavar="FILE", help="write working proxies, one per line")
    px.add_argument("--list-sources", action="store_true", help="show the built-in proxy list sources")
    px.add_argument("--json", action="store_true", help="JSON output on stdout")
    return p


def proxy_settings(args: argparse.Namespace) -> ProxySettings:
    custom: list[Proxy] = []
    for item in args.proxy:
        p = parse_proxy(item)
        if not p:
            raise ToolError(f"bad --proxy {item!r}")
        custom.append(p)
    if args.proxy_file:
        for line in Path(args.proxy_file).read_text(encoding="utf-8").splitlines():
            p = parse_proxy(line, source=Path(args.proxy_file).name)
            if p:
                custom.append(p)
        if not custom:
            raise ToolError(f"{args.proxy_file}: no proxies found")
    if args.tor:
        host, _, port = args.tor.rpartition(":")
        tor = Proxy("socks5", host or "127.0.0.1", int(port), source="tor", custom=True, isolate=True, rdns=True)
        custom.append(tor)
    if custom and args.direct:
        raise ToolError("--direct cannot be combined with --proxy/--proxy-file/--tor")
    if any(p.scheme != "http" for p in custom) and ProxyConnector is None:
        raise ToolError("SOCKS/Tor needs aiohttp-socks: python -m pip install aiohttp-socks")
    if args.protocols:
        protocols = {normalize_scheme(s.strip())[0] for s in args.protocols.split(",") if s.strip()}
    else:
        protocols = {"http", "socks5"} if ProxyConnector is not None else {"http"}
    if protocols - {"http"} and ProxyConnector is None:
        log.warning("aiohttp-socks not installed; ignoring socks protocols")
        protocols = {"http"}
    extra = []
    for i, src in enumerate(args.proxy_source):
        scheme, sep, url = src.partition("=")
        if not sep or scheme.startswith("http"):
            scheme, url = "http", src
        extra.append((f"custom-{i + 1}", url, normalize_scheme(scheme)[0], "text"))
    mode = "direct" if args.direct else ("custom" if custom else "free")
    return ProxySettings(
        mode=mode, custom=custom, protocols=protocols, pool_size=max(1, args.pool_size),
        test_timeout=args.proxy_timeout, test_concurrency=max(1, args.test_concurrency), max_test=max(1, args.max_test),
        cache_ttl=args.cache_ttl.total_seconds(), use_cache=not args.no_cache, leak_check=not args.no_leak_check,
        allow_direct_fallback=args.allow_direct_fallback, extra_sources=extra,
    )


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose >= 2 else logging.INFO)
    if args.verbose == 0 and not args.quiet and getattr(args, "json", False):
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


async def run(args: argparse.Namespace) -> int:
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "hosts":
        return cmd_hosts(args)
    if aiohttp is None:
        raise ToolError("aiohttp is required: python -m pip install aiohttp aiohttp-socks Pillow")
    net = Net(timeout=args.timeout, connect_timeout=args.connect_timeout, user_agent=args.user_agent)
    cfg = proxy_settings(args)
    pool = ProxyPool(net, cfg)
    engine = Engine(net, pool, max(1, args.retries))
    if cfg.mode == "direct":
        log.info("mode: direct connection (no proxy)")
    elif cfg.mode == "custom":
        log.info("mode: custom proxies (%s)", ", ".join(p.label for p in cfg.custom))
    else:
        log.info("mode: free proxy pool (%s)", ",".join(sorted(cfg.protocols)))
    if args.cmd == "upload":
        return await cmd_upload(args, engine)
    if args.cmd == "check":
        return await cmd_check(args, engine)
    if args.cmd == "proxies":
        return await cmd_proxies(args, engine)
    raise ToolError(f"unknown command {args.cmd}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args)
    try:
        return asyncio.run(run(args))
    except ToolError as exc:
        log.error("error: %s", exc)
        return 1
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
