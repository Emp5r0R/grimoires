"""Host interface, registry and shared upload helpers.

A host is one class. To add one: subclass Host, implement upload(), decorate
with @register. Optional hooks (lifetime, probe_target, interpret,
batch_status) let a host refine retention estimates and liveness checks
without touching the engine, the checker or the CLI.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
from typing import TYPE_CHECKING, Any, Optional, Sequence

try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None  # type: ignore

from ..util import MiB, UploadError, human_size, looks_blocked, now_utc, snippet, uploads_disabled

if TYPE_CHECKING:
    from ..media import Payload
    from ..net import Client, Net


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
    expire: Optional[dt.timedelta] = None
    nsfw: bool = False
    secret_urls: bool = False


class Host:
    name = ""
    label = ""
    site = ""
    max_size: Optional[int] = None
    images_only = False
    accepts_label = ""
    temporary = False
    retention = "permanent"
    env_key: Optional[str] = None  # host is only usable when this env var is set
    disabled: Optional[str] = None  # reason, when the site currently refuses uploads
    upload_ua: Optional[str] = None  # fixed User-Agent for uploads (some APIs reject browsers)
    notes = ""
    check_ua: Optional[str] = None
    download_method = "GET"
    domains: tuple[str, ...] = ()

    # -- capability / policy -------------------------------------------------

    def available(self) -> tuple[bool, str]:
        if self.disabled and not os.environ.get(f"MEDIA_DROP_ENABLE_{self.name.upper()}"):
            return False, f"disabled: {self.disabled}"
        if self.env_key and not os.environ.get(self.env_key):
            return False, f"set {self.env_key}"
        return True, ""

    def accepts(self, payload: "Payload") -> tuple[bool, str]:
        if self.images_only and not payload.is_image:
            return False, "images only"
        if self.images_only and payload.mime in ("image/svg+xml", "image/heic", "image/x-icon"):
            return False, f"{payload.mime} not supported"
        if self.max_size and payload.size > self.max_size:
            return False, f"file larger than {human_size(self.max_size)}"
        return True, ""

    def lifetime(self, size: int, opts: UploadOptions) -> Optional[dt.timedelta]:
        """Expected lifetime of a file this size; None = permanent / no fixed expiry."""
        return None

    def expiry(self, payload: "Payload", opts: UploadOptions) -> Optional[dt.datetime]:
        life = self.lifetime(payload.size, opts)
        return now_utc() + life if life else None

    # -- upload ----------------------------------------------------------------

    async def upload(self, net: "Net", c: "Client", payload: "Payload", opts: UploadOptions) -> UploadResult:
        raise NotImplementedError

    # -- liveness checks -------------------------------------------------------

    def probe_target(self, rec: dict[str, Any]) -> tuple[str, str, bool]:
        """(url, method, follow_redirects) used to check a record."""
        return rec.get("url") or rec.get("page_url"), self.download_method, True

    def interpret(self, rec: dict[str, Any], out: Any) -> Optional[tuple[str, str]]:
        """Host-specific verdict for a fetch outcome, or None for the generic one."""
        return None

    def soft_removed(self, final_url: str, content_type: str) -> bool:
        """Host-specific 'removed' placeholder detection."""
        return False

    async def batch_status(self, engine: Any, recs: Sequence[dict[str, Any]]) -> dict[str, tuple[str, str]]:
        """Optional bulk status API: record id -> (status, detail)."""
        return {}


REGISTRY: dict[str, Host] = {}


def register(cls):
    REGISTRY[cls.name] = cls()
    return cls


# -- helpers shared by host implementations ------------------------------------


async def read_body(resp: "aiohttp.ClientResponse", limit: int = 4 * MiB) -> str:
    raw = bytearray()
    async for chunk in resp.content.iter_chunked(64 * 1024):
        raw.extend(chunk)
        if len(raw) >= limit:
            break
    return bytes(raw).decode(resp.charset or "utf-8", errors="replace")


def check_http(status: int, text: str, via_proxy: bool, host: str) -> None:
    if 200 <= status < 300 and not (looks_blocked(text, strict=True) and "<html" in text[:500].lower()):
        return
    detail = snippet(text)
    if uploads_disabled(text):
        raise UploadError(f"{host}: the site has disabled uploads ({detail})", fatal=True)
    if status == 407:
        raise UploadError("proxy requires authentication", proxy_fault=True)
    if status == 413:
        raise UploadError(f"{host}: file too large (HTTP 413)", fatal=True)
    if status in (401, 412) and via_proxy:  # e.g. catbox "Invalid uploader": the proxy IP is banned
        raise UploadError(f"{host}: refused this IP (HTTP {status}) {detail}", proxy_fault=True)
    if looks_blocked(text) or status in (403, 429, 503, 520, 521, 522, 523, 524, 525, 526):
        raise UploadError(f"{host}: blocked/rate-limited (HTTP {status}) {detail}", proxy_fault=via_proxy)
    if status >= 500:
        raise UploadError(f"{host}: server error HTTP {status} {detail}")
    raise UploadError(f"{host}: rejected (HTTP {status}) {detail}", fatal=True)


def form(field: str, payload: "Payload", fields: Optional[dict[str, str]] = None) -> "aiohttp.FormData":
    fd = aiohttp.FormData()
    for k, v in (fields or {}).items():
        fd.add_field(k, v)
    fd.add_field(field, payload.data, filename=payload.upload_name, content_type=payload.mime)
    return fd


def nearest_choice(td: Optional[dt.timedelta], choices: Sequence[tuple[float, Any]], default: Any) -> Any:
    """Pick the smallest option >= requested seconds (or the largest one)."""
    if td is None:
        return default
    secs = td.total_seconds()
    for limit, value in choices:
        if secs <= limit:
            return value
    return choices[-1][1]


async def text_upload(c: "Client", host: str, method: str, url: str, **kw: Any) -> tuple[str, Any]:
    """Upload where the host answers with a bare URL; returns (url, headers)."""
    async with c.request(method, url, **kw) as r:
        text = (await read_body(r)).strip()
        check_http(r.status, text, c.proxy is not None, host)
        headers = r.headers
    first = text.splitlines()[0].strip() if text else ""
    if not first.startswith("http"):
        raise UploadError(f"{host}: {snippet(text)}", proxy_fault=c.proxy is not None)
    return first, headers
