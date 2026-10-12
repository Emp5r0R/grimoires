"""Proxies as values, HTTP clients that route through them, error classification."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import random
import re
import ssl
import urllib.parse
from typing import Any, Optional

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

from .util import ToolError, UploadError, random_token

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

PROXY_RE = re.compile(
    r"(?:(?P<scheme>https?|socks4a?|socks5h?)://)?"
    r"(?:(?P<user>[^:@\s/]+):(?P<pw>[^@\s/]+)@)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{2,5})\b",
    re.I,
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)


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
