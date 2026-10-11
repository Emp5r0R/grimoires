"""Free proxy discovery, validation, caching and rotation."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import time
from pathlib import Path
from typing import Optional

from .net import IP_RE, Net, Proxy, classify_exception, parse_proxy_list
from .util import atomic_write

log = logging.getLogger("media_drop")
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "media-drop"

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
