"""Retry engine: run a network action with proxy rotation and backoff."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Awaitable, Callable, Optional

from .checker import FetchOutcome, fetch_and_hash
from .hosts import Host, UploadOptions, UploadResult
from .media import Payload
from .net import Client, Net, classify_exception
from .proxies import NoProxyAvailable, ProxyPool
from .util import MiB, UploadError

log = logging.getLogger("media_drop")


class Engine:
    def __init__(self, net: Net, pool: ProxyPool, retries: int):
        self.net = net
        self.pool = pool
        self.retries = retries

    async def attempts(self, what: str, fn: Callable[[Client], Awaitable[Any]], *, total: Optional[float] = None,
                       ua: Optional[str] = None) -> tuple[Any, str]:
        """Run fn(client) up to `retries` times; returns (result, via)."""
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

    async def upload(self, host: Host, payload: Payload, opts: UploadOptions) -> tuple[UploadResult, str]:
        # Free proxies are slow: allow ~64 KiB/s on top of the base timeout.
        total = self.net.timeout + payload.size / (64 * 1024)
        return await self.attempts(f"[{host.name}] {payload.path.name}", lambda c: host.upload(self.net, c, payload, opts), total=total)

    async def fetch(self, url: str, *, max_bytes: int, quick: bool, host: Optional[Host], label: str,
                    method: Optional[str] = None, follow: bool = True) -> tuple[FetchOutcome, str]:
        ua = host.check_ua if host else None
        method = method or (host.download_method if host else "GET")
        return await self.attempts(
            label, lambda c: fetch_and_hash(c, url, max_bytes=max_bytes, quick=quick, ua=ua, method=method, follow=follow),
            total=self.net.timeout + max_bytes / (128 * 1024),
        )

    async def probe(self, host: Optional[Host], rec: dict[str, Any], *, max_bytes: int = 64 * MiB, quick: bool = False,
                    label: str = "check") -> tuple[FetchOutcome, str]:
        if host:
            url, method, follow = host.probe_target(rec)
        else:
            url, method, follow = rec.get("url"), "GET", True
        return await self.fetch(url, max_bytes=max_bytes, quick=quick, host=host, label=label, method=method, follow=follow)
