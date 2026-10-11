"""Upload service shared by the `upload` (images/media) and `file` commands."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from pathlib import Path
from typing import Any, Optional

from .checker import check_entry, classify, host_hash_matches
from .engine import Engine
from .hosts import Host, UploadOptions, UploadResult
from .manifest import LinkWriter, Manifest, make_record
from .media import Payload, build_payload, variant
from .selection import HostSelector
from .util import MiB, ToolError, UploadError, human_size, iso, now_utc

log = logging.getLogger("media_drop")


@dataclasses.dataclass
class UploadSettings:
    kind: str  # "image" | "file"
    mirrors: int
    all_hosts: bool
    opts: UploadOptions
    hash_mode: str = "none"
    unique_per_host: bool = False
    strip: bool = False
    keep_name: bool = False
    verify: bool = True
    force: bool = False
    max_download: int = 64 * MiB
    dh_threshold: int = 6
    concurrency: int = 3
    quiet_stdout: bool = False  # JSON mode: no per-link lines


class UploadService:
    def __init__(self, engine: Engine, selector: HostSelector, settings: UploadSettings,
                 manifest: Optional[Manifest] = None, links: Optional[LinkWriter] = None):
        self.engine = engine
        self.selector = selector
        self.s = settings
        self.manifest = manifest
        self.links = links
        self.results: list[dict[str, Any]] = []
        self.failures = 0

    # -- per host ------------------------------------------------------------

    async def _verify(self, host: Host, payload: Payload, res: UploadResult) -> tuple[Optional[dict[str, Any]], Optional[bool]]:
        host_ok = host_hash_matches(res.remote_hash, payload.hashes)
        if host_ok is False:
            log.warning("[%s] host reported a different hash than what was sent!", host.name)
        if not self.s.verify:
            return None, host_ok
        stub = {"url": res.url, "page_url": res.page_url, "extra": res.extra, "file": payload.describe(), "expires_at": iso(res.expires_at)}
        await asyncio.sleep(1.0)  # let CDNs settle
        try:
            out, via = await self.engine.probe(host, stub, max_bytes=self.s.max_download, label=f"[{host.name}] verify")
        except UploadError as exc:
            return {"at": iso(now_utc()), "status": "unverified", "detail": str(exc), "via": "-", "kind": "post-upload-verify"}, host_ok
        status, detail = classify(stub, out, host, self.s.dh_threshold)
        if status == "alive" and host_ok:
            status, detail = "intact", f"host-reported {next(iter(res.remote_hash))} matches; {detail}"
        entry = check_entry(stub, out, status, detail, via)
        entry["kind"] = "post-upload-verify"
        return entry, host_ok

    async def _one_host(self, host: Host, base: Payload, shared: Payload) -> Optional[dict[str, Any]]:
        source_sha = (base.original or base.hashes)["sha256"]
        if self.manifest and not self.s.force:
            prev = self.manifest.find(source_sha, host.name)
            if prev:
                log.info("[%s] %s already uploaded (%s) - use --force to re-upload", host.name, base.path.name, prev["url"])
                return {"host": host.name, "url": prev["url"], "file": str(base.path), "reused": True, "record_id": prev["id"]}
        payload = variant(base, self.s.hash_mode, rename=not self.s.keep_name) if self.s.unique_per_host else shared
        try:
            res, via = await self.engine.upload(host, payload, self.s.opts)
        except UploadError as exc:
            log.warning("[%s] %s: giving up: %s", host.name, base.path.name, exc)
            return None
        log.info("[%s] %s -> %s (via %s)", host.name, base.path.name, res.url, via)
        verify, host_ok = await self._verify(host, payload, res)
        if verify:
            log.info("[%s] verify: %s - %s", host.name, verify.get("status"), verify.get("detail"))
        out = {
            "host": host.name, "url": res.url, "page_url": res.page_url, "delete_url": res.delete_url,
            "delete_token": res.delete_token, "expires_at": iso(res.expires_at), "file": str(base.path),
            "sha256": payload.hashes["sha256"], "original_sha256": (payload.original or {}).get("sha256"),
            "hash_change": (payload.hash_change or {}).get("method"), "via": via,
            "verified": (verify or {}).get("status"),
        }
        if self.manifest:
            rec = make_record(self.s.kind, payload, res, via, verify, host_ok)
            await self.manifest.add(rec)
            out["record_id"] = rec["id"]
        if self.links:
            await self.links.add(payload, res)
        if not self.s.quiet_stdout:
            print(res.url, flush=True)
        return {k: v for k, v in out.items() if v is not None}

    # -- per file ------------------------------------------------------------

    def _fail(self, path: Path) -> None:
        self.failures += 1
        if not self.s.quiet_stdout:
            print(f"FAILED {path}", flush=True)

    async def _one_file(self, path: Path, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                base = build_payload(path, strip=self.s.strip, keep_name=self.s.keep_name)
                shared = variant(base, self.s.hash_mode)
            except (ToolError, OSError) as exc:
                log.error("%s: %s", path, exc)
                return self._fail(path)
            hosts = self.selector.rank(shared)
            if not hosts:
                log.error("%s (%s, %s): no selected host accepts this file with these options", path.name, shared.mime, human_size(shared.size))
                return self._fail(path)
            change = f", hash changed via {shared.hash_change['method']}" if shared.hash_change else ""
            log.info("%s: %s, %s, sha256 %s%s", path.name, shared.mime, human_size(shared.size), shared.hashes["sha256"][:16], change)
            target = len(hosts) if self.s.all_hosts else min(max(1, self.s.mirrors), len(hosts))
            done: list[dict[str, Any]] = []
            queue = list(hosts)
            while queue and len(done) < target:
                batch = [queue.pop(0) for _ in range(min(target - len(done), len(queue)))]
                for r in await asyncio.gather(*(self._one_host(h, base, shared) for h in batch)):
                    if r:
                        done.append(r)
                        if r.get("reused") and not self.s.quiet_stdout:
                            print(r["url"], flush=True)
            if not done:
                return self._fail(path)
            if len(done) < target:
                log.warning("%s: only %d of %d mirrors succeeded", path.name, len(done), target)
            self.results.extend(done)

    async def run(self, paths: list[Path]) -> tuple[list[dict[str, Any]], int]:
        sem = asyncio.Semaphore(max(1, self.s.concurrency))
        await asyncio.gather(*(self._one_file(p, sem) for p in paths))
        return self.results, self.failures
