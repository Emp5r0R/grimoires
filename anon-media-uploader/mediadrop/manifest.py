"""Hash manifest (JSON) and plain link list (TSV)."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, Optional

from .hosts import UploadResult
from .media import Payload
from .util import ToolError, atomic_write, iso, now_utc

TOOL = "media_drop"
MANIFEST_SCHEMA = 2
DEAD = {"removed", "expired", "blocked"}


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

    def find(self, source_sha256: str, host: str) -> Optional[dict[str, Any]]:
        """A live record of the same source file on the same host."""
        for rec in self.records:
            f = rec.get("file", {})
            src = (f.get("original") or {}).get("sha256") or f.get("sha256")
            if rec.get("host") == host and src == source_sha256 and rec.get("status") not in DEAD:
                return rec
        return None

    def by_uploaded_sha256(self, sha256: str) -> Optional[dict[str, Any]]:
        for rec in self.records:
            if rec.get("file", {}).get("sha256") == sha256:
                return rec
        return None

    def save(self) -> None:
        self.data["updated_at"] = iso(now_utc())
        self.data["schema"] = MANIFEST_SCHEMA
        atomic_write(self.path, json.dumps(self.data, indent=2, ensure_ascii=False) + "\n")

    async def add(self, rec: dict[str, Any]) -> None:
        async with self.lock:
            self.records.append(rec)
            self.save()


def make_record(kind: str, payload: Payload, res: UploadResult, via: str, verify: Optional[dict[str, Any]],
                host_hash_ok: Optional[bool]) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "kind": kind,
        "host": res.host,
        "url": res.url,
        "page_url": res.page_url,
        "delete_url": res.delete_url,
        "delete_token": res.delete_token,
        "manage": res.manage_note,
        "uploaded_at": iso(now_utc()),
        "expires_at": iso(res.expires_at),
        "via": via,
        "file": payload.describe(),
        "host_reported_hash": res.remote_hash,
        "host_hash_match": host_hash_ok,
        "remote": verify,
        "status": (verify or {}).get("status", "uploaded"),
        "last_checked": (verify or {}).get("at"),
        "checks": [verify] if verify else [],
    }
    if res.extra:
        rec["extra"] = res.extra
    return {k: v for k, v in rec.items() if v is not None}


class LinkWriter:
    """Append uploaded links to a simple tab-separated text file."""

    HEADER = "# uploaded_at\tfile\thost\turl\texpires_at\tsha256\tdelete\n"

    def __init__(self, path: Path):
        self.path = path
        self.lock = asyncio.Lock()

    async def add(self, payload: Payload, res: UploadResult) -> None:
        delete = res.delete_url or res.manage_note or ""
        row = [iso(now_utc()) or "", payload.path.name, res.host, res.url, iso(res.expires_at) or "never/unknown",
               payload.hashes["sha256"], delete]
        async with self.lock:
            new = not self.path.exists() or self.path.stat().st_size == 0
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                if new:
                    fh.write(self.HEADER)
                fh.write("\t".join(c.replace("\t", " ") for c in row) + "\n")
