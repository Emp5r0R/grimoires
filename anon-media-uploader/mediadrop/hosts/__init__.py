"""Host registry, groups and lookup."""

from __future__ import annotations

import urllib.parse
from typing import Optional

from ..util import ToolError
from . import file_hosts, image_hosts
from .base import REGISTRY, Host, UploadOptions, UploadResult

_REGISTERED_BY_IMPORT = (file_hosts, image_hosts)

# Default failover order (most reliable / longest-lived first).
ORDER = [
    "catbox", "imgbb", "freeimage", "pixhost", "imgin", "lain", "quax", "x0", "0x0", "cnet",
    "gofile", "lensdump", "imgur", "pixeldrain",
    "litterbox", "tempsh", "tmpfilelink", "filebin", "uguu", "tmpfiles",
]
HOSTS: dict[str, Host] = {n: REGISTRY[n] for n in ORDER if n in REGISTRY}
HOSTS.update({n: h for n, h in REGISTRY.items() if n not in HOSTS})

HOST_GROUPS = {
    "permanent": [n for n, h in HOSTS.items() if not h.temporary],
    "temporary": [n for n, h in HOSTS.items() if h.temporary],
    "images": [n for n, h in HOSTS.items() if h.images_only],
    "files": [n for n, h in HOSTS.items() if not h.images_only],
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


def is_group_spec(spec: str) -> bool:
    return all(p.strip().lower() in HOST_GROUPS for p in spec.split(",") if p.strip())


def host_for_url(url: str) -> Optional[Host]:
    netloc = urllib.parse.urlsplit(url).netloc.lower()
    for h in HOSTS.values():
        if any(netloc == d or netloc.endswith("." + d) for d in h.domains):
            return h
    return None


__all__ = ["HOSTS", "HOST_GROUPS", "Host", "UploadOptions", "UploadResult", "resolve_hosts", "host_for_url", "is_group_spec"]
