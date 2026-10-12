"""Choose hosts for a payload by size, type and how long the upload should live."""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
from typing import Optional, Sequence

from .hosts import Host, UploadOptions
from .media import Payload
from .util import human_duration

log = logging.getLogger("media_drop")

KEEP_CHOICES = ("any", "perm", "temp")


@dataclasses.dataclass
class RetentionPolicy:
    keep: str = "any"  # any | perm | temp
    min_life: Optional[dt.timedelta] = None
    max_life: Optional[dt.timedelta] = None

    def allows(self, host: Host, life: Optional[dt.timedelta]) -> tuple[bool, str]:
        if self.keep == "perm" and host.temporary:
            return False, "temporary host"
        if self.keep == "temp" and not host.temporary:
            return False, "permanent host"
        if self.min_life and life is not None and life < self.min_life:
            return False, f"keeps it ~{human_duration(life)} (< {human_duration(self.min_life)})"
        if self.max_life and (life is None or life > self.max_life):
            return False, f"keeps it {human_duration(life)} (> {human_duration(self.max_life)})"
        return True, ""


class HostSelector:
    """Filters hosts that can take a payload and orders them.

    sort_by_life=False keeps the caller's order (explicit --hosts lists);
    True puts permanent / longest-lived hosts first.
    """

    def __init__(self, hosts: Sequence[Host], policy: RetentionPolicy, opts: UploadOptions, sort_by_life: bool):
        self.hosts = list(hosts)
        self.policy = policy
        self.opts = opts
        self.sort_by_life = sort_by_life

    def rank(self, payload: Payload) -> list[Host]:
        picked: list[tuple[Host, Optional[dt.timedelta], int]] = []
        for idx, host in enumerate(self.hosts):
            for ok, why in (host.available(), host.accepts(payload)):
                if not ok:
                    log.debug("[%s] skip %s: %s", host.name, payload.path.name, why)
                    break
            else:
                life = host.lifetime(payload.size, self.opts)
                ok, why = self.policy.allows(host, life)
                if ok:
                    picked.append((host, life, idx))
                else:
                    log.debug("[%s] skip %s: %s", host.name, payload.path.name, why)
        if self.sort_by_life:
            picked.sort(key=lambda t: (t[0].temporary, -(t[1].total_seconds() if t[1] else float("inf")), t[2]))
        return [h for h, _, _ in picked]
