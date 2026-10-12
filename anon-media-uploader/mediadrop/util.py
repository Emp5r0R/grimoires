"""Small shared helpers: errors, time, sizes, durations, atomic writes, tables."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import os
import re
import secrets
import string
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

MiB = 1024 * 1024

BLOCK_MARKERS = (
    "cf-chl", "challenge-platform", "Just a moment...", "Attention Required!",
    "cf-browser-verification", "captcha", "Access denied", "DDoS protection", "bunkerweb",
)


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


def human_duration(td: Optional[dt.timedelta]) -> str:
    if td is None:
        return "permanent"
    secs = td.total_seconds()
    for unit, size in (("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            value = secs / size
            return f"{value:.0f}{unit}" if value >= 10 or value.is_integer() else f"{value:.1f}{unit}"
    return f"{secs:.0f}s"


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
    """argparse type for durations."""
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
    head = text[:6000].lower()
    return any(marker.lower() in head for marker in BLOCK_MARKERS)


def snippet(text: str, n: int = 160) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:n] + ("..." if len(text) > n else "")


def print_table(rows: Sequence[Sequence[Any]], headers: Sequence[str], out=None) -> None:
    out = out or sys.stdout
    cells = [[str(h) for h in headers]] + [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    for idx, row in enumerate(cells):
        out.write("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip() + "\n")
        if idx == 0:
            out.write("  ".join("-" * w for w in widths) + "\n")


def random_token(n: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
