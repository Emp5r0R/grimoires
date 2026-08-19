#!/usr/bin/env python3
"""
github_email_guard.py

Unified GitHub/Git email privacy scanner + defensive history rewriter.

Modes:
  scan          Fast REST-API scan of Git commit author/committer metadata.
  deep-scan     Mirror-clone repositories and inspect commits + annotated taggers.
  rewrite       Rewrite selected email identities with git-filter-repo.
  scan-rewrite  Scan first, then rewrite only explicitly selected emails, or all
                findings when --replace-all-found is explicitly supplied.

Design goals:
  * Safe-by-default destructive behavior: backups, verification, confirmation.
  * No git push --mirror; only normal heads/tags are ever pushed.
  * Force-with-lease based on a pre-rewrite remote snapshot to detect races.
  * Exact email matching for rewrites; names/messages are preserved.
  * Broad error classification: auth, permission, primary/secondary rate limit,
    proxy/DNS/TLS/timeout, disk/quota, protected branch/ruleset, hidden refs,
    non-fast-forward/lease race, corrupt repo, unsupported API version, etc.
  * Partial failures are recorded per repository instead of crashing a batch.
  * Human and JSON reports.

Requirements:
  scan / scan-rewrite discovery:
      Python 3.9+ and aiohttp (python -m pip install aiohttp)
  deep-scan / rewrite:
      Git >= 2.36
  rewrite:
      git-filter-repo available as `git filter-repo`

IMPORTANT:
  Rewriting Git history changes commit IDs and normally invalidates commit/tag
  signatures. Existing clones can re-introduce old history if they push later.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import email.utils
import json
import os
import random
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import textwrap
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Optional, Sequence

try:
    import aiohttp  # type: ignore
except ImportError:  # scan modes provide a targeted error later
    aiohttp = None  # type: ignore


API = "https://api.github.com"
DEFAULT_API_VERSION = "2026-03-10"
MIN_GIT = (2, 36, 0)
DEFAULT_WORKDIR = "github-email-guard-work"
NOREPLY_DOMAIN = "users.noreply.github.com"
NOREPLY_EXACT = {"noreply@github.com"}
MAX_ERROR_BODY = 4000


# ---------------------------------------------------------------------------
# Errors and status models
# ---------------------------------------------------------------------------


class GuardError(RuntimeError):
    """Expected operational error with a user-actionable message."""


class DependencyError(GuardError):
    pass


class ApiError(GuardError):
    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        url: Optional[str] = None,
        body: str = "",
        retry_after: Optional[float] = None,
        reset_epoch: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.url = url
        self.body = body
        self.retry_after = retry_after
        self.reset_epoch = reset_epoch


class ApiAuthError(ApiError):
    pass


class ApiPermissionError(ApiError):
    pass


class ApiNotFound(ApiError):
    pass


class ApiRateLimit(ApiError):
    pass


class ApiValidationError(ApiError):
    pass


class ApiVersionError(ApiError):
    pass


class ApiNetworkError(ApiError):
    pass


class RepoUnavailable(ApiError):
    pass


class GitCommandError(GuardError):
    def __init__(
        self,
        message: str,
        *,
        cmd: list[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @property
    def combined(self) -> str:
        return "\n".join(x for x in (self.stdout, self.stderr) if x)


@dataclasses.dataclass
class CmdResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def combined(self) -> str:
        return "\n".join(x for x in (self.stdout, self.stderr) if x)


@dataclasses.dataclass
class RepoSpec:
    display: str
    clone_url: str
    slug: str
    default_branch: Optional[str] = None
    archived: bool = False
    disabled: bool = False
    fork: bool = False


@dataclasses.dataclass
class ScanOccurrence:
    email: str
    role: str
    repo: str
    sha: Optional[str] = None
    branch: Optional[str] = None
    date: Optional[str] = None
    message: Optional[str] = None
    github_user: Optional[str] = None
    patch_url: Optional[str] = None
    ref: Optional[str] = None
    source: str = "api"


@dataclasses.dataclass
class RepoScanStatus:
    repo: str
    state: str
    message: str
    commits_seen: int = 0
    branches_seen: int = 0
    findings: int = 0
    partial_failures: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ScanReport:
    account: Optional[str]
    repos: list[str]
    findings: dict[str, list[ScanOccurrence]]
    repo_statuses: list[RepoScanStatus]
    unique_commits: int = 0
    source: str = "api"

    @property
    def failure_count(self) -> int:
        return sum(1 for s in self.repo_statuses if s.state in {"FAILED", "PARTIAL"})


@dataclasses.dataclass
class RemoteSnapshot:
    refs: dict[str, str] = dataclasses.field(default_factory=dict)
    captured_at: str = ""


@dataclasses.dataclass
class RewriteResult:
    repo: str
    state: str
    message: str
    leaked_before: int = 0
    pushed: bool = False
    protected_refs: list[str] = dataclasses.field(default_factory=list)
    rejected_refs: list[str] = dataclasses.field(default_factory=list)
    remote_mismatches: list[str] = dataclasses.field(default_factory=list)
    hidden_ref_matches: int = 0
    workdir: Optional[Path] = None
    log_path: Optional[Path] = None
    backup_path: Optional[Path] = None


# ---------------------------------------------------------------------------
# Logging / utility
# ---------------------------------------------------------------------------


class Logger:
    def __init__(self, path: Path, verbose: bool = False) -> None:
        self.path = path
        self.verbose = verbose
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, msg: str = "") -> None:
        timestamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")

    def info(self, msg: str) -> None:
        print(msg)
        self.write(msg)

    def debug(self, msg: str) -> None:
        self.write(msg)
        if self.verbose:
            print(msg)


class NullLogger(Logger):
    def __init__(self) -> None:
        self.path = Path(os.devnull)
        self.verbose = False

    def write(self, msg: str = "") -> None:
        pass

    def info(self, msg: str) -> None:
        pass

    def debug(self, msg: str) -> None:
        pass


def qcmd(cmd: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(x)) for x in cmd)


def run(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    logger: Optional[Logger] = None,
    check: bool = True,
    input_text: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> CmdResult:
    if logger:
        logger.debug(f"$ {qcmd(cmd)}")
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise DependencyError(f"Required executable not found: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise GuardError(
            f"Command timed out after {timeout}s: {qcmd(cmd)}"
        ) from e
    except OSError as e:
        raise GuardError(f"Could not execute {cmd[0]}: {e}") from e

    result = CmdResult(cmd, p.returncode, p.stdout, p.stderr)
    if logger:
        if p.stdout:
            logger.write("STDOUT:\n" + p.stdout.rstrip())
        if p.stderr:
            logger.write("STDERR:\n" + p.stderr.rstrip())

    if check and p.returncode != 0:
        raise GitCommandError(
            f"Command failed with exit code {p.returncode}: {qcmd(cmd)}",
            cmd=cmd,
            returncode=p.returncode,
            stdout=p.stdout,
            stderr=p.stderr,
        )
    return result


def parse_version(text: str) -> tuple[int, int, int]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return (0, 0, 0)
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def validate_email(value: str) -> str:
    value = value.strip()
    if (
        not value
        or value.count("@") != 1
        or any(c.isspace() for c in value)
        or "<" in value
        or ">" in value
        or "\x00" in value
    ):
        raise argparse.ArgumentTypeError(f"Invalid email address: {value!r}")
    local, domain = value.rsplit("@", 1)
    if not local or not domain or "." not in domain and domain.lower() != "localhost":
        raise argparse.ArgumentTypeError(f"Suspicious/invalid email address: {value!r}")
    return value


def is_noreply(email: str) -> bool:
    e = (email or "").strip().casefold()
    return e in NOREPLY_EXACT or e.endswith("@" + NOREPLY_DOMAIN)


def mask_proxy(proxy_url: str) -> str:
    try:
        p = urllib.parse.urlsplit(proxy_url)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return urllib.parse.urlunsplit((p.scheme, host, "", "", ""))
    except Exception:
        return "<invalid proxy URL>"


def json_default(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Not JSON serializable: {type(value).__name__}")


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=json_default) + "\n", encoding="utf-8")
    tmp.replace(path)


def check_git(*, need_filter_repo: bool) -> None:
    git = run(["git", "--version"])
    version = parse_version(git.stdout)
    if version < MIN_GIT:
        raise DependencyError(
            f"Git {'.'.join(map(str, MIN_GIT))}+ required; found {git.stdout.strip()}"
        )
    if need_filter_repo:
        try:
            run(["git", "filter-repo", "--version"])
        except GitCommandError as e:
            raise DependencyError(
                "git-filter-repo is not available. Install it, for example:\n"
                "  python -m pip install git-filter-repo\n"
                "Then verify with: git filter-repo --version"
            ) from e


def require_aiohttp() -> None:
    if aiohttp is None:
        raise DependencyError(
            "aiohttp is required for API scanning. Install it with:\n"
            "  python -m pip install aiohttp"
        )


# ---------------------------------------------------------------------------
# Repository normalization / discovery
# ---------------------------------------------------------------------------


def normalize_repo(raw: str, owner: Optional[str], protocol: str) -> RepoSpec:
    raw = raw.strip()
    if not raw:
        raise GuardError("Empty repository value.")

    m = re.fullmatch(r"git@github\.com:([^/]+)/(.+?)(?:\.git)?", raw)
    if m:
        slug = f"{m.group(1)}/{m.group(2)}"
        return RepoSpec(raw, f"git@github.com:{slug}.git", slug)

    if raw.startswith("ssh://"):
        u = urllib.parse.urlparse(raw)
        if u.hostname and u.hostname.lower() == "github.com":
            path = u.path.strip("/")
            if path.endswith(".git"):
                path = path[:-4]
            if path.count("/") == 1:
                clone = raw if protocol == "ssh" else f"https://github.com/{path}.git"
                return RepoSpec(raw, clone, path)

    if raw.startswith("http://") or raw.startswith("https://"):
        u = urllib.parse.urlparse(raw)
        if u.hostname and u.hostname.lower() == "github.com":
            path = u.path.strip("/")
            if path.endswith(".git"):
                path = path[:-4]
            if path.count("/") != 1:
                raise GuardError(f"Not a GitHub owner/repository URL: {raw}")
            clone = (
                f"git@github.com:{path}.git"
                if protocol == "ssh"
                else f"https://github.com/{path}.git"
            )
            return RepoSpec(raw, clone, path)

    value = raw[:-4] if raw.endswith(".git") else raw
    if "/" in value:
        if value.count("/") != 1:
            raise GuardError(f"Expected owner/repo, got: {raw}")
        slug = value
    else:
        if not owner:
            raise GuardError(
                f"Repository {raw!r} has no owner. Supply --owner OWNER or use OWNER/REPO."
            )
        slug = f"{owner}/{value}"

    clone = (
        f"git@github.com:{slug}.git"
        if protocol == "ssh"
        else f"https://github.com/{slug}.git"
    )
    return RepoSpec(raw, clone, slug)


def canonical_remote(url: str) -> str:
    url = url.strip()
    m = re.fullmatch(r"git@github\.com:([^/]+)/(.+?)(?:\.git)?", url)
    if m:
        return f"github.com/{m.group(1)}/{m.group(2)}".casefold()
    if url.startswith(("ssh://", "http://", "https://")):
        u = urllib.parse.urlparse(url)
        host = (u.hostname or "").casefold()
        path = u.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return f"{host}/{path}".casefold()
    return url.rstrip("/").removesuffix(".git").casefold()


def load_repo_file(path: Path) -> list[str]:
    try:
        content = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise GuardError(f"Cannot read repo file {path}: {e}") from e
    repos: list[str] = []
    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\x00" in line:
            raise GuardError(f"NUL byte in repo file {path} line {lineno}")
        repos.append(line)
    return repos


def gather_raw_repos(args: argparse.Namespace) -> list[str]:
    values = list(getattr(args, "repos", []) or []) + list(getattr(args, "repo", []) or [])
    repo_file = getattr(args, "repo_file", None)
    if repo_file:
        values.extend(load_repo_file(repo_file))
    return list(dict.fromkeys(x.strip() for x in values if x and x.strip()))


# ---------------------------------------------------------------------------
# GitHub REST API client with robust retry/error handling
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ApiConfig:
    token: Optional[str]
    proxy: Optional[str]
    concurrency: int
    retries: int
    timeout: float
    max_backoff: float
    api_version: str
    verbose: bool = False


class GitHubApiClient:
    def __init__(self, config: ApiConfig) -> None:
        require_aiohttp()
        self.config = config
        self.sem = asyncio.Semaphore(max(1, config.concurrency))
        self.session: Any = None

    async def __aenter__(self) -> "GitHubApiClient":
        assert aiohttp is not None
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.config.api_version,
            "User-Agent": "github-email-guard/1.0",
        }
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=min(30, self.config.timeout),
            sock_read=self.config.timeout,
        )
        connector = aiohttp.TCPConnector(limit=max(4, self.config.concurrency * 2), ttl_dns_cache=300)
        self.session = aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.session is not None:
            await self.session.close()

    @staticmethod
    def _message_from_body(body: str) -> str:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                msg = obj.get("message")
                if msg:
                    return str(msg)
        except Exception:
            pass
        text = re.sub(r"\s+", " ", body).strip()
        return text[:500] or "No response body"

    @staticmethod
    def _retry_after(headers: Any) -> Optional[float]:
        value = headers.get("Retry-After")
        if value:
            try:
                return max(0.0, float(value))
            except ValueError:
                try:
                    when = email.utils.parsedate_to_datetime(value)
                    return max(0.0, when.timestamp() - time.time())
                except Exception:
                    pass
        return None

    @staticmethod
    def _reset_epoch(headers: Any) -> Optional[int]:
        value = headers.get("X-RateLimit-Reset")
        if value:
            try:
                return int(value)
            except ValueError:
                return None
        return None

    def _rate_wait(self, headers: Any, attempt: int) -> tuple[float, Optional[int]]:
        retry_after = self._retry_after(headers)
        reset = self._reset_epoch(headers)
        if retry_after is not None:
            wait = retry_after
        elif headers.get("X-RateLimit-Remaining") == "0" and reset is not None:
            wait = max(0.0, reset - time.time()) + 1.0
        else:
            wait = min(self.config.max_backoff, 2.0 ** attempt + random.uniform(0.0, 1.0))
        return wait, reset

    async def _sleep_or_raise_rate_limit(
        self,
        *,
        status: int,
        url: str,
        body: str,
        headers: Any,
        attempt: int,
    ) -> None:
        wait, reset = self._rate_wait(headers, attempt)
        if attempt >= self.config.retries - 1 or wait > self.config.max_backoff:
            raise ApiRateLimit(
                f"GitHub rate limit reached; retry later (suggested wait {wait:.1f}s).",
                status=status,
                url=url,
                body=body,
                retry_after=wait,
                reset_epoch=reset,
            )
        if self.config.verbose:
            print(f"[api retry] rate limited; sleeping {wait:.1f}s for {url}", file=sys.stderr)
        await asyncio.sleep(wait)

    async def get_json(
        self,
        path_or_url: str,
        *,
        params: Optional[dict[str, Any]] = None,
        allow_404: bool = False,
        allow_409: bool = False,
        context: str = "request",
    ) -> tuple[Any, Any]:
        if self.session is None:
            raise RuntimeError("API client is not open")
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = API + path_or_url

        last_network: Optional[BaseException] = None
        for attempt in range(self.config.retries):
            try:
                async with self.sem:
                    async with self.session.get(url, params=params, proxy=self.config.proxy) as resp:
                        status = resp.status
                        headers = resp.headers
                        body = await resp.text(errors="replace")
                        final_url = str(resp.url)

                msg = self._message_from_body(body)

                if 200 <= status < 300:
                    if status == 204 or not body.strip():
                        return None, headers
                    try:
                        return json.loads(body), headers
                    except json.JSONDecodeError as e:
                        if attempt < self.config.retries - 1:
                            wait = min(self.config.max_backoff, 1.5 * (attempt + 1))
                            await asyncio.sleep(wait)
                            continue
                        raise ApiError(
                            f"GitHub returned non-JSON data for {context}: {msg}",
                            status=status,
                            url=final_url,
                            body=body[:MAX_ERROR_BODY],
                        ) from e

                if status == 401:
                    raise ApiAuthError(
                        f"GitHub authentication failed for {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status == 404:
                    if allow_404:
                        return None, headers
                    raise ApiNotFound(
                        f"GitHub resource not found for {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status == 409:
                    if allow_409:
                        return [], headers
                    raise RepoUnavailable(
                        f"Repository is empty, unavailable, or in a transient Git state during {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status == 410:
                    raise ApiVersionError(
                        f"GitHub API endpoint/version is no longer available during {context}: {msg}. "
                        f"Try --api-version with a currently supported version.",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status in (403, 429):
                    lowered = msg.casefold()
                    remaining = headers.get("X-RateLimit-Remaining")
                    rate_limited = (
                        remaining == "0"
                        or "rate limit" in lowered
                        or "secondary rate" in lowered
                        or "abuse detection" in lowered
                    )
                    if rate_limited:
                        await self._sleep_or_raise_rate_limit(
                            status=status,
                            url=final_url,
                            body=body[:MAX_ERROR_BODY],
                            headers=headers,
                            attempt=attempt,
                        )
                        continue
                    raise ApiPermissionError(
                        f"GitHub denied permission for {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status == 422:
                    raise ApiValidationError(
                        f"GitHub rejected parameters or temporarily blocked the request during {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                if status in (408, 425) or status >= 500:
                    if attempt < self.config.retries - 1:
                        wait = self._retry_after(headers)
                        if wait is None:
                            wait = min(self.config.max_backoff, 2.0 ** attempt + random.uniform(0.0, 1.0))
                        if wait <= self.config.max_backoff:
                            if self.config.verbose:
                                print(f"[api retry] HTTP {status}; sleeping {wait:.1f}s", file=sys.stderr)
                            await asyncio.sleep(wait)
                            continue
                    raise ApiError(
                        f"GitHub server/transient HTTP {status} during {context}: {msg}",
                        status=status,
                        url=final_url,
                        body=body[:MAX_ERROR_BODY],
                    )

                raise ApiError(
                    f"Unexpected GitHub HTTP {status} during {context}: {msg}",
                    status=status,
                    url=final_url,
                    body=body[:MAX_ERROR_BODY],
                )

            except ApiError:
                raise
            except asyncio.TimeoutError as e:
                last_network = e
                reason = "timeout"
            except ssl.SSLError as e:
                last_network = e
                reason = "TLS/SSL error"
            except Exception as e:
                # Keep compatibility across aiohttp minor versions where some
                # specialized connector exception classes may not exist.
                proxy_exc = getattr(aiohttp, "ClientProxyConnectionError", None) if aiohttp is not None else None
                cert_exc = getattr(aiohttp, "ClientConnectorCertificateError", None) if aiohttp is not None else None
                dns_exc = getattr(aiohttp, "ClientConnectorDNSError", None) if aiohttp is not None else None
                connector_exc = getattr(aiohttp, "ClientConnectorError", None) if aiohttp is not None else None
                client_exc = getattr(aiohttp, "ClientError", None) if aiohttp is not None else None
                if proxy_exc is not None and isinstance(e, proxy_exc):
                    last_network = e
                    reason = "proxy connection error"
                elif cert_exc is not None and isinstance(e, cert_exc):
                    last_network = e
                    reason = "TLS certificate error"
                elif dns_exc is not None and isinstance(e, dns_exc):
                    last_network = e
                    reason = "DNS resolution error"
                elif connector_exc is not None and isinstance(e, connector_exc):
                    last_network = e
                    reason = "connection error"
                elif client_exc is not None and isinstance(e, client_exc):
                    last_network = e
                    reason = type(e).__name__
                else:
                    raise

            if attempt < self.config.retries - 1:
                wait = min(self.config.max_backoff, 2.0 ** attempt + random.uniform(0.0, 1.0))
                if self.config.verbose:
                    print(f"[api retry] {reason}; sleeping {wait:.1f}s", file=sys.stderr)
                await asyncio.sleep(wait)
                continue
            raise ApiNetworkError(
                f"GitHub API {reason} during {context}: {last_network}",
                url=url,
            ) from last_network

        raise ApiNetworkError(f"GitHub API request failed unexpectedly: {context}", url=url)

    async def paged(
        self,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        allow_404: bool = False,
        allow_409: bool = False,
        context: str,
        max_pages: int = 10000,
    ) -> AsyncIterator[dict[str, Any]]:
        page = 1
        previous_fingerprint: Optional[str] = None
        while True:
            if page > max_pages:
                raise ApiError(f"Pagination safety limit exceeded during {context}.")
            q = {"per_page": 100, "page": page}
            if params:
                q.update(params)
            data, _headers = await self.get_json(
                path,
                params=q,
                allow_404=allow_404,
                allow_409=allow_409,
                context=f"{context} page {page}",
            )
            if not data:
                return
            if not isinstance(data, list):
                raise ApiError(
                    f"Expected a list from GitHub during {context}, got {type(data).__name__}."
                )

            try:
                first = data[0]
                last = data[-1]
                fingerprint = json.dumps(
                    [first.get("id") or first.get("sha") or first.get("name"),
                     last.get("id") or last.get("sha") or last.get("name"), len(data)],
                    sort_keys=True,
                )
            except Exception:
                fingerprint = f"page:{page}:len:{len(data)}"
            if previous_fingerprint == fingerprint:
                raise ApiError(
                    f"GitHub pagination repeated the same page during {context}; stopping to avoid a loop."
                )
            previous_fingerprint = fingerprint

            for item in data:
                if isinstance(item, dict):
                    yield item
            if len(data) < 100:
                return
            page += 1


async def discover_account_repositories(
    client: GitHubApiClient,
    account: str,
    *,
    include_forks: bool,
    include_archived: bool,
    include_private: bool,
) -> list[RepoSpec]:
    meta, _ = await client.get_json(
        f"/users/{urllib.parse.quote(account, safe='')}",
        context=f"identify account {account}",
    )
    if not isinstance(meta, dict):
        raise ApiError(f"Unexpected account metadata for {account!r}")
    acct_type = str(meta.get("type") or "User")
    login = str(meta.get("login") or account)

    repos: list[dict[str, Any]] = []
    if acct_type.casefold() == "organization":
        async for r in client.paged(
            f"/orgs/{urllib.parse.quote(login, safe='')}/repos",
            params={"type": "all", "sort": "full_name"},
            context=f"list organization repositories for {login}",
        ):
            repos.append(r)
    else:
        # Public account endpoint is predictable for arbitrary users.
        async for r in client.paged(
            f"/users/{urllib.parse.quote(login, safe='')}/repos",
            params={"type": "all", "sort": "full_name"},
            context=f"list public repositories for {login}",
        ):
            repos.append(r)

        # For the authenticated user, /user/repos can add visible private repos.
        if include_private and client.config.token:
            me, _ = await client.get_json("/user", context="identify authenticated GitHub user")
            if isinstance(me, dict) and str(me.get("login", "")).casefold() == login.casefold():
                async for r in client.paged(
                    "/user/repos",
                    params={"visibility": "all", "affiliation": "owner", "sort": "full_name"},
                    context=f"list authenticated repositories for {login}",
                ):
                    repos.append(r)

    by_full: dict[str, dict[str, Any]] = {}
    for repo in repos:
        full = str(repo.get("full_name") or "")
        if full:
            by_full[full.casefold()] = repo

    specs: list[RepoSpec] = []
    for repo in sorted(by_full.values(), key=lambda x: str(x.get("full_name", "")).casefold()):
        if repo.get("fork") and not include_forks:
            continue
        if repo.get("archived") and not include_archived:
            continue
        full = str(repo["full_name"])
        clone_url = str(repo.get("ssh_url") or f"git@github.com:{full}.git")
        specs.append(
            RepoSpec(
                display=full,
                clone_url=clone_url,
                slug=full,
                default_branch=repo.get("default_branch"),
                archived=bool(repo.get("archived")),
                disabled=bool(repo.get("disabled")),
                fork=bool(repo.get("fork")),
            )
        )
    return specs


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class EmailFilter:
    exact: set[str] = dataclasses.field(default_factory=set)
    ignored: set[str] = dataclasses.field(default_factory=set)
    regex: Optional[re.Pattern[str]] = None
    include_noreply: bool = False

    def matches(self, email: str) -> bool:
        e = (email or "").strip()
        if not e:
            return False
        cf = e.casefold()
        if cf in self.ignored:
            return False
        if not self.include_noreply and is_noreply(e):
            return False
        if self.exact and cf not in self.exact:
            return False
        if self.regex and not self.regex.search(e):
            return False
        return True


def make_email_filter(args: argparse.Namespace) -> EmailFilter:
    exact = {x.casefold() for x in (getattr(args, "match_email", None) or [])}
    ignored = {x.casefold() for x in (getattr(args, "ignore_email", None) or [])}
    regex_text = getattr(args, "email_regex", None)
    regex = None
    if regex_text:
        try:
            regex = re.compile(regex_text, re.IGNORECASE)
        except re.error as e:
            raise GuardError(f"Invalid --email-regex: {e}") from e
    return EmailFilter(
        exact=exact,
        ignored=ignored,
        regex=regex,
        include_noreply=bool(getattr(args, "include_noreply", False)),
    )


async def api_scan_branch(
    client: GitHubApiClient,
    spec: RepoSpec,
    branch: str,
    email_filter: EmailFilter,
    findings: dict[str, list[ScanOccurrence]],
    seen: set[tuple[str, str]],
) -> tuple[int, Optional[str]]:
    count = 0
    try:
        async for c in client.paged(
            f"/repos/{urllib.parse.quote(spec.slug, safe='/')}/commits",
            params={"sha": branch},
            allow_404=True,
            allow_409=True,
            context=f"scan {spec.slug} branch {branch}",
        ):
            sha = str(c.get("sha") or "")
            if not sha:
                continue
            key = (spec.slug.casefold(), sha)
            if key in seen:
                continue
            seen.add(key)
            count += 1

            git = c.get("commit") or {}
            for role in ("author", "committer"):
                person = git.get(role) or {}
                email = str(person.get("email") or "").strip()
                if not email_filter.matches(email):
                    continue
                linked = c.get(role) or {}
                occurrence = ScanOccurrence(
                    email=email,
                    github_user=linked.get("login") if isinstance(linked, dict) else None,
                    role=role,
                    repo=spec.slug,
                    branch=branch,
                    sha=sha,
                    date=person.get("date"),
                    message=(str(git.get("message") or "").splitlines() or [""])[0][:160],
                    patch_url=f"https://github.com/{spec.slug}/commit/{sha}.patch",
                    source="api",
                )
                findings[email.casefold()].append(occurrence)
        return count, None
    except ApiNotFound:
        # Branch can disappear between branch listing and commit traversal.
        return count, "branch disappeared or became inaccessible while scanning"
    except RepoUnavailable as e:
        return count, str(e)
    except ApiValidationError as e:
        return count, str(e)
    except ApiError as e:
        return count, str(e)


async def api_scan_repo(
    client: GitHubApiClient,
    spec: RepoSpec,
    email_filter: EmailFilter,
    findings: dict[str, list[ScanOccurrence]],
    seen: set[tuple[str, str]],
    branch_task_limit: int,
) -> RepoScanStatus:
    print(f"[repo] {spec.slug}", file=sys.stderr)
    if spec.disabled:
        return RepoScanStatus(spec.slug, "SKIPPED", "Repository is disabled.")

    try:
        branches = [
            b
            async for b in client.paged(
                f"/repos/{urllib.parse.quote(spec.slug, safe='/')}/branches",
                allow_404=True,
                allow_409=True,
                context=f"list branches for {spec.slug}",
            )
        ]
    except ApiError as e:
        return RepoScanStatus(spec.slug, "FAILED", str(e))

    if not branches:
        return RepoScanStatus(spec.slug, "OK", "No branches/commits found (possibly empty repository).")

    branch_sem = asyncio.Semaphore(max(1, branch_task_limit))

    async def one(branch_name: str) -> tuple[int, Optional[str]]:
        async with branch_sem:
            return await api_scan_branch(
                client, spec, branch_name, email_filter, findings, seen
            )

    tasks = [one(str(b.get("name") or "")) for b in branches if b.get("name")]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    commits = 0
    partial: list[str] = []
    for branch, result in zip([str(b.get("name")) for b in branches if b.get("name")], results):
        if isinstance(result, Exception):
            partial.append(f"{branch}: {type(result).__name__}: {result}")
        else:
            n, err = result
            commits += n
            if err:
                partial.append(f"{branch}: {err}")

    repo_findings = sum(
        1 for occs in findings.values() for o in occs if o.repo.casefold() == spec.slug.casefold()
    )
    if partial:
        return RepoScanStatus(
            spec.slug,
            "PARTIAL",
            f"Scanned with {len(partial)} branch-level warning(s).",
            commits_seen=commits,
            branches_seen=len(branches),
            findings=repo_findings,
            partial_failures=partial,
        )
    return RepoScanStatus(
        spec.slug,
        "OK",
        "Scan completed.",
        commits_seen=commits,
        branches_seen=len(branches),
        findings=repo_findings,
    )


async def run_api_scan(
    specs: list[RepoSpec],
    *,
    account: Optional[str],
    api_config: ApiConfig,
    email_filter: EmailFilter,
    repo_task_limit: int,
    branch_task_limit: int,
) -> ScanReport:
    findings: dict[str, list[ScanOccurrence]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    statuses: list[RepoScanStatus] = []

    async with GitHubApiClient(api_config) as client:
        repo_sem = asyncio.Semaphore(max(1, repo_task_limit))

        async def one(spec: RepoSpec) -> RepoScanStatus:
            async with repo_sem:
                return await api_scan_repo(
                    client,
                    spec,
                    email_filter,
                    findings,
                    seen,
                    branch_task_limit,
                )

        results = await asyncio.gather(*(one(s) for s in specs), return_exceptions=True)
        for spec, result in zip(specs, results):
            if isinstance(result, Exception):
                statuses.append(
                    RepoScanStatus(spec.slug, "FAILED", f"{type(result).__name__}: {result}")
                )
            else:
                statuses.append(result)

    return ScanReport(
        account=account,
        repos=[s.slug for s in specs],
        findings=dict(findings),
        repo_statuses=statuses,
        unique_commits=len(seen),
        source="api",
    )


def local_commit_matches(repo_dir: Path, email_filter: EmailFilter, logger: Logger) -> list[ScanOccurrence]:
    # NUL-separated fields avoid ambiguity from tabs/newlines in names/messages.
    fmt = "%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s%x00"
    r = run(["git", "log", "--all", f"--format={fmt}"], cwd=repo_dir, logger=logger)
    parts = r.stdout.split("\x00")
    out: list[ScanOccurrence] = []
    # 9 fields including trailing separator; tolerate malformed final fragments.
    step = 9
    for i in range(0, len(parts) - (step - 1), step):
        sha, an, ae, ad, cn, ce, cd, subject, _ = parts[i : i + step]
        sha = sha.strip()
        if not sha:
            continue
        if email_filter.matches(ae):
            out.append(
                ScanOccurrence(
                    email=ae,
                    role="author",
                    repo="",
                    sha=sha,
                    date=ad,
                    message=subject[:160],
                    source="git",
                )
            )
        if email_filter.matches(ce):
            out.append(
                ScanOccurrence(
                    email=ce,
                    role="committer",
                    repo="",
                    sha=sha,
                    date=cd,
                    message=subject[:160],
                    source="git",
                )
            )
    return out


def local_tag_matches(repo_dir: Path, email_filter: EmailFilter, logger: Logger) -> list[ScanOccurrence]:
    refs = run(
        ["git", "for-each-ref", "refs/tags", "--format=%(objecttype)%00%(objectname)%00%(refname)%00"],
        cwd=repo_dir,
        logger=logger,
    )
    parts = refs.stdout.split("\x00")
    out: list[ScanOccurrence] = []
    for i in range(0, len(parts) - 3, 4):
        objtype, obj, ref, _ = parts[i : i + 4]
        if objtype != "tag" or not obj or not ref:
            continue
        tag = run(["git", "cat-file", "-p", obj], cwd=repo_dir, logger=logger)
        for hdr in tag.stdout.splitlines():
            if not hdr.startswith("tagger "):
                if hdr == "":
                    break
                continue
            m = re.match(r"tagger\s+.*?<([^<>]+)>\s+(\d+)\s+([+-]\d{4})$", hdr)
            if not m:
                # Unusual but valid-ish tagger header: make a best-effort email extraction.
                m2 = re.search(r"<([^<>]+)>", hdr)
                if m2 and email_filter.matches(m2.group(1)):
                    out.append(
                        ScanOccurrence(
                            email=m2.group(1),
                            role="tagger",
                            repo="",
                            ref=ref,
                            source="git",
                        )
                    )
                break
            email_addr = m.group(1)
            if email_filter.matches(email_addr):
                try:
                    date = dt.datetime.fromtimestamp(int(m.group(2)), tz=dt.timezone.utc).isoformat()
                except Exception:
                    date = None
                out.append(
                    ScanOccurrence(
                        email=email_addr,
                        role="tagger",
                        repo="",
                        ref=ref,
                        date=date,
                        source="git",
                    )
                )
            break
    return out


def deep_scan_repo(
    spec: RepoSpec,
    *,
    root: Path,
    email_filter: EmailFilter,
    protocol: str,
    reuse_workdir: bool,
    verbose: bool,
) -> tuple[RepoScanStatus, list[ScanOccurrence]]:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", spec.slug)
    repo_dir = root / "scan-mirrors" / f"{safe}.git"
    log = Logger(root / "logs" / f"deep-scan-{safe}.log", verbose=verbose)
    log.info(f"=== deep-scan {spec.slug} ===")
    try:
        if repo_dir.exists():
            if not reuse_workdir:
                raise GuardError(
                    f"Deep-scan mirror already exists: {repo_dir}. Use --reuse-workdir or a new --workdir."
                )
            log.info("  Reusing mirror and fetching current refs...")
            run(["git", "remote", "update", "--prune"], cwd=repo_dir, logger=log)
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            run(["git", "clone", "--mirror", "--no-local", spec.clone_url, str(repo_dir)], logger=log)

        hits = local_commit_matches(repo_dir, email_filter, log) + local_tag_matches(repo_dir, email_filter, log)
        for h in hits:
            h.repo = spec.slug
            if h.sha:
                h.patch_url = f"https://github.com/{spec.slug}/commit/{h.sha}.patch"
        commits = run(["git", "rev-list", "--all", "--count"], cwd=repo_dir, logger=log, check=False)
        try:
            count = int(commits.stdout.strip()) if commits.returncode == 0 else 0
        except ValueError:
            count = 0
        return (
            RepoScanStatus(
                spec.slug,
                "OK",
                "Deep scan completed.",
                commits_seen=count,
                findings=len(hits),
            ),
            hits,
        )
    except GitCommandError as e:
        return RepoScanStatus(spec.slug, "FAILED", explain_git_failure(e)), []
    except GuardError as e:
        return RepoScanStatus(spec.slug, "FAILED", str(e)), []
    except Exception as e:
        return RepoScanStatus(spec.slug, "FAILED", f"Unexpected {type(e).__name__}: {e}"), []


def run_deep_scan(
    specs: list[RepoSpec],
    *,
    account: Optional[str],
    root: Path,
    email_filter: EmailFilter,
    protocol: str,
    reuse_workdir: bool,
    verbose: bool,
) -> ScanReport:
    check_git(need_filter_repo=False)
    findings: dict[str, list[ScanOccurrence]] = defaultdict(list)
    statuses: list[RepoScanStatus] = []
    total_commits = 0
    for spec in specs:
        status, hits = deep_scan_repo(
            spec,
            root=root,
            email_filter=email_filter,
            protocol=protocol,
            reuse_workdir=reuse_workdir,
            verbose=verbose,
        )
        statuses.append(status)
        total_commits += status.commits_seen
        for h in hits:
            findings[h.email.casefold()].append(h)
    return ScanReport(
        account=account,
        repos=[s.slug for s in specs],
        findings=dict(findings),
        repo_statuses=statuses,
        unique_commits=total_commits,
        source="git",
    )


# ---------------------------------------------------------------------------
# Rewrite / push safety
# ---------------------------------------------------------------------------


FORCE_DENY_PATTERNS = (
    "cannot force-push",
    "cannot force push",
    "protected branch hook declined",
    "gh013",
    "repository rule violations",
    "protected branch",
    "push declined due to repository rule violations",
)
AUTH_PATTERNS = (
    "permission denied",
    "authentication failed",
    "could not read username",
    "repository not found",
    "access denied",
    "publickey",
    "could not read from remote repository",
)
NETWORK_PATTERNS = (
    "could not resolve host",
    "failed to connect",
    "connection timed out",
    "connection reset",
    "network is unreachable",
    "unable to access",
    "tls",
    "ssl",
    "connection closed",
    "proxy",
)
DISK_PATTERNS = (
    "no space left on device",
    "disk quota exceeded",
    "file too large",
)
HIDDEN_REF_PATTERNS = (
    "deny updating a hidden ref",
    "refs/pull/",
    "hidden ref",
)
LEASE_PATTERNS = (
    "stale info",
    "fetch first",
    "non-fast-forward",
    "failed to push some refs",
    "would clobber existing tag",
)
CORRUPTION_PATTERNS = (
    "bad object",
    "missing blob",
    "missing tree",
    "missing commit",
    "object corrupt",
    "corrupt loose object",
    "invalid sha1 pointer",
    "broken link from",
)
LOCK_PATTERNS = (
    "index.lock",
    "cannot lock ref",
    "unable to create.*lock",
    "another git process",
)


def classify_git_failure(text: str) -> str:
    t = text.casefold()
    if any(x in t for x in DISK_PATTERNS):
        return "disk"
    if any(x in t for x in CORRUPTION_PATTERNS):
        return "corruption"
    if any(re.search(x, t) if ".*" in x else x in t for x in LOCK_PATTERNS):
        return "lock"
    if any(x in t for x in AUTH_PATTERNS):
        return "auth"
    if any(x in t for x in NETWORK_PATTERNS):
        return "network"
    if any(x in t for x in FORCE_DENY_PATTERNS):
        return "protected"
    if any(x in t for x in HIDDEN_REF_PATTERNS):
        return "hidden-ref"
    if any(x in t for x in LEASE_PATTERNS):
        return "lease-race"
    return "git"


def explain_git_failure(err: GitCommandError) -> str:
    kind = classify_git_failure(err.combined)
    if kind == "disk":
        return "Disk space/quota/file-size failure. Free space or move --workdir and retry."
    if kind == "corruption":
        return "Git repository/object corruption detected. Do not push; restore/reclone and inspect git fsck output."
    if kind == "lock":
        return "Git lock/concurrent-process failure. Ensure no other Git process is using the workdir, then retry."
    if kind == "auth":
        return "GitHub authentication/authorization failure. Verify SSH/HTTPS credentials and push permissions."
    if kind == "network":
        return "Network/DNS/TLS/proxy failure. Fix connectivity and retry this repository."
    if kind == "protected":
        return "GitHub branch protection/ruleset rejected the history update. Use an authorized bypass or temporarily permit force pushes."
    if kind == "hidden-ref":
        return "A GitHub-managed hidden ref was rejected. This tool never intentionally pushes refs/pull/*."
    if kind == "lease-race":
        return "Remote refs changed after the safety snapshot (or Git rejected a non-fast-forward update). Re-scan/reclone before retrying."
    tail = err.combined.strip().splitlines()[-1:] or ["unknown Git error"]
    return f"Git command failed: {tail[0]}"


def discover_default_branch(url: str, logger: Logger) -> Optional[str]:
    result = run(["git", "ls-remote", "--symref", url, "HEAD"], logger=logger, check=False)
    if result.returncode != 0:
        logger.write("Could not discover default branch before cloning.")
        return None
    for line in result.stdout.splitlines():
        m = re.match(r"ref:\s+refs/heads/(.+?)\s+HEAD$", line)
        if m:
            return m.group(1)
    return None


def get_ref_map(repo_dir: Path, namespaces: Sequence[str], logger: Logger) -> dict[str, str]:
    result: dict[str, str] = {}
    for ns in namespaces:
        r = run(
            ["git", "for-each-ref", ns, "--format=%(refname)%00%(objectname)%00"],
            cwd=repo_dir,
            logger=logger,
        )
        parts = r.stdout.split("\x00")
        for i in range(0, len(parts) - 2, 3):
            ref, sha, _ = parts[i : i + 3]
            ref, sha = ref.strip(), sha.strip()
            if ref and sha:
                result[ref] = sha
    return result


def capture_remote_snapshot(url: str, logger: Logger) -> RemoteSnapshot:
    r = run(["git", "ls-remote", "--heads", "--tags", url], logger=logger)
    refs: dict[str, str] = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        if ref.endswith("^{}"):
            continue
        if ref.startswith("refs/heads/") or ref.startswith("refs/tags/"):
            refs[ref] = sha
    return RemoteSnapshot(refs=refs, captured_at=dt.datetime.now().astimezone().isoformat())


def verify_pre_rewrite_snapshot(repo_dir: Path, snapshot: RemoteSnapshot, logger: Logger) -> None:
    """Refuse to rewrite a stale mirror.

    The remote can change between `git clone --mirror` and `git ls-remote`.  A lease
    created from the newer remote state would otherwise authorize overwriting commits
    that the local mirror never contained.  Therefore the local normal refs must match
    the captured remote snapshot exactly before history rewriting starts.
    """
    local = get_ref_map(repo_dir, ("refs/heads", "refs/tags"), logger)
    all_refs = sorted(set(local) | set(snapshot.refs))
    mismatches = [
        ref for ref in all_refs
        if local.get(ref) != snapshot.refs.get(ref)
    ]
    if mismatches:
        details = []
        for ref in mismatches[:10]:
            details.append(
                f"{ref}: local={local.get(ref) or '<missing>'} remote={snapshot.refs.get(ref) or '<missing>'}"
            )
        raise GuardError(
            "Remote refs changed during/just after cloning, so the mirror is not a safe rewrite base. "
            "Delete/recreate this mirror and retry. Mismatch(es): " + "; ".join(details)
        )


def ensure_origin(
    repo_dir: Path,
    expected_url: str,
    logger: Logger,
    *,
    allow_remote_change: bool,
) -> None:
    remotes = run(["git", "remote"], cwd=repo_dir, logger=logger)
    names = set(remotes.stdout.split())
    if "origin" not in names:
        logger.info("  [repair] origin missing (normal after git-filter-repo); restoring it.")
        run(["git", "remote", "add", "origin", expected_url], cwd=repo_dir, logger=logger)
        return
    current = run(["git", "remote", "get-url", "--push", "origin"], cwd=repo_dir, logger=logger).stdout.strip()
    if canonical_remote(current) != canonical_remote(expected_url):
        msg = f"origin unexpectedly points to {current!r}; expected {expected_url!r}."
        if not allow_remote_change:
            raise GuardError(msg + " Refusing to push. Use --allow-origin-repair only after reviewing the target.")
        logger.info(f"  [repair] {msg} Resetting origin.")
        run(["git", "remote", "set-url", "origin", expected_url], cwd=repo_dir, logger=logger)


def git_fsck(repo_dir: Path, logger: Logger) -> None:
    r = run(
        ["git", "fsck", "--full", "--strict", "--no-reflogs"],
        cwd=repo_dir,
        logger=logger,
        check=False,
    )
    if r.returncode != 0:
        raise GitCommandError(
            "git fsck reported repository integrity errors.",
            cmd=r.cmd,
            returncode=r.returncode,
            stdout=r.stdout,
            stderr=r.stderr,
        )


def create_backup(repo_dir: Path, backup_path: Path, logger: Logger) -> None:
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "bundle", "create", str(backup_path), "--all"], cwd=repo_dir, logger=logger)
    run(["git", "bundle", "verify", str(backup_path)], cwd=repo_dir, logger=logger)


def hidden_pull_identity_hits(repo_dir: Path, emails: set[str], logger: Logger) -> list[str]:
    """Find selected commit identities reachable from local refs/pull/*.

    GitHub manages these refs. We inspect them when a mirror clone contains them, but
    intentionally never attempt to push them.
    """
    refs_result = run(
        ["git", "for-each-ref", "refs/pull", "--format=%(refname)"],
        cwd=repo_dir,
        logger=logger,
        check=False,
    )
    refs = [x.strip() for x in refs_result.stdout.splitlines() if x.strip()]
    if refs_result.returncode != 0 or not refs:
        return []

    needles = {e.casefold() for e in emails}
    fmt = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00"
    r = run(
        ["git", "log", "--stdin", f"--format={fmt}"],
        cwd=repo_dir,
        logger=logger,
        input_text="\n".join(refs) + "\n",
    )
    parts = r.stdout.split("\x00")
    hits: list[str] = []
    seen: set[str] = set()
    for i in range(0, len(parts) - 5, 6):
        sha, an, ae, cn, ce, _ = parts[i : i + 6]
        sha = sha.strip()
        if not sha or sha in seen:
            continue
        roles: list[str] = []
        if ae.casefold() in needles:
            roles.append(f"author={an} <{ae}>")
        if ce.casefold() in needles:
            roles.append(f"committer={cn} <{ce}>")
        if roles:
            seen.add(sha)
            hits.append(f"{sha}: " + "; ".join(roles))
    return hits


def exact_identity_hits(repo_dir: Path, emails: set[str], logger: Logger) -> list[str]:
    needles = {e.casefold() for e in emails}
    hits: list[str] = []
    r = run(
        ["git", "log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00"],
        cwd=repo_dir,
        logger=logger,
    )
    parts = r.stdout.split("\x00")
    for i in range(0, len(parts) - 5, 6):
        sha, an, ae, cn, ce, _ = parts[i : i + 6]
        roles: list[str] = []
        if ae.casefold() in needles:
            roles.append(f"author={an} <{ae}>")
        if ce.casefold() in needles:
            roles.append(f"committer={cn} <{ce}>")
        if roles:
            hits.append(f"{sha.strip()}: " + "; ".join(roles))

    refs = run(
        ["git", "for-each-ref", "refs/tags", "--format=%(objecttype)%00%(objectname)%00%(refname)%00"],
        cwd=repo_dir,
        logger=logger,
    )
    tparts = refs.stdout.split("\x00")
    for i in range(0, len(tparts) - 3, 4):
        objtype, obj, ref, _ = tparts[i : i + 4]
        if objtype != "tag":
            continue
        tag = run(["git", "cat-file", "-p", obj], cwd=repo_dir, logger=logger)
        for hdr in tag.stdout.splitlines():
            if hdr.startswith("tagger "):
                m = re.search(r"<([^<>]+)>", hdr)
                if m and m.group(1).casefold() in needles:
                    hits.append(f"{ref}: {hdr}")
                break
            if hdr == "":
                break
    return hits


def build_email_callback(old_emails: Sequence[str], new_email: str) -> str:
    # Avoid rebuilding a set on every callback invocation.
    olds = repr({e.casefold().encode("utf-8") for e in old_emails})
    new_b = repr(new_email.encode("utf-8"))
    return f"old = {olds}\nreturn {new_b} if email.lower() in old else email"


def parse_rejected_refs(text: str) -> list[str]:
    refs: list[str] = []
    for line in text.splitlines():
        if "[remote rejected]" not in line and "[rejected]" not in line:
            continue
        m = re.search(r"\]\s+(.+?)\s+->\s+(.+?)(?:\s+\(|$)", line)
        if m:
            dest = m.group(2).strip()
            if dest not in refs:
                refs.append(dest)
    return refs


def normalize_rejected_ref(short_or_full: str, local_refs: dict[str, str]) -> Optional[str]:
    ref = short_or_full.strip()
    if ref.startswith("refs/pull/") or ref.startswith("pull/"):
        return None
    if ref.startswith("refs/"):
        return ref if ref in local_refs else ref
    candidates = [f"refs/heads/{ref}", f"refs/tags/{ref}"]
    for c in candidates:
        if c in local_refs:
            return c
    return None


def chunks(seq: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def push_refs_with_leases(
    repo_dir: Path,
    snapshot: RemoteSnapshot,
    logger: Logger,
    *,
    force_without_lease: bool,
    prune_remote: bool,
    batch_size: int = 40,
) -> tuple[bool, list[str], str]:
    # `git clone --mirror` sets remote.origin.mirror=true.  Explicit refspec pushes
    # cannot be combined with mirror-push mode, so defensively remove that setting.
    run(["git", "config", "--unset-all", "remote.origin.mirror"], cwd=repo_dir, logger=logger, check=False)
    local = get_ref_map(repo_dir, ("refs/heads", "refs/tags"), logger)
    refnames = sorted(local)
    outputs: list[str] = []
    rejected: list[str] = []
    ok = True

    for batch in chunks(refnames, max(1, batch_size)):
        cmd = ["git", "push", "origin"]
        if force_without_lease:
            cmd.append("--force")
        else:
            for ref in batch:
                expected = snapshot.refs.get(ref)
                if expected:
                    cmd.append(f"--force-with-lease={ref}:{expected}")
                else:
                    # Ref appeared locally but was not in snapshot. Require remote nonexistence.
                    cmd.append(f"--force-with-lease={ref}:")
        cmd.extend(f"{ref}:{ref}" for ref in batch)
        r = run(cmd, cwd=repo_dir, logger=logger, check=False)
        outputs.append(r.combined)
        if r.returncode != 0:
            ok = False
            rejected.extend(x for x in parse_rejected_refs(r.combined) if x not in rejected)

    if prune_remote:
        # Deletions are intentionally a separate, explicit phase and still use leases.
        stale = sorted(set(snapshot.refs) - set(local))
        for batch in chunks(stale, max(1, batch_size)):
            cmd = ["git", "push", "origin"]
            if force_without_lease:
                cmd.append("--force")
            else:
                for ref in batch:
                    cmd.append(f"--force-with-lease={ref}:{snapshot.refs[ref]}")
            cmd.extend(f":{ref}" for ref in batch)
            r = run(cmd, cwd=repo_dir, logger=logger, check=False)
            outputs.append(r.combined)
            if r.returncode != 0:
                ok = False
                rejected.extend(x for x in parse_rejected_refs(r.combined) if x not in rejected)

    return ok, rejected, "\n".join(outputs)


def verify_remote_refs(repo_dir: Path, logger: Logger) -> list[str]:
    local = get_ref_map(repo_dir, ("refs/heads", "refs/tags"), logger)
    r = run(["git", "ls-remote", "--heads", "--tags", "origin"], cwd=repo_dir, logger=logger, check=False)
    if r.returncode != 0:
        raise GitCommandError(
            "Could not verify remote refs after push.",
            cmd=r.cmd,
            returncode=r.returncode,
            stdout=r.stdout,
            stderr=r.stderr,
        )
    remote: dict[str, str] = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        if ref.endswith("^{}"):
            continue
        remote[ref] = sha
    mismatches = [ref for ref, sha in local.items() if remote.get(ref) != sha]
    return mismatches


def retry_rejected_refs(
    repo_dir: Path,
    rejected: list[str],
    snapshot: RemoteSnapshot,
    logger: Logger,
    *,
    force_without_lease: bool,
) -> list[str]:
    run(["git", "config", "--unset-all", "remote.origin.mirror"], cwd=repo_dir, logger=logger, check=False)
    local = get_ref_map(repo_dir, ("refs/heads", "refs/tags"), logger)
    remaining: list[str] = []
    for raw in rejected:
        ref = normalize_rejected_ref(raw, local)
        if ref is None:
            logger.info(f"  [skip] Not retrying hidden/unknown ref {raw!r}.")
            remaining.append(raw)
            continue
        if ref.startswith("refs/pull/"):
            remaining.append(raw)
            continue
        cmd = ["git", "push", "origin"]
        if force_without_lease:
            cmd.append("--force")
        else:
            expected = snapshot.refs.get(ref)
            cmd.append(f"--force-with-lease={ref}:{expected or ''}")
        cmd.append(f"{ref}:{ref}")
        r = run(cmd, cwd=repo_dir, logger=logger, check=False)
        if r.returncode != 0:
            remaining.append(raw)
    return remaining


def confirm_rewrite(args: argparse.Namespace, specs: list[RepoSpec], old_emails: Sequence[str]) -> None:
    if args.yes or args.dry_run or args.no_push:
        return
    print()
    print("WARNING: this operation rewrites Git history and updates remote branches/tags.")
    print("Commit IDs will change; existing clones should normally be re-cloned afterward.")
    print("Repositories:")
    for s in specs:
        print(f"  - {s.slug}")
    print("Old email(s): " + ", ".join(old_emails))
    print("Replacement:  " + args.new_email)
    print("Push safety:  " + ("unconditional --force" if args.force_without_lease else "force-with-lease remote snapshot"))
    print()
    if not sys.stdin.isatty():
        raise GuardError("Refusing destructive push without an interactive terminal. Use --yes only after reviewing the command.")
    answer = input("Type REWRITE to continue: ").strip()
    if answer != "REWRITE":
        raise GuardError("Cancelled by user.")


def process_rewrite_repo(
    spec: RepoSpec,
    args: argparse.Namespace,
    root: Path,
    old_emails: Sequence[str],
) -> RewriteResult:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", spec.slug)
    repo_dir = root / "rewrite-mirrors" / f"{safe}.git"
    log_path = root / "logs" / f"rewrite-{safe}.log"
    logger = Logger(log_path, verbose=args.verbose)
    result = RewriteResult(
        repo=spec.slug,
        state="FAILED",
        message="Unknown failure",
        workdir=repo_dir,
        log_path=log_path,
    )
    logger.info(f"=== rewrite {spec.slug} ===")
    logger.info(f"Target: {spec.clone_url}")

    try:
        spec.default_branch = spec.default_branch or discover_default_branch(spec.clone_url, logger)

        snapshot_file = root / "snapshots" / f"{safe}.json"
        if args.push_only:
            if not repo_dir.exists() or not args.reuse_workdir:
                raise GuardError("--push-only requires an existing rewrite mirror and --reuse-workdir.")
            ensure_origin(repo_dir, spec.clone_url, logger, allow_remote_change=args.allow_origin_repair)
            if snapshot_file.exists():
                obj = json.loads(snapshot_file.read_text(encoding="utf-8"))
                snapshot = RemoteSnapshot(refs=dict(obj.get("refs") or {}), captured_at=str(obj.get("captured_at") or ""))
            else:
                if not args.force_without_lease:
                    raise GuardError(
                        f"Safety snapshot missing: {snapshot_file}. Refusing leased push. "
                        "Either rerun a fresh rewrite or explicitly use --force-without-lease."
                    )
                snapshot = capture_remote_snapshot(spec.clone_url, logger)
        else:
            if repo_dir.exists():
                if args.reuse_workdir:
                    logger.info(f"  [warn] Reusing existing rewrite workdir {repo_dir}")
                else:
                    raise GuardError(
                        f"Rewrite workdir already exists: {repo_dir}. Use a new --workdir, remove it, or pass --reuse-workdir."
                    )
            else:
                repo_dir.parent.mkdir(parents=True, exist_ok=True)
                logger.info("  Cloning fresh mirror...")
                run(["git", "clone", "--mirror", "--no-local", spec.clone_url, str(repo_dir)], logger=logger)

            initial_origin = run(["git", "remote", "get-url", "--push", "origin"], cwd=repo_dir, logger=logger).stdout.strip()
            if canonical_remote(initial_origin) != canonical_remote(spec.clone_url):
                raise GuardError(f"Fresh clone origin mismatch: got {initial_origin!r}, expected {spec.clone_url!r}.")

            logger.info("  Capturing remote heads/tags safety snapshot...")
            snapshot = capture_remote_snapshot(spec.clone_url, logger)
            verify_pre_rewrite_snapshot(repo_dir, snapshot, logger)
            logger.info("  Pre-rewrite mirror matches remote snapshot.")
            atomic_write_json(snapshot_file, snapshot)

        old_set = set(old_emails)
        before = exact_identity_hits(repo_dir, old_set, logger)
        result.leaked_before = len(before)
        hidden_before = hidden_pull_identity_hits(repo_dir, old_set, logger)
        result.hidden_ref_matches = len(hidden_before)
        if hidden_before:
            logger.info(
                f"  [warn] {len(hidden_before)} matching commit(s) are reachable from local refs/pull/*. "
                "GitHub manages those refs; this tool will not push them."
            )
            for ex in hidden_before[:5]:
                logger.info(f"    hidden-ref: {ex}")
            if args.fail_on_hidden_refs and not args.push_only:
                raise GuardError(
                    "Selected email identities are reachable from GitHub-managed refs/pull/*. "
                    "Strict --fail-on-hidden-refs mode refuses the rewrite/push because those refs cannot be updated directly."
                )

        if args.push_only:
            if before:
                raise GuardError(
                    f"--push-only refused: {len(before)} selected old-email identity record(s) still exist. Nothing was pushed."
                )
            git_fsck(repo_dir, logger)
        else:
            if not before:
                result.state = "SKIPPED"
                result.message = "None of the selected old emails were found in commit/tag identities."
                return result

            logger.info(f"  Found {len(before)} matching identity record(s).")
            for ex in before[:5]:
                logger.info(f"    {ex}")
            if len(before) > 5:
                logger.info("    ...")

            if args.backup and not args.dry_run:
                stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
                backup_path = root / "backups" / f"{safe}-PRE-REWRITE-{stamp}.bundle"
                result.backup_path = backup_path
                logger.info(f"  Creating and verifying backup: {backup_path}")
                create_backup(repo_dir, backup_path, logger)

            callback = build_email_callback(old_emails, args.new_email)
            cmd = ["git", "filter-repo", "--email-callback", callback]
            if args.dry_run:
                cmd.append("--dry-run")
            logger.info("  Running git-filter-repo" + (" --dry-run..." if args.dry_run else "..."))
            run(cmd, cwd=repo_dir, logger=logger)

            if args.dry_run:
                result.state = "DRY-RUN"
                result.message = f"Would rewrite {len(before)} matching identity record(s); no push performed."
                return result

            ensure_origin(repo_dir, spec.clone_url, logger, allow_remote_change=args.allow_origin_repair)
            remaining = exact_identity_hits(repo_dir, old_set, logger)
            if remaining:
                raise GuardError(
                    f"Verification failed: {len(remaining)} selected old-email identity record(s) remain after rewrite. Nothing was pushed."
                )
            logger.info("  Identity verification passed.")
            git_fsck(repo_dir, logger)
            logger.info("  git fsck passed.")

        if args.no_push:
            result.state = "REWRITTEN-NOT-PUSHED" if not args.push_only else "VERIFIED-NOT-PUSHED"
            result.message = "Local rewritten history verified; push disabled."
            return result

        ensure_origin(repo_dir, spec.clone_url, logger, allow_remote_change=args.allow_origin_repair)
        logger.info(
            "  Pushing normal branches/tags "
            + ("with unconditional --force..." if args.force_without_lease else "with force-with-lease safety...")
        )
        ok, rejected, output = push_refs_with_leases(
            repo_dir,
            snapshot,
            logger,
            force_without_lease=args.force_without_lease,
            prune_remote=args.prune_remote,
            batch_size=args.push_batch_size,
        )
        result.rejected_refs = rejected

        if not ok:
            kind = classify_git_failure(output)
            if kind == "protected":
                result.protected_refs = list(rejected)
                if args.retry_protected and sys.stdin.isatty():
                    print()
                    print(f"{spec.slug}: GitHub blocked one or more refs via protection/rulesets.")
                    answer = input("After enabling an authorized bypass/force-push rule, type RETRY (or Enter to stop): ").strip()
                    if answer == "RETRY":
                        rejected = retry_rejected_refs(
                            repo_dir,
                            rejected,
                            snapshot,
                            logger,
                            force_without_lease=args.force_without_lease,
                        )
                        result.rejected_refs = rejected
                        result.protected_refs = list(rejected)
                        ok = not rejected
                if not ok:
                    result.state = "PARTIAL-PUSH"
                    result.message = "Protected/ruleset-blocked refs remain: " + (", ".join(rejected) or "unknown")
                    return result
            elif kind == "lease-race" and not args.force_without_lease:
                result.state = "RACE-DETECTED"
                result.message = (
                    "Remote refs changed after the pre-rewrite snapshot. The tool refused to overwrite concurrent updates. "
                    "Re-run from a fresh mirror after coordinating with other pushers."
                )
                return result
            else:
                raise GuardError(
                    f"Push was not fully successful ({kind}). Some refs may already be updated; inspect {log_path}."
                )

        mismatches = verify_remote_refs(repo_dir, logger)
        result.remote_mismatches = mismatches
        if mismatches:
            result.state = "PARTIAL-PUSH"
            result.message = "Post-push verification mismatch for: " + ", ".join(mismatches[:20])
            return result

        result.state = "SUCCESS"
        result.pushed = True
        result.message = (
            f"Rewrote {result.leaked_before} matching identity record(s), verified repository integrity, "
            "and verified all local heads/tags on the remote."
        )
        if result.hidden_ref_matches:
            result.message += (
                f" WARNING: {result.hidden_ref_matches} matching commit(s) were reachable from refs/pull/* "
                "before rewriting. Those GitHub-managed refs were not pushed and may retain old history; verify them separately."
            )
        return result

    except GitCommandError as e:
        explanation = explain_git_failure(e)
        logger.info(f"  [ERROR] {explanation}")
        logger.write(e.combined)
        result.state = "FAILED"
        result.message = explanation
        return result
    except (GuardError, OSError, json.JSONDecodeError) as e:
        logger.info(f"  [ERROR] {e}")
        result.state = "FAILED"
        result.message = str(e)
        return result
    except KeyboardInterrupt:
        logger.info("  [INTERRUPTED] User interrupted operation.")
        result.state = "INTERRUPTED"
        result.message = "Interrupted. Inspect the log/workdir before retrying."
        return result
    except Exception as e:
        logger.info(f"  [UNEXPECTED ERROR] {type(e).__name__}: {e}")
        result.state = "FAILED"
        result.message = f"Unexpected {type(e).__name__}: {e}. See log."
        return result


def run_rewrite(
    specs: list[RepoSpec],
    args: argparse.Namespace,
    old_emails: Sequence[str],
) -> list[RewriteResult]:
    check_git(need_filter_repo=not args.push_only)
    if not old_emails:
        raise GuardError("No old email addresses selected for rewrite.")
    old_emails = list(dict.fromkeys(old_emails))
    if args.new_email.casefold() in {e.casefold() for e in old_emails}:
        raise GuardError("--new-email must differ from every selected old email.")
    confirm_rewrite(args, specs, old_emails)
    root = args.workdir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    results: list[RewriteResult] = []
    for spec in specs:
        r = process_rewrite_repo(spec, args, root, old_emails)
        results.append(r)
        print(f"[{r.state}] {r.repo}: {r.message}")
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_scan_report(report: ScanReport, *, max_occurrences: int = 10) -> None:
    print()
    print(f"Scan source: {report.source}")
    print(f"Repositories: {len(report.repos)}")
    print(f"Unique commits inspected: {report.unique_commits}")
    print(f"Distinct matching email(s): {len(report.findings)}")
    if not report.findings:
        print("OK: no matching email identities found.")
    else:
        print()
        for email_key, occs in sorted(report.findings.items()):
            display_email = occs[0].email if occs else email_key
            users = sorted({o.github_user for o in occs if o.github_user})
            user_text = f" (GitHub: {', '.join('@' + u for u in users)})" if users else ""
            print(f"{display_email}{user_text} — {len(occs)} occurrence(s)")
            for o in occs[:max_occurrences]:
                loc = o.ref or (f"{o.repo}@{o.sha[:10]}" if o.sha else o.repo)
                extra = f" branch={o.branch}" if o.branch else ""
                print(f"  [{o.role:9s}] {loc}{extra} {o.date or ''} {o.message or ''}".rstrip())
                if o.patch_url:
                    print(f"             {o.patch_url}")
            if len(occs) > max_occurrences:
                print(f"  ... and {len(occs) - max_occurrences} more")

    warnings = [s for s in report.repo_statuses if s.state in {"FAILED", "PARTIAL"}]
    if warnings:
        print()
        print(f"Warnings/failures: {len(warnings)} repository/repositories")
        for s in warnings:
            print(f"  [{s.state}] {s.repo}: {s.message}")
            for p in s.partial_failures[:5]:
                print(f"      - {p}")
            if len(s.partial_failures) > 5:
                print(f"      ... and {len(s.partial_failures) - 5} more")


def write_report_if_requested(path: Optional[Path], payload: Any) -> None:
    if path:
        atomic_write_json(path.expanduser().resolve(), payload)
        print(f"JSON report: {path.expanduser().resolve()}", file=sys.stderr)


def rewrite_exit_code(results: list[RewriteResult]) -> int:
    bad = {"FAILED", "INTERRUPTED", "PARTIAL-PUSH", "RACE-DETECTED"}
    return 2 if any(r.state in bad for r in results) else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def add_repo_inputs(p: argparse.ArgumentParser, *, allow_account: bool = True) -> None:
    if allow_account:
        p.add_argument("--account", help="GitHub user or organization; repositories are discovered via REST API.")
    p.add_argument("repos", nargs="*", help="Repositories as OWNER/REPO, bare name with --owner, or GitHub clone URL.")
    p.add_argument("--repo", action="append", default=[], help="Additional repository; repeat as needed.")
    p.add_argument("--repo-file", type=Path, help="Text file with one repository per line; # comments allowed.")
    p.add_argument("--owner", help="Owner used for bare repository names.")
    p.add_argument("--protocol", choices=("ssh", "https"), default="ssh", help="Clone/push protocol for normalized repo inputs.")


def add_api_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--token", help="GitHub token. Default: $GITHUB_TOKEN.")
    p.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy. Default: $GITHUB_PROXY/$HTTPS_PROXY.")
    p.add_argument("--concurrency", type=int, default=8, metavar="N", help="Max in-flight HTTP requests (default: 8).")
    p.add_argument("--repo-concurrency", type=int, default=4, metavar="N", help="Max repositories scanned concurrently (default: 4).")
    p.add_argument("--branch-concurrency", type=int, default=4, metavar="N", help="Max branch tasks per repository (default: 4).")
    p.add_argument("--retries", type=int, default=6, metavar="N", help="HTTP attempts for transient errors (default: 6).")
    p.add_argument("--timeout", type=float, default=60.0, metavar="SEC", help="HTTP request timeout (default: 60).")
    p.add_argument("--max-backoff", type=float, default=60.0, metavar="SEC", help="Maximum automatic backoff wait (default: 60).")
    p.add_argument("--api-version", default=DEFAULT_API_VERSION, help=f"GitHub REST API version (default: {DEFAULT_API_VERSION}).")
    p.add_argument("--include-forks", action="store_true", help="Include forked repositories during account discovery.")
    p.add_argument("--include-archived", action="store_true", help="Include archived repositories during account discovery.")
    p.add_argument("--include-private", action="store_true", help="Include token-visible private repos when discovery endpoint supports it.")


def add_scan_filter_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--match-email", action="append", type=validate_email, help="Only report this exact email; repeatable.")
    p.add_argument("--ignore-email", action="append", type=validate_email, help="Ignore this exact email; repeatable.")
    p.add_argument("--email-regex", help="Only report emails matching this case-insensitive regex.")
    p.add_argument("--include-noreply", action="store_true", help="Also report GitHub noreply identities.")
    p.add_argument("--json-report", type=Path, help="Write a complete JSON report to this file.")
    p.add_argument("--max-occurrences", type=int, default=10, help="Max occurrences printed per email (JSON remains complete).")


def add_rewrite_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--old-email", action="append", type=validate_email, help="Exact old email to rewrite; repeatable.")
    p.add_argument("--new-email", required=True, type=validate_email, help="Replacement email, usually GitHub users.noreply address.")
    p.add_argument("--workdir", type=Path, default=Path(DEFAULT_WORKDIR), help=f"Work directory (default: ./{DEFAULT_WORKDIR}).")
    p.add_argument("--dry-run", action="store_true", help="Run git-filter-repo --dry-run; never push.")
    p.add_argument("--no-push", action="store_true", help="Rewrite and verify locally but do not push.")
    p.add_argument("--no-backup", dest="backup", action="store_false", help="Disable verified pre-rewrite bundle backup.")
    p.set_defaults(backup=True)
    p.add_argument("--allow-origin-repair", action="store_true", help="Allow resetting an unexpected origin to the requested repository.")
    p.add_argument("--retry-protected", action="store_true", help="Interactively retry refs rejected by branch/ruleset protection.")
    p.add_argument("--push-only", action="store_true", help="Reuse an already rewritten mirror: verify then push; no rewrite.")
    p.add_argument("--reuse-workdir", action="store_true", help="Reuse existing mirrors. Fresh mirrors are safer for rewriting.")
    p.add_argument("--force-without-lease", action="store_true", help="DANGEROUS: use unconditional --force instead of remote-snapshot leases.")
    p.add_argument("--prune-remote", action="store_true", help="Also delete remote heads/tags absent locally. Off by default for safety.")
    p.add_argument(
        "--fail-on-hidden-refs",
        action="store_true",
        help="Refuse rewrite/push if selected identities are reachable from GitHub-managed refs/pull/*.",
    )
    p.add_argument("--push-batch-size", type=int, default=40, metavar="N", help="Refs per git push command (default: 40).")
    p.add_argument("--yes", action="store_true", help="Skip REWRITE confirmation for destructive remote updates.")
    p.add_argument("--verbose", action="store_true", help="Echo detailed commands in addition to per-repository logs.")
    p.add_argument("--rewrite-json-report", type=Path, help="Write rewrite results as JSON.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Scan GitHub/Git history for exposed email identities and safely rewrite selected addresses.",
        epilog=textwrap.dedent(
            """
            Examples:
              # Fast account scan (public + token-visible repos when applicable)
              github_email_guard.py scan --account USER --include-forks

              # Deep Git scan including annotated tagger emails
              github_email_guard.py deep-scan --account USER --workdir guard-work

              # Rewrite one exact email in explicit repositories, verify locally first
              github_email_guard.py rewrite OWNER/repo1 OWNER/repo2 \\
                  --old-email old@example.com \\
                  --new-email 123+user@users.noreply.github.com --no-push

              # Scan account and rewrite ONLY explicitly selected leaked emails
              github_email_guard.py scan-rewrite --account USER \\
                  --old-email old@example.com \\
                  --new-email 123+user@users.noreply.github.com --no-push

              # Scan account and explicitly choose every non-noreply finding for replacement
              github_email_guard.py scan-rewrite --account USER \\
                  --replace-all-found \\
                  --new-email 123+user@users.noreply.github.com --no-push
            """
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Fast async GitHub REST API scanner.")
    add_repo_inputs(scan)
    add_api_options(scan)
    add_scan_filter_options(scan)
    scan.add_argument("--verbose", action="store_true")

    deep = sub.add_parser("deep-scan", help="Mirror-clone and inspect commits + annotated tagger identities.")
    add_repo_inputs(deep)
    add_api_options(deep)  # used only if --account discovery is requested
    add_scan_filter_options(deep)
    deep.add_argument("--workdir", type=Path, default=Path(DEFAULT_WORKDIR))
    deep.add_argument("--reuse-workdir", action="store_true")
    deep.add_argument("--verbose", action="store_true")

    rewrite = sub.add_parser("rewrite", help="Rewrite exact selected emails using git-filter-repo.")
    add_repo_inputs(rewrite)
    add_api_options(rewrite)  # used only if --account discovery is requested
    add_rewrite_options(rewrite)

    combo = sub.add_parser("scan-rewrite", help="Scan first, then safely rewrite selected findings.")
    add_repo_inputs(combo)
    add_api_options(combo)
    add_scan_filter_options(combo)
    add_rewrite_options(combo)
    combo.add_argument(
        "--replace-all-found",
        action="store_true",
        help="Explicitly rewrite every email found by the scan (excluding ignored/noreply filters).",
    )
    combo.add_argument(
        "--only-repos-with-findings",
        action="store_true",
        help="Rewrite only repositories where the scan found a selected email.",
    )

    return p


def api_config_from_args(args: argparse.Namespace) -> ApiConfig:
    proxy = (
        args.proxy
        or os.environ.get("GITHUB_PROXY")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
    )
    token = args.token or os.environ.get("GITHUB_TOKEN")
    if proxy:
        print(f"note: routing GitHub API via proxy {mask_proxy(proxy)} (credentials hidden)", file=sys.stderr)
    if not token:
        print("note: no GitHub token configured; rate limits and private-repo visibility will be lower", file=sys.stderr)
    return ApiConfig(
        token=token,
        proxy=proxy,
        concurrency=max(1, args.concurrency),
        retries=max(1, args.retries),
        timeout=max(1.0, args.timeout),
        max_backoff=max(0.0, args.max_backoff),
        api_version=args.api_version,
        verbose=bool(getattr(args, "verbose", False)),
    )


async def resolve_specs_async(args: argparse.Namespace, config: ApiConfig) -> list[RepoSpec]:
    raw = gather_raw_repos(args)
    explicit = [normalize_repo(x, args.owner, args.protocol) for x in raw]
    discovered: list[RepoSpec] = []
    if getattr(args, "account", None):
        async with GitHubApiClient(config) as client:
            discovered = await discover_account_repositories(
                client,
                args.account,
                include_forks=args.include_forks,
                include_archived=args.include_archived,
                include_private=args.include_private,
            )
            # honor requested clone protocol for discovered repos
            for s in discovered:
                s.clone_url = (
                    f"git@github.com:{s.slug}.git"
                    if args.protocol == "ssh"
                    else f"https://github.com/{s.slug}.git"
                )
    combined: dict[str, RepoSpec] = {}
    for s in discovered + explicit:
        combined[s.slug.casefold()] = s
    specs = list(combined.values())
    if not specs:
        raise GuardError("No repositories supplied/discovered. Use --account, repository arguments, --repo, or --repo-file.")
    return specs


def validate_common_args(args: argparse.Namespace) -> None:
    if hasattr(args, "dry_run") and args.dry_run and args.no_push:
        raise GuardError("--dry-run and --no-push are redundant; choose one.")
    if hasattr(args, "push_only") and args.push_only and not args.reuse_workdir:
        raise GuardError("--push-only requires --reuse-workdir.")
    if hasattr(args, "push_only") and args.push_only and args.dry_run:
        raise GuardError("--push-only cannot be combined with --dry-run.")
    if hasattr(args, "push_batch_size") and args.push_batch_size < 1:
        raise GuardError("--push-batch-size must be at least 1.")
    if hasattr(args, "max_occurrences") and args.max_occurrences < 0:
        raise GuardError("--max-occurrences cannot be negative.")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        validate_common_args(args)
        config = api_config_from_args(args)
        specs = asyncio.run(resolve_specs_async(args, config))

        if args.command == "scan":
            report = asyncio.run(
                run_api_scan(
                    specs,
                    account=args.account,
                    api_config=config,
                    email_filter=make_email_filter(args),
                    repo_task_limit=max(1, args.repo_concurrency),
                    branch_task_limit=max(1, args.branch_concurrency),
                )
            )
            print_scan_report(report, max_occurrences=args.max_occurrences)
            write_report_if_requested(args.json_report, report)
            if report.failure_count:
                return 2
            return 1 if report.findings else 0

        if args.command == "deep-scan":
            root = args.workdir.expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            report = run_deep_scan(
                specs,
                account=args.account,
                root=root,
                email_filter=make_email_filter(args),
                protocol=args.protocol,
                reuse_workdir=args.reuse_workdir,
                verbose=args.verbose,
            )
            print_scan_report(report, max_occurrences=args.max_occurrences)
            write_report_if_requested(args.json_report, report)
            if report.failure_count:
                return 2
            return 1 if report.findings else 0

        if args.command == "rewrite":
            old = list(dict.fromkeys(args.old_email or []))
            if not old:
                raise GuardError("rewrite requires at least one --old-email.")
            results = run_rewrite(specs, args, old)
            write_report_if_requested(args.rewrite_json_report, results)
            return rewrite_exit_code(results)

        if args.command == "scan-rewrite":
            # If exact old emails were provided, scan only those unless user also supplied
            # an explicit regex/other scan filter. This keeps the scan focused and avoids
            # accidentally treating unrelated identities as candidates.
            if args.old_email and not args.match_email and not args.email_regex:
                args.match_email = list(args.old_email)
            report = asyncio.run(
                run_api_scan(
                    specs,
                    account=args.account,
                    api_config=config,
                    email_filter=make_email_filter(args),
                    repo_task_limit=max(1, args.repo_concurrency),
                    branch_task_limit=max(1, args.branch_concurrency),
                )
            )
            print_scan_report(report, max_occurrences=args.max_occurrences)
            write_report_if_requested(args.json_report, report)
            if report.failure_count:
                raise GuardError(
                    "scan-rewrite refuses to continue while any repository scan is partial/failed. "
                    "Resolve scan errors first so the rewrite target set is complete."
                )

            if args.replace_all_found:
                old = [occs[0].email for _, occs in sorted(report.findings.items()) if occs]
            else:
                old = list(dict.fromkeys(args.old_email or []))
                if not old:
                    print("\nNo rewrite requested: supply --old-email or explicitly use --replace-all-found.")
                    return 1 if report.findings else 0

            if not old:
                print("\nNothing matched the selected rewrite criteria; no history was changed.")
                return 0

            rewrite_specs = specs
            if args.only_repos_with_findings:
                selected = {e.casefold() for e in old}
                repos_with = {
                    o.repo.casefold()
                    for email_key, occs in report.findings.items()
                    if email_key.casefold() in selected
                    for o in occs
                }
                rewrite_specs = [s for s in specs if s.slug.casefold() in repos_with]
                if not rewrite_specs:
                    print("\nNo repositories contain the selected email(s); no history was changed.")
                    return 0

            results = run_rewrite(rewrite_specs, args, old)
            write_report_if_requested(args.rewrite_json_report, results)
            return rewrite_exit_code(results)

        raise GuardError(f"Unknown command: {args.command}")

    except ApiRateLimit as e:
        reset = ""
        if e.reset_epoch:
            try:
                reset = " Reset: " + dt.datetime.fromtimestamp(e.reset_epoch, tz=dt.timezone.utc).isoformat()
            except Exception:
                pass
        print(f"ERROR: {e}{reset}", file=sys.stderr)
        return 3
    except (ApiAuthError, ApiPermissionError, ApiVersionError, ApiValidationError, ApiNetworkError, ApiError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except DependencyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 4
    except GuardError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
