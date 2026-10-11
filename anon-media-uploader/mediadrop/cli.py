"""Command line interface: argument parsing and the commands."""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import hashlib
import json
import logging
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Optional, Sequence

from . import VERSION, rehash
from .checker import CHECK_HISTORY, DEAD_STATES, check_entry, classify
from .engine import Engine
from .hosts import HOST_GROUPS, HOSTS, UploadOptions, host_for_url, is_group_spec, resolve_hosts
from .manifest import LinkWriter, Manifest
from .media import expand_inputs
from .net import Net, Proxy, ProxyConnector, normalize_scheme, parse_proxy
from .proxies import FREE_PROXY_SOURCES, ProxyPool, ProxySettings
from .selection import KEEP_CHOICES, HostSelector, RetentionPolicy
from .uploader import UploadService, UploadSettings
from .util import MiB, ToolError, UploadError, duration_arg, human_duration, human_size, print_table

try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None  # type: ignore

log = logging.getLogger("media_drop")
DEFAULT_MANIFEST = "media_hashes.json"


# ---------------------------------------------------------------------------
# upload / file
# ---------------------------------------------------------------------------


async def run_upload(args: argparse.Namespace, engine: Engine, kind: str) -> int:
    media_only = kind == "image"
    paths = expand_inputs(args.inputs, args.recursive, media_only=media_only)
    if not paths:
        raise ToolError("nothing to upload")
    default_spec = "permanent" if media_only else "files"
    spec = args.hosts or default_spec
    hosts = resolve_hosts(spec)
    explicit = not is_group_spec(spec)
    for h in hosts:
        ok, why = h.available()
        if not ok and explicit:
            log.warning("%s skipped: %s", h.name, why)
    opts = UploadOptions(expire=args.expire, nsfw=getattr(args, "nsfw", False), secret_urls=args.secret_urls)
    policy = RetentionPolicy(keep=getattr(args, "keep", "any"), min_life=getattr(args, "min_life", None), max_life=getattr(args, "max_life", None))
    selector = HostSelector(hosts, policy, opts, sort_by_life=not media_only and not explicit)
    manifest = Manifest(Path(args.save_hashes)) if args.save_hashes else None
    links = LinkWriter(Path(args.save_links)) if args.save_links else None
    settings = UploadSettings(
        kind=kind, mirrors=args.mirror, all_hosts=args.all, opts=opts, hash_mode=args.change_hash,
        unique_per_host=args.unique_per_host, strip=getattr(args, "strip_metadata", False), keep_name=args.keep_name,
        verify=(bool(manifest) and not args.no_verify) or args.verify, force=args.force,
        max_download=args.max_download * MiB, dh_threshold=args.dhash_threshold, concurrency=args.concurrency,
        quiet_stdout=args.json,
    )
    if args.unique_per_host and args.change_hash == "none":
        raise ToolError("--unique-per-host needs --change-hash safe|append|wrap")
    service = UploadService(engine, selector, settings, manifest, links)
    try:
        results, failures = await service.run(paths)
    finally:
        engine.pool.save_cache()
    if args.json:
        print(json.dumps({"uploads": results, "failed_files": failures}, indent=2))
    if manifest:
        log.info("hashes saved to %s (%d records)", manifest.path, len(manifest.records))
    if links and links.path.exists():
        log.info("links saved to %s", links.path)
    return 1 if failures and not results else (3 if failures else 0)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


async def cmd_check(args: argparse.Namespace, engine: Engine) -> int:
    manifest: Optional[Manifest] = None
    records: list[dict[str, Any]] = []
    if args.urls:
        for i, u in enumerate(args.urls):
            h = host_for_url(u)
            rec: dict[str, Any] = {"id": f"url{i + 1}", "host": h.name if h else urllib.parse.urlsplit(u).netloc, "url": u, "file": {}}
            if args.expect_sha256:
                rec["file"]["sha256"] = args.expect_sha256.lower()
            records.append(rec)
    else:
        path = Path(args.manifest)
        if not path.exists():
            raise ToolError(f"manifest {path} not found (upload with --save-hashes first, or pass URLs)")
        manifest = Manifest(path)
        records = list(manifest.records)
    if args.host:
        wanted = {h.name for h in resolve_hosts(args.host)}
        records = [r for r in records if r.get("host") in wanted]
    if args.status:
        wanted_status = {s.strip() for s in args.status.split(",")}
        records = [r for r in records if r.get("status", "uploaded") in wanted_status]
    if args.id:
        records = [r for r in records if r.get("id") in set(args.id)]
    if args.kind:
        records = [r for r in records if r.get("kind", "image") == args.kind]
    if not records:
        log.warning("no records to check")
        return 0

    verdicts: dict[str, tuple[str, str]] = {}
    if not args.no_host_api:
        by_host: dict[str, list[dict[str, Any]]] = {}
        for r in records:
            by_host.setdefault(r.get("host", ""), []).append(r)
        for name, recs in by_host.items():
            if name in HOSTS:
                verdicts.update(await HOSTS[name].batch_status(engine, recs))

    sem = asyncio.Semaphore(max(1, args.concurrency))
    rows: list[dict[str, Any]] = []

    async def one(rec: dict[str, Any]) -> None:
        async with sem:
            host = HOSTS.get(rec.get("host", ""))
            if rec.get("id") in verdicts:
                status, detail = verdicts[rec["id"]]
                entry = check_entry(rec, None, status, detail, "api")
            else:
                try:
                    out, via = await engine.probe(host, rec, max_bytes=args.max_download * MiB, quick=args.quick, label=f"[{rec.get('host')}] check")
                    status, detail = classify(rec, out, host, args.dhash_threshold)
                    entry = check_entry(rec, out, status, detail, via)
                except UploadError as exc:
                    entry = check_entry(rec, None, "error", str(exc), "-")
            prev = rec.get("status")
            rec["status"] = entry["status"]
            rec["last_checked"] = entry["at"]
            if entry["status"] in DEAD_STATES and not rec.get("first_seen_dead"):
                rec["first_seen_dead"] = entry["at"]
            rec.setdefault("checks", []).append(entry)
            rec["checks"] = rec["checks"][-CHECK_HISTORY:]
            rows.append({"id": rec.get("id"), "host": rec.get("host"), "status": entry["status"], "previous": prev,
                         "url": rec.get("url"), "detail": entry["detail"]})
            log.info("[%s] %s %s - %s", rec.get("host"), entry["status"].upper(), rec.get("url"), entry["detail"])
            if manifest and not args.no_update:
                async with manifest.lock:
                    manifest.save()

    try:
        await asyncio.gather(*(one(r) for r in records))
    finally:
        engine.pool.save_cache()
    order = {r.get("id"): i for i, r in enumerate(records)}
    rows.sort(key=lambda r: order.get(r["id"], 0))
    if args.json:
        print(json.dumps({"checked": len(rows), "results": rows}, indent=2))
    else:
        print_table([(r["id"], r["host"], r["status"], r["url"], r["detail"][:70]) for r in rows], ["id", "host", "status", "url", "detail"])
        summary: dict[str, int] = {}
        for r in rows:
            summary[r["status"]] = summary.get(r["status"], 0) + 1
        print("\n" + ", ".join(f"{k}: {v}" for k, v in sorted(summary.items())))
    bad = [r for r in rows if r["status"] in DEAD_STATES or r["status"] == "changed"]
    return 2 if bad else 0


# ---------------------------------------------------------------------------
# list / hosts / proxies / restore
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    path = Path(args.manifest)
    if not path.exists():
        raise ToolError(f"manifest {path} not found")
    recs = Manifest(path).records
    if args.host:
        wanted = {h.name for h in resolve_hosts(args.host)}
        recs = [r for r in recs if r.get("host") in wanted]
    if args.kind:
        recs = [r for r in recs if r.get("kind", "image") == args.kind]
    if args.json:
        print(json.dumps(recs, indent=2, ensure_ascii=False))
        return 0
    cols = ["id", "kind", "host", "status", "uploaded_at", "expires_at", "last_checked", "file", "size", "md5", "sha1",
            "sha256", "original_sha256", "hash_change", "dhash", "url", "page_url", "delete_url"]
    flat = []
    for r in recs:
        f = r.get("file", {})
        flat.append({
            "id": r.get("id"), "kind": r.get("kind", "image"), "host": r.get("host"), "status": r.get("status"),
            "uploaded_at": r.get("uploaded_at"), "expires_at": r.get("expires_at"), "last_checked": r.get("last_checked"),
            "file": f.get("name"), "size": f.get("size"), "md5": f.get("md5"), "sha1": f.get("sha1"), "sha256": f.get("sha256"),
            "original_sha256": (f.get("original") or {}).get("sha256"), "hash_change": (f.get("hash_change") or {}).get("method"),
            "dhash": f.get("dhash"), "url": r.get("url"), "page_url": r.get("page_url"), "delete_url": r.get("delete_url"),
        })
    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=cols)
        w.writeheader()
        w.writerows(flat)
        return 0
    print_table([(r["id"], r["kind"], r["host"], r["status"], r["file"], (r["sha256"] or "")[:16], r["url"]) for r in flat],
                ["id", "kind", "host", "status", "file", "sha256", "url"])
    return 0


def cmd_hosts(args: argparse.Namespace) -> int:
    hosts = resolve_hosts(args.group) if args.group else list(HOSTS.values())
    opts = UploadOptions()
    rows = []
    for h in hosts:
        ok, why = h.available()
        life = h.lifetime(10 * MiB, opts)
        rows.append((
            h.name, h.label, "temp" if h.temporary else "perm", h.accepts_label or ("images" if h.images_only else "any file"),
            human_size(h.max_size) if h.max_size else "-", h.retention, human_duration(life) if life else "-",
            "yes" if ok else f"no ({why})", h.notes,
        ))
    print_table(rows, ["name", "site", "type", "accepts", "max", "retention", "10MiB file", "usable", "notes"])
    print("\ngroups: " + ", ".join(f"{g} ({len(v)})" for g, v in HOST_GROUPS.items()))
    return 0


async def cmd_proxies(args: argparse.Namespace, engine: Engine) -> int:
    pool = engine.pool
    if pool.cfg.mode != "free":
        raise ToolError("`proxies` works with the free proxy pool (drop --direct/--tor/--proxy)")
    if args.list_sources:
        print_table([(n, s, u) for n, u, s, _ in FREE_PROXY_SOURCES + pool.cfg.extra_sources], ["name", "default", "url"])
        return 0
    if args.refresh:
        pool.good = []
    if args.retest and pool.good:
        log.info("re-testing %d cached proxies ...", len(pool.good))
        results = await asyncio.gather(*(pool.test_proxy(p) for p in pool.good))
        pool.good = [p for p, ok in zip(pool.good, results) if ok]
    await pool.refill(args.count or pool.cfg.pool_size)
    ranked = sorted(pool.good, key=Proxy.score)
    if args.export:
        Path(args.export).write_text("\n".join(p.label for p in ranked) + "\n", encoding="utf-8")
        log.info("exported %d proxies to %s", len(ranked), args.export)
    if args.json:
        print(json.dumps([p.to_json() for p in ranked], indent=2))
    else:
        print_table([(p.label, f"{p.latency:.2f}s" if p.latency else "-", p.exit_ip, p.source, p.ok, p.fail) for p in ranked],
                    ["proxy", "latency", "exit ip", "source", "ok", "fail"])
    return 0 if ranked else 1


def cmd_restore(args: argparse.Namespace) -> int:
    manifest = Manifest(Path(args.manifest)) if args.manifest and Path(args.manifest).exists() else None
    outdir = Path(args.output) if args.output else None
    failures = 0
    for item in args.files:
        p = Path(item)
        data = p.read_bytes()
        res = rehash.restore(data)
        if not res:
            log.error("%s: no media_drop hash-change marker found", p)
            failures += 1
            continue
        original, method, inner = res
        name = inner or (p.stem + ".restored" + p.suffix)
        dest = (outdir or p.parent) / Path(name).name
        if dest.resolve() == p.resolve():
            dest = dest.with_name(dest.stem + ".restored" + dest.suffix)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(original)
        sha = hashlib.sha256(original).hexdigest()
        note = ""
        if manifest:
            rec = manifest.by_uploaded_sha256(hashlib.sha256(data).hexdigest())
            f = (rec or {}).get("file", {})
            expected = (f.get("hash_change") or {}).get("restores_to") or (f.get("original") or {}).get("sha256")
            if expected:
                note = " (matches the pre-upload file in manifest)" if expected == sha else " (DOES NOT match the manifest!)"
        print(f"{dest}  [{method}] sha256 {sha}{note}")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _net_parent() -> argparse.ArgumentParser:
    net = argparse.ArgumentParser(add_help=False)
    g = net.add_argument_group("network / proxy")
    g.add_argument("--direct", action="store_true", help="no proxy (system HTTP(S)_PROXY is still honoured)")
    g.add_argument("--tor", nargs="?", const="127.0.0.1:9050", metavar="HOST:PORT", help="route through Tor SOCKS (new circuit per attempt); default 127.0.0.1:9050")
    g.add_argument("--proxy", action="append", default=[], metavar="URL", help="use your own proxy (http://, socks5://user:pass@...); repeatable")
    g.add_argument("--proxy-file", metavar="FILE", help="file with one proxy per line")
    g.add_argument("--proxy-source", action="append", default=[], metavar="[SCHEME=]URL", help="extra free-proxy list URL, e.g. socks5=https://.../list.txt")
    g.add_argument("--protocols", default=None, help="free proxy protocols: http,socks4,socks5 (default http,socks5 with aiohttp-socks)")
    g.add_argument("--pool-size", type=int, default=20, help="working free proxies to keep (default 20)")
    g.add_argument("--proxy-timeout", type=float, default=8.0, help="seconds per proxy validation (default 8)")
    g.add_argument("--test-concurrency", type=int, default=150, help="parallel proxy validations (default 150)")
    g.add_argument("--max-test", type=int, default=6000, help="max candidates to test per refill (default 6000)")
    g.add_argument("--cache-ttl", type=duration_arg, default=dt.timedelta(minutes=30), help="reuse validated proxies for this long (default 30m)")
    g.add_argument("--no-cache", action="store_true", help="ignore and do not write the proxy cache")
    g.add_argument("--no-leak-check", action="store_true", help="skip discarding proxies whose exit IP equals yours")
    g.add_argument("--allow-direct-fallback", action="store_true", help="go direct when no proxy works (off by default)")
    g.add_argument("--timeout", type=float, default=45.0, help="base request timeout in seconds (default 45)")
    g.add_argument("--connect-timeout", type=float, default=12.0, help="TCP/proxy connect timeout (default 12)")
    g.add_argument("--retries", type=int, default=6, help="attempts per host / per check, rotating proxies (default 6)")
    g.add_argument("--user-agent", help="fixed User-Agent instead of rotating")
    g.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    g.add_argument("-q", "--quiet", action="store_true", help="only errors on stderr")
    return net


def _upload_parent() -> argparse.ArgumentParser:
    up = argparse.ArgumentParser(add_help=False)
    g = up.add_argument_group("upload")
    g.add_argument("inputs", nargs="+", help="files or directories")
    g.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    g.add_argument("--all", action="store_true", help="upload to every matching host")
    g.add_argument("--save-hashes", nargs="?", const=DEFAULT_MANIFEST, metavar="FILE", help=f"record hashes + links per host (default {DEFAULT_MANIFEST})")
    g.add_argument("--save-links", nargs="?", const="links.txt", metavar="FILE", help="append the links to a text file (default links.txt)")
    g.add_argument("--change-hash", choices=rehash.MODES, default="none", help="none (default): as-is; safe: format-aware marker; append: trailing marker; wrap: inside a zip")
    g.add_argument("--unique-per-host", action="store_true", help="with --change-hash: a different hash on every host")
    g.add_argument("--verify", action="store_true", help="re-download after upload and compare hashes (default with --save-hashes)")
    g.add_argument("--no-verify", action="store_true", help="with --save-hashes: skip the re-download check")
    g.add_argument("--force", action="store_true", help="re-upload even if the manifest has a live copy on that host")
    g.add_argument("--keep-name", action="store_true", help="keep the original filename (default: random name)")
    g.add_argument("--expire", type=duration_arg, metavar="DURATION", help="ask hosts that support it to delete after e.g. 1h, 3d, 30d")
    g.add_argument("--secret-urls", action="store_true", help="longer unguessable URLs where supported (0x0, x0)")
    g.add_argument("--concurrency", type=int, default=3, help="files uploaded in parallel (default 3)")
    g.add_argument("--max-download", type=int, default=64, metavar="MiB", help="verify downloads up to this size (default 64)")
    g.add_argument("--dhash-threshold", type=int, default=6, help="max dHash distance counted as 'same image' (default 6)")
    g.add_argument("--json", action="store_true", help="JSON output on stdout")
    return up


def build_parser() -> argparse.ArgumentParser:
    net, upl = _net_parent(), _upload_parent()
    p = argparse.ArgumentParser(
        prog="media_drop.py",
        description="Upload images and files to free hosts through rotating free proxies, save hashes, and check links later.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
        "  media_drop.py upload cat.jpg --all --save-hashes\n"
        "  media_drop.py file backup.zip --mirror 3 --save-links\n"
        "  media_drop.py file big.iso --keep temp --change-hash safe --unique-per-host --save-hashes\n"
        "  media_drop.py file notes.pdf --keep perm --min-life 30d\n"
        "  media_drop.py check\n"
        "  media_drop.py restore downloaded.pdf\n",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("upload", parents=[upl, net], help="upload images/media (image + file hosts)")
    up.add_argument("--hosts", help="comma list of hosts/groups; order = failover order (default: permanent)")
    up.add_argument("--mirror", type=int, default=1, help="upload each file to N hosts (default 1)")
    up.add_argument("--strip-metadata", action="store_true", help="remove EXIF/GPS/XMP from still images (needs Pillow)")
    up.add_argument("--nsfw", action="store_true", help="flag content as adult on hosts that require it")

    fl = sub.add_parser("file", parents=[upl, net], help="upload any file to file hosts (picked by size and retention)")
    fl.add_argument("--hosts", help="comma list of hosts/groups (default: all file hosts, auto-ranked)")
    fl.add_argument("--mirror", type=int, default=3, help="upload each file to N hosts (default 3)")
    fl.add_argument("--keep", choices=KEEP_CHOICES, default="any", help="perm: permanent hosts only, temp: temporary only, any (default)")
    fl.add_argument("--min-life", type=duration_arg, metavar="DURATION", help="only hosts expected to keep the file at least this long (e.g. 30d)")
    fl.add_argument("--max-life", type=duration_arg, metavar="DURATION", help="only hosts that delete the file within this time (e.g. 1d)")

    ck = sub.add_parser("check", parents=[net], help="check uploads are still online and unmodified")
    ck.add_argument("urls", nargs="*", help="ad-hoc URLs instead of a manifest")
    ck.add_argument("--manifest", default=DEFAULT_MANIFEST, help=f"manifest to check and update (default {DEFAULT_MANIFEST})")
    ck.add_argument("--expect-sha256", help="for ad-hoc URLs: expected SHA-256")
    ck.add_argument("--host", help="only these hosts/groups")
    ck.add_argument("--kind", choices=("image", "file"), help="only image or file uploads")
    ck.add_argument("--status", help="only records whose last status is in this comma list (e.g. intact,alive,error)")
    ck.add_argument("--id", action="append", help="only this record id (repeatable)")
    ck.add_argument("--quick", action="store_true", help="status-only check (first 1 KiB), no hash comparison")
    ck.add_argument("--no-update", action="store_true", help="do not write results back to the manifest")
    ck.add_argument("--no-host-api", action="store_true", help="skip host status APIs (pixhost)")
    ck.add_argument("--concurrency", type=int, default=6, help="parallel checks (default 6)")
    ck.add_argument("--max-download", type=int, default=64, metavar="MiB", help="hash files up to this size (default 64)")
    ck.add_argument("--dhash-threshold", type=int, default=6, help="max dHash distance counted as 'same image' (default 6)")
    ck.add_argument("--json", action="store_true", help="JSON output on stdout")

    ls = sub.add_parser("list", help="show manifest records")
    ls.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ls.add_argument("--host", help="only these hosts/groups")
    ls.add_argument("--kind", choices=("image", "file"))
    out = ls.add_mutually_exclusive_group()
    out.add_argument("--csv", action="store_true", help="CSV with all hashes on stdout")
    out.add_argument("--json", action="store_true", help="raw JSON records")

    hs = sub.add_parser("hosts", help="list supported hosts")
    hs.add_argument("group", nargs="?", help="only this host group (permanent, temporary, images, files)")

    px = sub.add_parser("proxies", parents=[net], help="fetch/validate/export the free proxy pool")
    px.add_argument("--count", type=int, help="how many working proxies to find (default --pool-size)")
    px.add_argument("--refresh", action="store_true", help="ignore cached proxies and validate fresh ones")
    px.add_argument("--retest", action="store_true", help="re-test cached proxies before topping up")
    px.add_argument("--export", metavar="FILE", help="write working proxies, one per line")
    px.add_argument("--list-sources", action="store_true", help="show the built-in proxy list sources")
    px.add_argument("--json", action="store_true", help="JSON output on stdout")

    rs = sub.add_parser("restore", help="undo --change-hash on downloaded files (gives back the original bytes)")
    rs.add_argument("files", nargs="+")
    rs.add_argument("-o", "--output", metavar="DIR", help="write restored files here (default: next to the input)")
    rs.add_argument("--manifest", default=DEFAULT_MANIFEST, help="compare against the original hash recorded here")

    for sp in (ls, hs, rs):
        sp.add_argument("-v", "--verbose", action="count", default=0)
        sp.add_argument("-q", "--quiet", action="store_true")
    return p


def proxy_settings(args: argparse.Namespace) -> ProxySettings:
    custom: list[Proxy] = []
    for item in args.proxy:
        p = parse_proxy(item)
        if not p:
            raise ToolError(f"bad --proxy {item!r}")
        custom.append(p)
    if args.proxy_file:
        for line in Path(args.proxy_file).read_text(encoding="utf-8").splitlines():
            p = parse_proxy(line, source=Path(args.proxy_file).name)
            if p:
                custom.append(p)
        if not custom:
            raise ToolError(f"{args.proxy_file}: no proxies found")
    if args.tor:
        host, _, port = args.tor.rpartition(":")
        custom.append(Proxy("socks5", host or "127.0.0.1", int(port), source="tor", custom=True, isolate=True, rdns=True))
    if custom and args.direct:
        raise ToolError("--direct cannot be combined with --proxy/--proxy-file/--tor")
    if any(p.scheme != "http" for p in custom) and ProxyConnector is None:
        raise ToolError("SOCKS/Tor needs aiohttp-socks: python -m pip install aiohttp-socks")
    if args.protocols:
        protocols = {normalize_scheme(s.strip())[0] for s in args.protocols.split(",") if s.strip()}
    else:
        protocols = {"http", "socks5"} if ProxyConnector is not None else {"http"}
    if protocols - {"http"} and ProxyConnector is None:
        log.warning("aiohttp-socks not installed; ignoring socks protocols")
        protocols = {"http"}
    extra = []
    for i, src in enumerate(args.proxy_source):
        scheme, sep, url = src.partition("=")
        if not sep or scheme.startswith("http"):
            scheme, url = "http", src
        extra.append((f"custom-{i + 1}", url, normalize_scheme(scheme)[0], "text"))
    mode = "direct" if args.direct else ("custom" if custom else "free")
    return ProxySettings(
        mode=mode, custom=custom, protocols=protocols, pool_size=max(1, args.pool_size),
        test_timeout=args.proxy_timeout, test_concurrency=max(1, args.test_concurrency), max_test=max(1, args.max_test),
        cache_ttl=args.cache_ttl.total_seconds(), use_cache=not args.no_cache, leak_check=not args.no_leak_check,
        allow_direct_fallback=args.allow_direct_fallback, extra_sources=extra,
    )


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose >= 2 else logging.INFO)
    if args.verbose == 0 and not args.quiet and getattr(args, "json", False):
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


async def run(args: argparse.Namespace) -> int:
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "hosts":
        return cmd_hosts(args)
    if args.cmd == "restore":
        return cmd_restore(args)
    if aiohttp is None:
        raise ToolError("aiohttp is required: python -m pip install aiohttp aiohttp-socks Pillow")
    net = Net(timeout=args.timeout, connect_timeout=args.connect_timeout, user_agent=args.user_agent)
    cfg = proxy_settings(args)
    engine = Engine(net, ProxyPool(net, cfg), max(1, args.retries))
    if cfg.mode == "direct":
        log.info("mode: direct connection (no proxy)")
    elif cfg.mode == "custom":
        log.info("mode: custom proxies (%s)", ", ".join(p.label for p in cfg.custom))
    else:
        log.info("mode: free proxy pool (%s)", ",".join(sorted(cfg.protocols)))
    if args.cmd == "upload":
        return await run_upload(args, engine, "image")
    if args.cmd == "file":
        return await run_upload(args, engine, "file")
    if args.cmd == "check":
        return await cmd_check(args, engine)
    if args.cmd == "proxies":
        return await cmd_proxies(args, engine)
    raise ToolError(f"unknown command {args.cmd}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args)
    try:
        return asyncio.run(run(args))
    except ToolError as exc:
        log.error("error: %s", exc)
        return 1
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130
