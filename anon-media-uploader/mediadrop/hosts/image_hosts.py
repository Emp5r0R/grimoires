"""Image hosts (images only, except imgur which also takes short videos)."""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time

from ..util import MiB, UploadError, parse_iso, snippet
from .base import Host, UploadResult, check_http, form, nearest_choice, read_body, register

log = logging.getLogger("media_drop")

CHEVERETO_TOKEN_RE = re.compile(r"auth_token\s*=\s*[\"']([0-9a-f]{16,})[\"']", re.I)
CHEVERETO_EXPIRY = [
    (300, "PT5M"), (900, "PT15M"), (1800, "PT30M"), (3600, "PT1H"), (3 * 3600, "PT3H"),
    (6 * 3600, "PT6H"), (12 * 3600, "PT12H"), (86400, "P1D"), (2 * 86400, "P2D"), (3 * 86400, "P3D"),
    (7 * 86400, "P1W"), (14 * 86400, "P2W"), (30 * 86400, "P1M"), (60 * 86400, "P2M"),
    (90 * 86400, "P3M"), (180 * 86400, "P6M"),
]


def chevereto_result(host: str, text: str, via_proxy: bool) -> UploadResult:
    try:
        data = json.loads(text)
    except ValueError:
        raise UploadError(f"{host}: non-JSON reply {snippet(text)}", proxy_fault=via_proxy)
    if int(data.get("status_code", 0)) != 200 or "image" not in data:
        err = data.get("error") or {}
        msg = err.get("message") if isinstance(err, dict) else err
        raise UploadError(f"{host}: {msg or snippet(text)}", fatal=True)
    img = data["image"]
    url = img.get("url") or (img.get("image") or {}).get("url")
    if not url:
        raise UploadError(f"{host}: no URL in reply", fatal=True)
    remote = {"md5": img["md5"]} if isinstance(img.get("md5"), str) and len(img["md5"]) == 32 else None
    return UploadResult(
        host, url, page_url=img.get("url_viewer"), delete_url=img.get("delete_url"),
        expires_at=parse_iso(img.get("expiration_date_gmt")), remote_hash=remote,
    )


class CheveretoWeb(Host):
    """Chevereto-powered sites: fetch homepage for PHPSESSID + auth_token, POST /json."""

    images_only = True

    def lifetime(self, size, opts):
        return opts.expire

    async def upload(self, net, c, payload, opts):
        via = c.proxy is not None
        async with c.get(self.site + "/", headers={"Accept": "text/html"}) as r:
            html = await read_body(r)
            check_http(r.status, html, via, self.name)
        m = CHEVERETO_TOKEN_RE.search(html)
        if not m:
            raise UploadError(f"{self.name}: auth_token not found on page", proxy_fault=via)
        fields = {
            "type": "file", "action": "upload", "timestamp": str(int(time.time() * 1000)),
            "auth_token": m.group(1), "nsfw": "1" if opts.nsfw else "0",
        }
        if opts.expire:
            fields["expiration"] = nearest_choice(opts.expire, CHEVERETO_EXPIRY, "P6M")
        headers = {
            "Accept": "application/json", "Origin": self.site, "Referer": self.site + "/",
            "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        }
        async with c.post(self.site + "/json", data=form("source", payload, fields), headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, via, self.name)
        res = chevereto_result(self.name, text, via)
        res.expires_at = res.expires_at or self.expiry(payload, opts)
        return res


@register
class ImgBB(CheveretoWeb):
    name, label, site = "imgbb", "imgbb.com", "https://imgbb.com"
    max_size = 32 * 1000 * 1000
    notes = "web flow (no key); set IMGBB_API_KEY to use the official API"
    domains = ("ibb.co", "imgbb.com", "i.ibb.co")

    async def upload(self, net, c, payload, opts):
        key = os.environ.get("IMGBB_API_KEY")
        if not key:
            return await super().upload(net, c, payload, opts)
        params = {"key": key}
        if opts.expire:
            params["expiration"] = str(int(min(max(opts.expire.total_seconds(), 60), 15552000)))
        async with c.post("https://api.imgbb.com/1/upload", params=params, data=form("image", payload)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        d = json.loads(text).get("data") or {}
        if not d.get("url"):
            raise UploadError(f"imgbb api: {snippet(text)}", fatal=True)
        exp = None
        if d.get("expiration") and str(d.get("expiration")) != "0" and d.get("time"):
            exp = dt.datetime.fromtimestamp(int(d["time"]) + int(d["expiration"]), dt.timezone.utc)
        return UploadResult(self.name, d["url"], page_url=d.get("url_viewer"), delete_url=d.get("delete_url"), expires_at=exp)


@register
class Freeimage(Host):
    name, label, site = "freeimage", "freeimage.host", "https://freeimage.host"
    max_size = 64 * MiB
    images_only = True
    notes = "public guest API key (override with FREEIMAGE_API_KEY)"
    domains = ("freeimage.host", "iili.io")
    PUBLIC_KEY = "6d207e02198a847aa98d0a2a901485a5"  # published on freeimage.host/page/api

    async def upload(self, net, c, payload, opts):
        fields = {"key": os.environ.get("FREEIMAGE_API_KEY", self.PUBLIC_KEY), "action": "upload", "format": "json"}
        async with c.post("https://freeimage.host/api/1/upload", data=form("source", payload, fields)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        return chevereto_result(self.name, text, c.proxy is not None)


@register
class Pixhost(Host):
    name, label, site = "pixhost", "pixhost.cc", "https://pixhost.cc"
    max_size = 10 * MiB
    images_only = True
    notes = "official API v2; supports batch status checks"
    domains = ("pixhost.to", "pixhost.cc", "pixho.st")

    async def upload(self, net, c, payload, opts):
        fields = {"content_type": "1" if opts.nsfw else "0", "max_th_size": "420", "include_manage_url": "1"}
        async with c.post("https://api.pixhost.cc/images", data=form("img", payload, fields), headers={"Accept": "application/json"}) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        data = json.loads(text)
        show, thumb = data.get("show_url"), data.get("th_url")
        if not show:
            raise UploadError(f"pixhost: {snippet(text)}", fatal=True)
        direct = show
        if thumb:
            direct = re.sub(r"//t(\d+)\.", r"//img\1.", thumb).replace("/thumbs/", "/images/")
        return UploadResult(self.name, direct, page_url=show, delete_url=data.get("manage_url"), extra={"thumb_url": thumb})

    async def batch_status(self, engine, recs):
        pages = [r["page_url"] for r in recs if r.get("page_url")]
        by_page = {r.get("page_url"): r.get("id") for r in recs}
        verdicts: dict[str, tuple[str, str]] = {}
        for i in range(0, len(pages), 100):
            chunk = pages[i : i + 100]

            async def call(c, chunk=chunk):
                async with c.post("https://api.pixhost.cc/images/status", json={"urls": chunk}, headers={"Accept": "application/json"}) as r:
                    text = await read_body(r)
                    check_http(r.status, text, c.proxy is not None, self.name)
                    return json.loads(text)

            try:
                data, _ = await engine.attempts("[pixhost] status api", call)
            except UploadError as exc:
                log.warning("pixhost status API failed: %s", exc)
                continue
            for item in data.get("results", []):
                state = item.get("status")
                rid = by_page.get(item.get("url"))
                if rid and state in ("deleted", "not_found"):
                    verdicts[rid] = ("removed", f"pixhost API: {state}")
        return verdicts


@register
class ImgInTh(CheveretoWeb):
    name, label, site = "imgin", "img.in.th", "https://img.in.th"
    max_size = 50 * MiB
    domains = ("img.in.th",)


@register
class Lensdump(CheveretoWeb):
    name, label, site = "lensdump", "lensdump.com", "https://lensdump.com"
    max_size = 50 * MiB
    notes = "Cloudflare-fronted; many free proxies get challenged"
    domains = ("lensdump.com", "i.lensdump.com")


@register
class Imgur(Host):
    name, label, site = "imgur", "imgur.com", "https://imgur.com"
    max_size = 200 * MiB
    env_key = "IMGUR_CLIENT_ID"
    accepts_label = "images/videos"
    notes = "official API, needs IMGUR_CLIENT_ID; blocks many proxies"
    domains = ("imgur.com", "i.imgur.com")

    def accepts(self, payload):
        if not (payload.is_image or payload.mime in ("video/mp4", "video/quicktime", "video/webm")):
            return False, "images and mp4/mov/webm only"
        if payload.is_image and payload.size > 20 * MiB:
            return False, "images larger than 20 MiB"
        return super().accepts(payload)

    async def upload(self, net, c, payload, opts):
        field = "image" if payload.is_image else "video"
        headers = {"Authorization": f"Client-ID {os.environ[self.env_key]}"}
        async with c.post("https://api.imgur.com/3/image", data=form(field, payload, {"type": "file"}), headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        d = json.loads(text).get("data") or {}
        if not d.get("link"):
            raise UploadError(f"imgur: {snippet(text)}", fatal=True)
        token = d.get("deletehash")
        note = f"curl -X DELETE -H 'Authorization: Client-ID ...' https://api.imgur.com/3/image/{token}" if token else None
        return UploadResult(self.name, d["link"], page_url=f"https://imgur.com/{d.get('id')}", delete_token=token, manage_note=note)

    def soft_removed(self, final_url, content_type):
        return final_url.rstrip("/").endswith("removed.png")
