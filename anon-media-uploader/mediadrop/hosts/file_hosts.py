"""General file hosts: any file type, permanent or temporary, size-dependent retention."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import urllib.parse

from ..util import MiB, UploadError, random_token, snippet
from .base import Host, UploadResult, check_http, form, nearest_choice, read_body, register, text_upload

GiB = 1024 * MiB
DAY = dt.timedelta(days=1)


@register
class Catbox(Host):
    name, label, site = "catbox", "catbox.moe", "https://catbox.moe"
    max_size = 200 * MiB
    notes = "set CATBOX_USERHASH to own/delete uploads"
    domains = ("catbox.moe",)

    async def upload(self, net, c, payload, opts):
        fields = {"reqtype": "fileupload"}
        if os.environ.get("CATBOX_USERHASH"):
            fields["userhash"] = os.environ["CATBOX_USERHASH"]
        url, _ = await text_upload(c, self.name, "POST", "https://catbox.moe/user/api.php", data=form("fileToUpload", payload, fields))
        return UploadResult(self.name, url)


@register
class Litterbox(Host):
    name, label, site = "litterbox", "litterbox.catbox.moe", "https://litterbox.catbox.moe"
    max_size = 1 * GiB
    temporary = True
    retention = "1h-72h (--expire, default 72h)"
    domains = ("litter.catbox.moe", "litterbox.catbox.moe")
    CHOICES = [(3600, "1h"), (12 * 3600, "12h"), (24 * 3600, "24h"), (72 * 3600, "72h")]

    def lifetime(self, size, opts):
        return dt.timedelta(hours=int(nearest_choice(opts.expire, self.CHOICES, "72h")[:-1]))

    async def upload(self, net, c, payload, opts):
        fields = {"reqtype": "fileupload", "time": nearest_choice(opts.expire, self.CHOICES, "72h")}
        url, _ = await text_upload(c, self.name, "POST", "https://litterbox.catbox.moe/resources/internals/api.php", data=form("fileToUpload", payload, fields))
        return UploadResult(self.name, url, expires_at=self.expiry(payload, opts))


@register
class ZeroX0(Host):
    name, label, site = "0x0", "0x0.st", "https://0x0.st"
    max_size = 512 * MiB
    retention = "30d-1y by size (--expire to shorten)"
    notes = "blocks many VPN/proxy ranges; returns a delete token"
    domains = ("0x0.st",)

    def lifetime(self, size, opts):
        if opts.expire:
            return opts.expire
        min_age, max_age = 30, 365
        return dt.timedelta(days=min_age + (min_age - max_age) * pow(size / self.max_size - 1, 3))

    async def upload(self, net, c, payload, opts):
        fields: dict[str, str] = {}
        if opts.expire:
            fields["expires"] = str(max(1, int(opts.expire.total_seconds() // 3600)))
        if opts.secret_urls:
            fields["secret"] = ""
        url, headers = await text_upload(c, self.name, "POST", "https://0x0.st", data=form("file", payload, fields))
        token = headers.get("X-Token")
        note = f"curl -Ftoken={token} -Fdelete= {url}" if token else None
        return UploadResult(self.name, url, delete_token=token, manage_note=note, expires_at=self.expiry(payload, opts))


@register
class X0At(Host):
    name, label, site = "x0", "x0.at", "https://x0.at"
    max_size = 1 * GiB
    retention = "3d-100d by size"
    domains = ("x0.at",)

    def lifetime(self, size, opts):
        return dt.timedelta(days=3 + (100 - 3) * pow(1 - size / self.max_size, 2))

    async def upload(self, net, c, payload, opts):
        fields = {"id_length": "24"} if opts.secret_urls else {}
        url, _ = await text_upload(c, self.name, "POST", "https://x0.at/", data=form("file", payload, fields))
        return UploadResult(self.name, url, expires_at=self.expiry(payload, opts))


class Pomf(Host):
    """pomf-compatible hosts: POST files[] -> {"success":true,"files":[{"url":..}]}."""

    endpoint = ""

    def fields(self, opts) -> dict[str, str]:
        return {}

    async def upload(self, net, c, payload, opts):
        async with c.post(self.endpoint, data=form("files[]", payload, self.fields(opts)), headers={"Accept": "application/json"}) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        try:
            data = json.loads(text)
        except ValueError:
            if text.strip().startswith("https://"):
                return UploadResult(self.name, text.strip().splitlines()[0], expires_at=self.expiry(payload, opts))
            raise UploadError(f"{self.name}: non-JSON reply {snippet(text)}", proxy_fault=c.proxy is not None)
        if not data.get("success") or not data.get("files"):
            msg = data.get("description") or data.get("error") or snippet(text)
            raise UploadError(f"{self.name}: {msg}", fatal=True)
        f = data["files"][0]
        remote = {"sha1": f["hash"]} if isinstance(f.get("hash"), str) and len(f["hash"]) == 40 else None
        return UploadResult(self.name, f["url"], expires_at=self.expiry(payload, opts), remote_hash=remote)


@register
class LainPomf(Pomf):
    name, label, site = "lain", "pomf.lain.la", "https://pomf.lain.la"
    endpoint = "https://pomf.lain.la/upload.php"
    max_size = 1 * GiB
    domains = ("pomf.lain.la", "pomf2.lain.la")


@register
class QuAx(Pomf):
    name, label, site = "quax", "qu.ax", "https://qu.ax"
    endpoint = "https://qu.ax/upload"
    max_size = 256 * 1000 * 1000
    retention = "permanent, or 1d/7d/30d/365d with --expire"
    domains = ("qu.ax",)
    CHOICES = [(86400, "1"), (7 * 86400, "7"), (30 * 86400, "30"), (365 * 86400, "365")]

    def _days(self, opts) -> str:
        return nearest_choice(opts.expire, self.CHOICES, "-1")

    def fields(self, opts):
        return {"expiry": self._days(opts)}

    def lifetime(self, size, opts):
        days = int(self._days(opts))
        return dt.timedelta(days=days) if days > 0 else None


@register
class Gofile(Host):
    name, label, site = "gofile", "gofile.io", "https://gofile.io"
    retention = "kept while downloaded (guest)"
    notes = "no size limit; check confirms the file exists (downloads need its web app)"
    domains = ("gofile.io",)

    async def upload(self, net, c, payload, opts):
        async with c.post("https://upload.gofile.io/uploadfile", data=form("file", payload)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        reply = json.loads(text)
        d = reply.get("data") or {}
        if reply.get("status") != "ok" or not d.get("downloadPage"):
            raise UploadError(f"gofile: {snippet(text)}", fatal=True)
        server = (d.get("servers") or ["store1"])[0]
        probe = f"https://{server}.gofile.io/download/web/{d['id']}/{urllib.parse.quote(d.get('name') or payload.upload_name)}"
        token = d.get("guestToken")
        note = None
        if token:
            note = (f"curl -X DELETE https://api.gofile.io/contents -H 'Authorization: Bearer {token}' "
                    f"-H 'Content-Type: application/json' -d '{{\"contentsId\":\"{d['id']}\"}}'")
        remote = {"md5": d["md5"]} if isinstance(d.get("md5"), str) and len(d["md5"]) == 32 else None
        return UploadResult(self.name, d["downloadPage"], delete_token=token, manage_note=note, remote_hash=remote,
                            extra={"probe_url": probe, "file_id": d["id"]})

    def probe_target(self, rec):
        return (rec.get("extra") or {}).get("probe_url") or rec["url"], "GET", False

    def interpret(self, rec, out):
        if out.http_status in (301, 302, 303, 307, 308) and "/d/" in (out.location or ""):
            return "alive", "file exists (gofile serves downloads only through its web app)"
        if out.http_status == 404:
            return "removed", "HTTP 404"
        return None


@register
class CNetPaste(Host):
    name, label, site = "cnet", "paste.c-net.org", "https://paste.c-net.org"
    max_size = 50 * 1000 * 1000
    retention = "180d, renewed on every access"
    domains = ("paste.c-net.org",)

    def lifetime(self, size, opts):
        return 180 * DAY

    async def upload(self, net, c, payload, opts):
        target = "https://paste.c-net.org/" + urllib.parse.quote(payload.upload_name)
        url, _ = await text_upload(c, self.name, "PUT", target, data=payload.data, headers={"Content-Type": payload.mime})
        return UploadResult(self.name, url, expires_at=self.expiry(payload, opts))


@register
class Pixeldrain(Host):
    name, label, site = "pixeldrain", "pixeldrain.com", "https://pixeldrain.com"
    env_key = "PIXELDRAIN_API_KEY"
    retention = "kept while viewed"
    notes = "needs PIXELDRAIN_API_KEY (free account)"
    domains = ("pixeldrain.com",)

    async def upload(self, net, c, payload, opts):
        auth = base64.b64encode(f":{os.environ[self.env_key]}".encode()).decode()
        url = "https://pixeldrain.com/api/file/" + urllib.parse.quote(payload.upload_name)
        async with c.request("PUT", url, data=payload.data, headers={"Authorization": f"Basic {auth}"}) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        fid = json.loads(text).get("id")
        if not fid:
            raise UploadError(f"pixeldrain: {snippet(text)}", fatal=True)
        return UploadResult(self.name, f"https://pixeldrain.com/api/file/{fid}", page_url=f"https://pixeldrain.com/u/{fid}")


# -- temporary -------------------------------------------------------------------


@register
class TempSh(Host):
    name, label, site = "tempsh", "temp.sh", "https://temp.sh"
    max_size = 4 * GiB
    temporary = True
    retention = "3 days"
    download_method = "POST"  # GET shows a download page, POST returns the file
    domains = ("temp.sh",)

    def lifetime(self, size, opts):
        return 3 * DAY

    async def upload(self, net, c, payload, opts):
        url, _ = await text_upload(c, self.name, "POST", "https://temp.sh/upload", data=form("file", payload))
        return UploadResult(self.name, url, expires_at=self.expiry(payload, opts))


@register
class TmpfileLink(Host):
    name, label, site = "tmpfilelink", "tmpfile.link", "https://tmpfile.link"
    max_size = 100 * 1000 * 1000
    temporary = True
    retention = "7 days"
    domains = ("tmpfile.link", "tempfilestorage.link")

    def lifetime(self, size, opts):
        return 7 * DAY

    async def upload(self, net, c, payload, opts):
        async with c.post("https://tmpfile.link/api/upload", data=form("file", payload)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        d = json.loads(text)
        url = d.get("downloadLinkEncoded") or d.get("downloadLink")
        if not url:
            raise UploadError(f"tmpfile.link: {snippet(text)}", fatal=True)
        return UploadResult(self.name, url, expires_at=self.expiry(payload, opts))


@register
class Filebin(Host):
    name, label, site = "filebin", "filebin.net", "https://filebin.net"
    temporary = True
    retention = "6 days"
    notes = "anyone with the bin URL can delete it"
    check_ua = "curl/8.10.1"
    domains = ("filebin.net",)

    def lifetime(self, size, opts):
        return 6 * DAY

    async def upload(self, net, c, payload, opts):
        bin_id = random_token(16)
        url = f"https://filebin.net/{bin_id}/{urllib.parse.quote(payload.upload_name)}"
        headers = {"Content-Type": payload.mime, "Accept": "application/json", "User-Agent": self.check_ua}
        async with c.post(url, data=payload.data, headers=headers) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        return UploadResult(self.name, url, page_url=f"https://filebin.net/{bin_id}",
                            manage_note=f"curl -X DELETE {url}", expires_at=self.expiry(payload, opts))


@register
class Uguu(Pomf):
    name, label, site = "uguu", "uguu.se", "https://uguu.se"
    endpoint = "https://uguu.se/upload?output=json"
    max_size = 128 * MiB
    temporary = True
    retention = "3 hours"
    domains = ("uguu.se",)

    def lifetime(self, size, opts):
        return dt.timedelta(hours=3)


@register
class Tmpfiles(Host):
    name, label, site = "tmpfiles", "tmpfiles.org", "https://tmpfiles.org"
    max_size = 100 * MiB
    temporary = True
    retention = "60 minutes"
    domains = ("tmpfiles.org",)

    def lifetime(self, size, opts):
        return dt.timedelta(minutes=60)

    async def upload(self, net, c, payload, opts):
        async with c.post("https://tmpfiles.org/api/v1/upload", data=form("file", payload)) as r:
            text = await read_body(r)
            check_http(r.status, text, c.proxy is not None, self.name)
        data = json.loads(text)
        page = data.get("data", {}).get("url")
        if data.get("status") != "success" or not page:
            raise UploadError(f"tmpfiles: {snippet(text)}", fatal=True)
        page = re.sub(r"^http://", "https://", page)
        direct = re.sub(r"^(https://tmpfiles\.org)/(?!dl/)", r"\1/dl/", page)
        return UploadResult(self.name, direct, page_url=page, expires_at=self.expiry(payload, opts))
