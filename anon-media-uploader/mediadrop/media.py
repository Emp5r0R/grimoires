"""File inspection: type sniffing, hashing, perceptual hash, metadata strip, payloads."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import logging
import mimetypes
from pathlib import Path
from typing import Any, Optional, Sequence

from . import rehash
from .util import ToolError, random_token

try:
    from PIL import Image, ImageOps  # type: ignore
except ImportError:
    Image = None  # type: ignore
    ImageOps = None  # type: ignore

log = logging.getLogger("media_drop")

MIME_EXT = {
    "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp",
    "image/bmp": "bmp", "image/tiff": "tiff", "image/x-icon": "ico", "image/heic": "heic",
    "image/avif": "avif", "image/svg+xml": "svg", "video/mp4": "mp4", "video/quicktime": "mov",
    "video/webm": "webm", "video/x-matroska": "mkv", "video/x-msvideo": "avi", "video/3gpp": "3gp",
    "audio/mpeg": "mp3", "audio/flac": "flac", "audio/wav": "wav", "application/ogg": "ogg",
    "application/pdf": "pdf", "application/zip": "zip", "application/gzip": "gz",
    "application/x-7z-compressed": "7z", "application/vnd.rar": "rar", "application/x-bzip2": "bz2",
    "application/x-xz": "xz", "application/x-tar": "tar", "application/x-iso9660-image": "iso",
    "application/vnd.sqlite3": "sqlite",
}
MEDIA_SUFFIXES = {
    "." + ext for mime, ext in MIME_EXT.items() if mime.split("/")[0] in ("image", "video", "audio") or mime == "application/ogg"
} | {".jpeg", ".tif", ".m4v", ".m4a", ".heif", ".jfif"}


def sniff_mime(data: bytes, name: str = "") -> str:
    """Identify a file by magic bytes; fall back to the file extension."""
    h = data[:64]
    guess, _ = mimetypes.guess_type(name)
    if h[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if h[:4] == b"RIFF":
        form = h[8:12]
        return {b"WEBP": "image/webp", b"AVI ": "video/x-msvideo", b"WAVE": "audio/wav"}.get(form, "application/octet-stream")
    if h[:2] == b"BM" and len(data) > 26:
        return "image/bmp"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if h[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"avif", b"avis"):
            return "image/avif"
        if brand in (b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"hevc"):
            return "image/heic"
        if brand == b"qt  ":
            return "video/quicktime"
        if brand.startswith(b"3g"):
            return "video/3gpp"
        if brand.startswith(b"M4A"):
            return "audio/mp4"
        return "video/mp4"
    if h[:4] == b"\x1aE\xdf\xa3":
        return "video/webm" if b"webm" in data[:256] else "video/x-matroska"
    if h[:4] == b"OggS":
        return "application/ogg"
    if h[:4] == b"fLaC":
        return "audio/flac"
    if h[:3] == b"ID3" or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mpeg"
    if h[:5] == b"%PDF-":
        return "application/pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return guess if guess and guess != "application/octet-stream" else "application/zip"
    if h[:3] == b"\x1f\x8b\x08":
        return "application/gzip"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "application/x-7z-compressed"
    if h[:6] == b"Rar!\x1a\x07":
        return "application/vnd.rar"
    if h[:3] == b"BZh":
        return "application/x-bzip2"
    if h[:6] == b"\xfd7zXZ\x00":
        return "application/x-xz"
    if h[:16] == b"SQLite format 3\x00":
        return "application/vnd.sqlite3"
    if h[:4] == b"\x7fELF":
        return "application/x-executable"
    if h[:2] == b"MZ":
        return "application/vnd.microsoft.portable-executable"
    if data[257:262] == b"ustar":
        return "application/x-tar"
    if any(data[o : o + 5] == b"CD001" for o in (0x8001, 0x8801, 0x9001)):
        return "application/x-iso9660-image"
    text_head = data[:512].lstrip().lower()
    if text_head.startswith(b"<svg") or (text_head.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return "image/svg+xml"
    if guess:
        return guess
    try:
        data[:4096].decode("utf-8")
        if b"\x00" not in data[:4096]:
            return "text/plain"
    except UnicodeDecodeError:
        pass
    return "application/octet-stream"


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def dhash(data: bytes, size: int = 8) -> Optional[str]:
    """64-bit difference hash; survives re-encoding/resizing. Needs Pillow."""
    if Image is None:
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.seek(0)
            resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
            px = im.convert("L").resize((size + 1, size), resample).tobytes()
    except Exception:
        return None
    bits = 0
    for row in range(size):
        for col in range(size):
            left = px[row * (size + 1) + col]
            right = px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{size * size // 4}x}"


def hamming_hex(a: Optional[str], b: Optional[str]) -> Optional[int]:
    if not a or not b or len(a) != len(b):
        return None
    return bin(int(a, 16) ^ int(b, 16)).count("1")


STRIPPABLE = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP", "image/tiff": "TIFF", "image/bmp": "BMP"}


def strip_metadata(data: bytes, mime: str) -> Optional[bytes]:
    """Re-save a still image without EXIF/XMP/text chunks (GPS, camera, etc).

    Orientation is baked into the pixels so the image still displays upright.
    Returns None when the format is not strippable (video, animation, svg...).
    """
    if Image is None:
        raise ToolError("--strip-metadata needs Pillow: python -m pip install Pillow")
    fmt = STRIPPABLE.get(mime)
    if not fmt:
        return None
    with Image.open(io.BytesIO(data)) as im:
        if getattr(im, "is_animated", False) and getattr(im, "n_frames", 1) > 1:
            return None
        icc = im.info.get("icc_profile")
        orientation = im.getexif().get(0x0112, 1)
        out = io.BytesIO()
        kwargs: dict[str, Any] = {}
        if icc:
            kwargs["icc_profile"] = icc
        if orientation in (None, 1):
            target = im
            if fmt == "JPEG":
                kwargs["quality"] = "keep"
        else:
            target = ImageOps.exif_transpose(im)
            if fmt == "JPEG":
                kwargs["quality"] = 95
        if fmt == "WEBP":
            kwargs["quality"] = 95
        if fmt == "JPEG" and target.mode not in ("RGB", "L", "CMYK"):
            target = target.convert("RGB")
        target.save(out, format=fmt, **kwargs)
        return out.getvalue()


@dataclasses.dataclass
class Payload:
    """The exact bytes that get uploaded, plus where they came from."""

    path: Path
    data: bytes
    mime: str
    upload_name: str
    hashes: dict[str, str]
    dhash: Optional[str]
    prepared: bytes  # bytes after optional strip, before the hash change
    original: Optional[dict[str, Any]] = None  # on-disk file when bytes were changed
    transforms: list[str] = dataclasses.field(default_factory=list)
    hash_change: Optional[dict[str, str]] = None
    base_name: str = ""  # random/kept name without the wrap suffix

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def is_image(self) -> bool:
        return self.mime.startswith("image/")

    def describe(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "path": str(self.path),
            "name": self.path.name,
            "upload_name": self.upload_name,
            "size": self.size,
            "mime": self.mime,
            **self.hashes,
        }
        if self.dhash:
            info["dhash"] = self.dhash
        if self.original:
            info["original"] = self.original
        if self.transforms:
            info["transforms"] = self.transforms
        if self.hash_change:
            info["hash_change"] = self.hash_change
        return info


def _with_hash_change(base: Payload, mode: str) -> Payload:
    """New payload variant: base.prepared + a fresh hash change."""
    change = rehash.change_hash(base.prepared, base.mime, base.path.name, mode)
    if change is None:
        return base
    data = change.data
    mime = change.mime or base.mime
    name = base.base_name + (f".{change.suffix}" if change.suffix else "")
    transforms = [t for t in base.transforms if not t.startswith("hash:")] + [f"hash:{change.method}"]
    original = base.original or {**file_hashes(base.prepared), "size": len(base.prepared), "mime": base.mime}
    return dataclasses.replace(
        base, data=data, mime=mime, upload_name=name, hashes=file_hashes(data),
        dhash=dhash(data) if mime.startswith("image/") else None, original=original,
        transforms=transforms, hash_change={**change.describe(), "restores_to": hashlib.sha256(base.prepared).hexdigest()},
    )


def build_payload(path: Path, *, strip: bool = False, keep_name: bool = False, hash_mode: str = "none") -> Payload:
    raw = path.read_bytes()
    if not raw:
        raise ToolError(f"{path}: file is empty")
    mime = sniff_mime(raw, path.name)
    data = raw
    original = None
    transforms: list[str] = []
    if strip:
        stripped = strip_metadata(raw, mime)
        if stripped is None:
            log.warning("%s: metadata stripping not supported for %s, uploading as-is", path.name, mime)
        else:
            original = {**file_hashes(raw), "size": len(raw), "mime": mime}
            transforms.append("strip-metadata")
            data = stripped
    ext = (MIME_EXT.get(mime) or path.suffix.lstrip(".").lower()
           or (mimetypes.guess_extension(mime) or "").lstrip(".") or ("txt" if mime.startswith("text/") else "bin"))
    if keep_name:
        name = path.name if path.suffix else f"{path.name}.{ext}"
    else:
        name = f"{random_token(12)}.{ext}"
    base = Payload(
        path=path, data=data, mime=mime, upload_name=name, hashes=file_hashes(data),
        dhash=dhash(data) if mime.startswith("image/") else None, prepared=data,
        original=original, transforms=transforms, base_name=name,
    )
    return variant(base, hash_mode)


def variant(base: Payload, hash_mode: str, rename: bool = False) -> Payload:
    """Fresh hash-changed copy of a payload (used for unique hashes per host).

    rename=True also draws a new random filename so copies on different hosts
    cannot be linked by name.
    """
    if rename:
        ext = base.base_name.rsplit(".", 1)[-1] if "." in base.base_name else "bin"
        base = dataclasses.replace(base, base_name=f"{random_token(12)}.{ext}", upload_name=f"{random_token(12)}.{ext}")
    if hash_mode == "none":
        return base
    try:
        return _with_hash_change(base, hash_mode)
    except ValueError as exc:
        raise ToolError(f"{base.path.name}: could not change hash ({exc})")


def expand_inputs(items: Sequence[str], recursive: bool, media_only: bool) -> list[Path]:
    out: list[Path] = []
    for item in items:
        p = Path(item).expanduser()
        if p.is_dir():
            walker = p.rglob("*") if recursive else p.glob("*")
            found = sorted(f for f in walker if f.is_file() and (not media_only or f.suffix.lower() in MEDIA_SUFFIXES))
            if not found:
                log.warning("%s: no %sfiles found%s", p, "media " if media_only else "", "" if recursive else " (try --recursive)")
            out.extend(found)
        elif p.is_file():
            out.append(p)
        else:
            raise ToolError(f"input not found: {item}")
    return out
