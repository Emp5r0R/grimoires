"""Change a file's hash without breaking it, and undo it again.

Modes
  none    upload the bytes as they are
  auto    like `safe`, but never wraps: formats without an in-format marker
          are uploaded unchanged (default for pictures, so image hosts never
          receive a zip)
  safe    embed a random marker where the format allows it (JPEG comment,
          PNG private chunk, GIF comment, RIFF chunk, PDF comment, ZIP comment,
          empty gzip member, MP4 'free' box, Matroska Void, XML/HTML comment,
          trailing whitespace for text, overlay for unsigned executables...).
          Unknown or fragile formats fall back to `wrap`.
  append  append the marker to the end of any file (most formats ignore it)
  wrap    store the untouched file inside a ZIP with a random comment

Every change is verified before use: the result must still parse (where a
validator exists) and restore() must give back the exact original bytes.
Each strategy is a small class; add a new format by adding a Strategy to
SAFE_STRATEGIES.
"""

from __future__ import annotations

import abc
import dataclasses
import datetime as dt
import gzip
import io
import logging
import re
import secrets
import struct
import zipfile
import zlib
from typing import Optional

try:
    from PIL import Image  # type: ignore
except ImportError:
    Image = None  # type: ignore

log = logging.getLogger("media_drop")

MODES = ("none", "auto", "safe", "append", "wrap")
MARK_PREFIX = b"MDROP1:"
WRAP_PREFIX = b"MDROPW1:"
TOKEN_RE = rb"[0-9a-f]{16}"
MARK_RE = re.compile(MARK_PREFIX + TOKEN_RE)
VALIDATE_LIMIT = 256 * 1024 * 1024  # skip expensive validation above this


@dataclasses.dataclass
class HashChange:
    mode: str
    method: str
    marker: str
    data: bytes
    mime: Optional[str] = None  # new MIME when the container changes (wrap)
    suffix: Optional[str] = None  # new filename extension (wrap)

    def describe(self) -> dict:
        return {"mode": self.mode, "method": self.method, "marker": self.marker}


def new_marker() -> bytes:
    return MARK_PREFIX + secrets.token_hex(8).encode()


def pillow_ok(data: bytes) -> bool:
    if Image is None:
        return True
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.verify()
        with Image.open(io.BytesIO(data)) as im:  # verify() does not decode pixels
            for frame in range(getattr(im, "n_frames", 1)):
                im.seek(frame)
                im.load()
        return True
    except Exception:
        return False


class Strategy(abc.ABC):
    name = ""

    @abc.abstractmethod
    def match(self, data: bytes, mime: str, name: str) -> bool: ...

    @abc.abstractmethod
    def embed(self, data: bytes, marker: bytes) -> bytes: ...

    @abc.abstractmethod
    def extract(self, data: bytes) -> Optional[bytes]:
        """Return the original bytes if this strategy's marker is present."""

    def valid(self, data: bytes) -> bool:
        return True


class SuffixStrategy(Strategy):
    """Strategies whose marker is a fixed-shape suffix."""

    tail_re: re.Pattern

    def extract(self, data: bytes) -> Optional[bytes]:
        m = self.tail_re.search(data[-256:])
        if not m:
            return None
        return data[: len(data) - (len(data[-256:]) - m.start())]


class JpegComment(Strategy):
    name = "jpeg-comment"

    def match(self, data, mime, name):
        return data[:3] == b"\xff\xd8\xff"

    def embed(self, data, marker):
        seg = b"\xff\xfe" + struct.pack(">H", len(marker) + 2) + marker
        return data[:2] + seg + data[2:]

    def extract(self, data):
        if data[:2] != b"\xff\xd8" or data[2:4] != b"\xff\xfe":
            return None
        length = struct.unpack(">H", data[4:6])[0]
        if MARK_RE.fullmatch(data[6 : 4 + length]):
            return data[:2] + data[4 + length :]
        return None

    def valid(self, data):
        return pillow_ok(data)


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_TYPE = b"mdRp"  # ancillary, private, reserved-ok, safe-to-copy


def _png_chunks(data: bytes):
    pos = 8
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        yield pos, length, ctype
        pos += 12 + length
        if ctype == b"IEND":
            return


class PngChunk(Strategy):
    name = "png-chunk"

    def match(self, data, mime, name):
        return data[:8] == PNG_SIG and any(t == b"IEND" for _, _, t in _png_chunks(data))

    def embed(self, data, marker):
        iend = next(p for p, _, t in _png_chunks(data) if t == b"IEND")
        chunk = struct.pack(">I", len(marker)) + PNG_TYPE + marker + struct.pack(">I", zlib.crc32(PNG_TYPE + marker) & 0xFFFFFFFF)
        return data[:iend] + chunk + data[iend:]

    def extract(self, data):
        if data[:8] != PNG_SIG:
            return None
        for pos, length, ctype in _png_chunks(data):
            if ctype == PNG_TYPE and MARK_RE.fullmatch(data[pos + 8 : pos + 8 + length]):
                return data[:pos] + data[pos + 12 + length :]
        return None

    def valid(self, data):
        return pillow_ok(data)


class GifComment(SuffixStrategy):
    name = "gif-comment"
    tail_re = re.compile(rb"\x21\xfe\x17" + MARK_PREFIX + TOKEN_RE + rb"\x00;\Z")

    def match(self, data, mime, name):
        # Decoders accept extension blocks in GIF87a files too; Pillow validates the result.
        return data[:6] in (b"GIF87a", b"GIF89a") and data[-1:] == b";"

    def embed(self, data, marker):
        return data[:-1] + b"\x21\xfe" + bytes([len(marker)]) + marker + b"\x00;"

    def extract(self, data):
        original = super().extract(data)
        return original + b";" if original is not None else None

    def valid(self, data):
        return pillow_ok(data)


class RiffChunk(Strategy):
    """WAV / AVI get a JUNK chunk; extended WebP gets an unknown chunk."""

    name = "riff-chunk"
    tail_re = re.compile(rb"(JUNK|mdrp)\x17\x00\x00\x00" + MARK_PREFIX + TOKEN_RE + rb"\x00\Z")

    def match(self, data, mime, name):
        if data[:4] != b"RIFF" or len(data) < 16:
            return False
        if struct.unpack("<I", data[4:8])[0] + 8 != len(data):
            return False
        form = data[8:12]
        return form in (b"WAVE", b"AVI ") or (form == b"WEBP" and data[12:16] == b"VP8X")

    def embed(self, data, marker):
        cid = b"mdrp" if data[8:12] == b"WEBP" else b"JUNK"
        chunk = cid + struct.pack("<I", len(marker)) + marker + (b"\x00" if len(marker) % 2 else b"")
        out = data + chunk
        return out[:4] + struct.pack("<I", len(out) - 8) + out[8:]

    def extract(self, data):
        if data[:4] != b"RIFF":
            return None
        m = self.tail_re.search(data[-64:])
        if not m:
            return None
        cut = len(data) - (len(data[-64:]) - m.start())
        out = data[:cut]
        return out[:4] + struct.pack("<I", len(out) - 8) + out[8:]

    def valid(self, data):
        return pillow_ok(data) if data[8:12] == b"WEBP" else True


class PdfComment(SuffixStrategy):
    name = "pdf-comment"
    tail_re = re.compile(rb"\n%" + MARK_PREFIX + TOKEN_RE + rb"\n\Z")

    def match(self, data, mime, name):
        return data[:5] == b"%PDF-"

    def embed(self, data, marker):
        return data + b"\n%" + marker + b"\n"


def find_eocd(data: bytes) -> Optional[int]:
    """Offset of the ZIP end-of-central-directory record whose comment ends at EOF."""
    start = max(0, len(data) - 65557)
    i = data.rfind(b"PK\x05\x06", start)
    while i >= start:
        if i + 22 <= len(data):
            clen = struct.unpack("<H", data[i + 20 : i + 22])[0]
            if i + 22 + clen == len(data):
                return i
        i = data.rfind(b"PK\x05\x06", start, i)
    return None


def zip_ok(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.infolist()
        return True
    except Exception:
        return False


class ZipComment(Strategy):
    """ZIP and ZIP-based formats (docx, xlsx, pptx, odt, epub, jar)."""

    name = "zip-comment"
    tail_re = re.compile(rb"\n?" + MARK_PREFIX + TOKEN_RE + rb"\Z")

    def match(self, data, mime, name):
        if data[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
            return False
        if b"APK Sig Block 42" in data[-4 * 1024 * 1024 :]:
            return False  # APK v2+ signatures cover the EOCD record
        eocd = find_eocd(data)
        return eocd is not None and len(data) - eocd - 22 + 24 <= 65535

    def embed(self, data, marker):
        eocd = find_eocd(data)
        comment = data[eocd + 22 :]
        comment = comment + (b"\n" if comment else b"") + marker
        return data[: eocd + 20] + struct.pack("<H", len(comment)) + comment

    def extract(self, data):
        eocd = find_eocd(data)
        if eocd is None:
            return None
        comment = data[eocd + 22 :]
        m = self.tail_re.search(comment)
        if not m or comment.startswith(WRAP_PREFIX):
            return None
        comment = comment[: m.start()]
        return data[: eocd + 20] + struct.pack("<H", len(comment)) + comment

    def valid(self, data):
        return zip_ok(data)


class GzipMember(SuffixStrategy):
    """Append an empty gzip member carrying the marker as its FCOMMENT."""

    name = "gzip-member"
    tail_re = re.compile(rb"\x1f\x8b\x08\x10\x00{4}\x00\xff" + MARK_PREFIX + TOKEN_RE + rb"\x00\x03\x00\x00{8}\Z")

    def match(self, data, mime, name):
        return data[:3] == b"\x1f\x8b\x08"

    @staticmethod
    def member(marker: bytes) -> bytes:
        return b"\x1f\x8b\x08\x10" + b"\x00" * 4 + b"\x00\xff" + marker + b"\x00" + b"\x03\x00" + b"\x00" * 8

    def embed(self, data, marker):
        return data + self.member(marker)

    def valid(self, data):
        try:
            return gzip.decompress(self.member(new_marker())) == b""
        except Exception:
            return False


def _bmff_boxes_ok(data: bytes) -> bool:
    pos = 0
    while pos < len(data):
        if pos + 8 > len(data):
            return False
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        if size == 1:
            if pos + 16 > len(data):
                return False
            size = struct.unpack(">Q", data[pos + 8 : pos + 16])[0]
        if size < 8:
            return False  # size 0 ("to end of file") cannot be appended to
        pos += size
    return pos == len(data)


class IsoBmffFree(SuffixStrategy):
    """MP4 / MOV / M4A / 3GP / HEIC / AVIF: append a top-level 'free' box."""

    name = "mp4-free-box"
    tail_re = re.compile(rb"\x00\x00\x00\x1ffree" + MARK_PREFIX + TOKEN_RE + rb"\Z")

    def match(self, data, mime, name):
        return data[4:8] == b"ftyp" and _bmff_boxes_ok(data)

    def embed(self, data, marker):
        return data + struct.pack(">I", 8 + len(marker)) + b"free" + marker

    def valid(self, data):
        return _bmff_boxes_ok(data)


class EbmlVoid(SuffixStrategy):
    """Matroska / WebM: append an EBML Void element (allowed at any level)."""

    name = "mkv-void"
    tail_re = re.compile(rb"\xec\x97" + MARK_PREFIX + TOKEN_RE + rb"\Z")

    def match(self, data, mime, name):
        return data[:4] == b"\x1a\x45\xdf\xa3"

    def embed(self, data, marker):
        return data + b"\xec" + bytes([0x80 | len(marker)]) + marker


MARKUP_EXT = (".html", ".htm", ".xhtml", ".xml", ".svg", ".plist", ".rss", ".atom", ".kml", ".gpx")


class MarkupComment(SuffixStrategy):
    name = "xml-comment"
    tail_re = re.compile(rb"\n<!-- " + MARK_PREFIX + TOKEN_RE + rb" -->\n\Z")

    def match(self, data, mime, name):
        return (mime in ("image/svg+xml", "text/html", "application/xml", "text/xml") or name.lower().endswith(MARKUP_EXT)) and _is_text(data)

    def embed(self, data, marker):
        return data + b"\n<!-- " + marker + b" -->\n"


TEXT_EXT = (
    ".txt", ".md", ".rst", ".log", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".py", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".c", ".h",
    ".cpp", ".hpp", ".cs", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".pl", ".lua", ".r", ".swift",
    ".css", ".scss", ".sql", ".tex", ".srt", ".vtt", ".nfo", ".asc", ".pem",
)


def _is_text(data: bytes) -> bool:
    head = data[:65536]
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc.start >= len(head) - 4  # a multi-byte char cut at the boundary
    return True


class TextWhitespace(Strategy):
    """Plain text/code: a trailing line of 64 spaces/tabs encodes the marker.

    CSV/TSV are not matched (a blank row could be read as data); they wrap.
    """

    name = "text-whitespace"
    tail_re = re.compile(rb"\n[ \t]{64}\n\Z")

    def match(self, data, mime, name):
        lower = name.lower()
        if lower.endswith((".csv", ".tsv")):
            return False
        return (mime == "text/plain" or lower.endswith(TEXT_EXT)) and _is_text(data)

    def embed(self, data, marker):
        bits = int(marker[len(MARK_PREFIX) :], 16)
        ws = bytes(0x09 if bits >> (63 - i) & 1 else 0x20 for i in range(64))
        return data + b"\n" + ws + b"\n"

    def extract(self, data):
        m = self.tail_re.search(data[-80:])
        if not m:
            return None
        return data[: len(data) - 66]


def _pe_signed(data: bytes) -> Optional[bool]:
    """True/False for a PE file's Authenticode signature, None if not a PE."""
    try:
        off = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[off : off + 4] != b"PE\x00\x00":
            return None
        opt = off + 24
        magic = struct.unpack("<H", data[opt : opt + 2])[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        _, size = struct.unpack("<II", data[dirs + 32 : dirs + 40])  # entry 4 = security
        return size > 0
    except (struct.error, IndexError):
        return None


class TrailingData(SuffixStrategy):
    """Formats whose readers ignore trailing bytes: ELF, unsigned PE, tar, ISO, MP3."""

    name = "trailing-data"
    tail_re = re.compile(rb"\x00" + MARK_PREFIX + TOKEN_RE + rb"\Z")

    def match(self, data, mime, name):
        if data[:4] == b"\x7fELF":
            return True
        if data[:2] == b"MZ":
            return _pe_signed(data) is False
        if data[257:262] == b"ustar":
            return True
        if any(data[o : o + 5] == b"CD001" for o in (0x8001, 0x8801, 0x9001)):
            return True
        return data[:3] == b"ID3" or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")

    def embed(self, data, marker):
        return data + b"\x00" + marker


class ImageTrailing(TrailingData):
    """BMP, TIFF, ICO, simple WebP: decoders stop at their own structures; Pillow validates."""

    name = "image-trailing"

    def match(self, data, mime, name):
        return mime in ("image/bmp", "image/tiff", "image/x-icon", "image/webp") and Image is not None

    def valid(self, data):
        return pillow_ok(data)


class AppendAny(TrailingData):
    name = "append"

    def match(self, data, mime, name):
        return True


class ZipWrap(Strategy):
    name = "zip-wrap"
    comment_re = re.compile(WRAP_PREFIX + TOKEN_RE + rb"\Z")

    def match(self, data, mime, name):
        return True

    def wrap(self, data: bytes, marker: bytes, inner_name: str) -> bytes:
        buf = io.BytesIO()
        info = zipfile.ZipInfo(inner_name or "file", date_time=dt.datetime.now().timetuple()[:6])
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = 0o644 << 16
        with zipfile.ZipFile(buf, "w") as zf:
            zf.comment = WRAP_PREFIX + marker[len(MARK_PREFIX) :]
            zf.writestr(info, data)
        return buf.getvalue()

    def embed(self, data, marker):
        return self.wrap(data, marker, "file")

    def unwrap(self, data: bytes) -> Optional[tuple[bytes, str]]:
        eocd = find_eocd(data)
        if eocd is None or not self.comment_re.fullmatch(data[eocd + 22 :]):
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = zf.infolist()
                if len(members) != 1:
                    return None
                return zf.read(members[0]), members[0].filename
        except Exception:
            return None

    def extract(self, data):
        res = self.unwrap(data)
        return res[0] if res else None

    def valid(self, data):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return zf.testzip() is None
        except Exception:
            return False


SAFE_STRATEGIES: list[Strategy] = [
    JpegComment(), PngChunk(), GifComment(), RiffChunk(), PdfComment(), ZipComment(), GzipMember(),
    IsoBmffFree(), EbmlVoid(), MarkupComment(), TextWhitespace(), TrailingData(), ImageTrailing(),
]
APPEND = AppendAny()
WRAP = ZipWrap()


def _verified(strategy: Strategy, original: bytes, out: bytes) -> bool:
    if len(out) <= VALIDATE_LIMIT and not strategy.valid(out):
        return False
    restored = WRAP.extract(out) if strategy is WRAP else strategy.extract(out)
    return restored == original


def change_hash(data: bytes, mime: str, name: str, mode: str) -> Optional[HashChange]:
    """Return a verified HashChange for `mode`, or None for mode 'none'."""
    if mode == "none":
        return None
    marker = new_marker()
    token = marker.decode()
    if mode in ("safe", "auto"):
        for s in SAFE_STRATEGIES:
            if not s.match(data, mime, name):
                continue
            out = s.embed(data, marker)
            if _verified(s, data, out):
                return HashChange(mode, s.name, token, out)
            log.debug("%s: %s produced an invalid result, trying next", name, s.name)
        if mode == "auto":
            log.warning("%s: no safe in-format marker for %s, uploading with its original hash", name, mime)
            return None
        log.info("%s: no safe in-format marker for %s, wrapping in a zip instead", name, mime)
        mode = "wrap"
    if mode == "append":
        out = APPEND.embed(data, marker)
        if _verified(APPEND, data, out):
            return HashChange("append", APPEND.name, token, out)
        raise ValueError("append verification failed")
    if mode == "wrap":
        out = WRAP.wrap(data, marker, name)
        if _verified(WRAP, data, out):
            return HashChange("wrap", WRAP.name, token, out, mime="application/zip", suffix="zip")
        raise ValueError("zip wrap verification failed")
    raise ValueError(f"unknown hash mode {mode!r}")


def restore(data: bytes) -> Optional[tuple[bytes, str, Optional[str]]]:
    """Undo a hash change: (original bytes, method, inner filename or None)."""
    unwrapped = WRAP.unwrap(data)
    if unwrapped:
        return unwrapped[0], WRAP.name, unwrapped[1]
    for s in SAFE_STRATEGIES + [APPEND]:
        original = s.extract(data)
        if original is not None:
            return original, s.name, None
    return None
