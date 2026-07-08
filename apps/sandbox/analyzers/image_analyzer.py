"""
Analizador de imágenes — detecta amenazas en formatos gráficos.

Cobertura: JPEG, PNG, GIF, BMP, WebP, TIFF, ICO, SVG.

Detecciones:
  • SVG: <script>, event handlers, <foreignObject>, data:text/javascript, referencias externas
  • Estructural: dimensiones inválidas (0, negativo, extremo), archivo corrupto/truncado
  • Datos extra: bytes después del marcador de fin de imagen (posible stego)
  • Metadatos: EXIF con campos sospechosos (muy largos, software raro)
  • Tamaño anómalo: archivo demasiado grande para sus dimensiones
"""
import os
import struct
import re
from typing import Optional

from .base import empty_result, evidence


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("image")
    ext = os.path.splitext(filepath)[1].lower()
    raw = _safe_read(filepath)
    if raw is None:
        return result

    # ── 1. Validación estructural básica ──────────────────────────────
    _check_magic_bytes(raw, ext, result)
    dims = _parse_dimensions(raw, ext)
    if dims:
        _check_dimensions(dims, result)
        _check_size_vs_dimensions(filepath, dims, result)
    else:
        if ext != ".svg":
            result["evidence"].append(evidence(
                "image_unreadable", f"No se pudieron leer dimensiones ({ext})", 20,
            ))
            result["score"] = max(result["score"], 20)

    # ── 2. SVG-specific checks ────────────────────────────────────────
    if ext == ".svg":
        _analyze_svg(raw, result)

    # ── 3. Metadatos EXIF (JPEG, TIFF, WebP) ──────────────────────────
    if ext in (".jpg", ".jpeg", ".tiff", ".tif", ".webp"):
        _analyze_exif(filepath, result)

    # ── 4. Datos extra después del marcador de fin ────────────────────
    extra = _check_trailing_data(raw, ext)
    if extra:
        result["evidence"].append(evidence(
            "image_trailing_data",
            f"{len(extra)} bytes extra después del marcador de fin de imagen",
            min(50, 10 + len(extra) // 1024),
        ))
        result["score"] = max(result["score"], min(50, 10 + len(extra) // 1024))

    # ── 5. Threat name ────────────────────────────────────────────────
    if result["score"] >= 80:
        result["threat"] = "Imagen maliciosa"
    elif result["score"] >= 60:
        result["threat"] = "Imagen de alto riesgo"
    elif result["score"] >= 30:
        result["threat"] = "Imagen sospechosa"

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Magic bytes por formato
# ═══════════════════════════════════════════════════════════════════════

MAGIC = {
    ".jpg":  (b"\xff\xd8\xff",       "JPEG"),
    ".jpeg": (b"\xff\xd8\xff",       "JPEG"),
    ".png":  (b"\x89\x50\x4e\x47",    "PNG"),
    ".gif":  (b"\x47\x49\x46\x38",    "GIF"),
    ".bmp":  (b"\x42\x4d",            "BMP"),
    ".webp": (b"\x52\x49\x46\x46",    "WebP"),
    ".tiff": (b"\x49\x49\x2a\x00",    "TIFF (little-endian)"),
    ".tif":  (b"\x49\x49\x2a\x00",    "TIFF (little-endian)"),
    ".ico":  (b"\x00\x00\x01\x00",    "ICO"),
}

# Marcadores de fin de imagen por formato
END_MARKERS = {
    ".jpg":  b"\xff\xd9",           # EOI (End of Image)
    ".jpeg": b"\xff\xd9",
    ".png":  b"\x49\x45\x4e\x44",   # IEND chunk
    ".gif":  b"\x00\x3b",           # GIF trailer
    ".bmp":  None,                   # no marcador fijo
    ".webp": None,
    ".tiff": None,
    ".tif":  None,
    ".ico":  None,
}

# Rangos de dimensión válidos (ancho/alto)
MIN_DIM = 1
MAX_DIM = 100000


# ═══════════════════════════════════════════════════════════════════════
#  Helpers de lectura
# ═══════════════════════════════════════════════════════════════════════

def _safe_read(filepath: str, limit: int = 50 * 1024 * 1024) -> Optional[bytes]:
    try:
        size = os.path.getsize(filepath)
        if size > limit:
            return None
        with open(filepath, "rb") as f:
            return f.read()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
#  1. Magic bytes
# ═══════════════════════════════════════════════════════════════════════

def _check_magic_bytes(raw: bytes, ext: str, result: dict):
    expected = MAGIC.get(ext)
    if not expected:
        return
    magic, name = expected
    if not raw.startswith(magic):
        alt = MAGIC.get(ext)
        if alt:
            other_name = alt[1]
            result["evidence"].append(evidence(
                "image_magic_mismatch",
                f"Extensión {ext} no coincide con firma ({other_name})",
                40,
            ))
            result["score"] = max(result["score"], 40)


# ═══════════════════════════════════════════════════════════════════════
#  2. Dimensiones
# ═══════════════════════════════════════════════════════════════════════

def _parse_dimensions(raw: bytes, ext: str) -> Optional[tuple]:
    try:
        if ext in (".jpg", ".jpeg"):
            return _jpg_dims(raw)
        if ext == ".png":
            return _png_dims(raw)
        if ext == ".gif":
            return _gif_dims(raw)
        if ext == ".bmp":
            return _bmp_dims(raw)
        if ext == ".webp":
            return _webp_dims(raw)
        if ext in (".tiff", ".tif"):
            return _tiff_dims(raw)
        if ext == ".ico":
            return _ico_dims(raw)
    except Exception:
        pass
    return None


def _jpg_dims(raw: bytes) -> Optional[tuple]:
    """Lee dimensiones desde el marco SOF0 (Start of Frame)."""
    i = 2
    while i < len(raw) - 1:
        if raw[i] != 0xff:
            break
        marker = raw[i+1]
        if marker == 0xc0 or marker == 0xc1 or marker == 0xc2:
            if i + 9 < len(raw):
                h = struct.unpack(">H", raw[i+5:i+7])[0]
                w = struct.unpack(">H", raw[i+7:i+9])[0]
                return (w, h)
        if marker == 0xd9:
            break
        if marker == 0x00 or marker == 0xd0 or marker == 0xd1 or marker == 0xd2 or marker == 0xd3 or marker == 0xd4 or marker == 0xd5 or marker == 0xd6 or marker == 0xd7 or marker == 0xd8:
            i += 2
            continue
        if i + 3 < len(raw):
            length = struct.unpack(">H", raw[i+2:i+4])[0]
            i += 2 + length
        else:
            break
    return None


def _png_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 24:
        return None
    w = struct.unpack(">I", raw[16:20])[0]
    h = struct.unpack(">I", raw[20:24])[0]
    return (w, h)


def _gif_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 10:
        return None
    w = struct.unpack("<H", raw[6:8])[0]
    h = struct.unpack("<H", raw[8:10])[0]
    return (w, h)


def _bmp_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 26:
        return None
    w = struct.unpack("<i", raw[18:22])[0]
    h = struct.unpack("<i", raw[22:26])[0]
    return (abs(w), abs(h))


def _webp_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 30:
        return None
    if raw[0:4] != b"RIFF" or raw[8:12] != b"WEBP":
        return None
    fmt = raw[12:16]
    if fmt == b"VP8 " and len(raw) >= 26:
        # VP8 keyframe
        w = struct.unpack("<H", raw[24:26])[0] & 0x3fff
        h = struct.unpack("<H", raw[26:28])[0] & 0x3fff
        return (w, h)
    if fmt == b"VP8L" and len(raw) >= 25:
        bits = struct.unpack("<I", raw[21:25])[0]
        w = (bits & 0x3fff) + 1
        h = ((bits >> 14) & 0x3fff) + 1
        return (w, h)
    if fmt == b"VP8X" and len(raw) >= 30:
        w = struct.unpack("<I", raw[24:28])[0] & 0x00ffffff
        h = struct.unpack("<I", raw[28:32])[0] & 0x00ffffff
        return (w + 1, h + 1)
    return None


def _tiff_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 8:
        return None
    le = raw[0:2] == b"II"
    endian = "<" if le else ">"
    if raw[0:2] not in (b"II", b"MM"):
        return None
    ifd_offset = struct.unpack(f"{endian}I", raw[4:8])[0]
    if ifd_offset + 2 > len(raw):
        return None
    n_entries = struct.unpack(f"{endian}H", raw[ifd_offset:ifd_offset+2])[0]
    w, h = None, None
    for i in range(n_entries):
        entry_off = ifd_offset + 2 + i * 12
        if entry_off + 12 > len(raw):
            break
        tag = struct.unpack(f"{endian}H", raw[entry_off:entry_off+2])[0]
        val_off = entry_off + 8
        if tag == 0x0100 and val_off + 4 <= len(raw):
            w = struct.unpack(f"{endian}I", raw[val_off:val_off+4])[0]
        elif tag == 0x0101 and val_off + 4 <= len(raw):
            h = struct.unpack(f"{endian}I", raw[val_off:val_off+4])[0]
        if w and h:
            return (w, h)
    return None


def _ico_dims(raw: bytes) -> Optional[tuple]:
    if len(raw) < 6:
        return None
    count = struct.unpack("<H", raw[4:6])[0]
    if count < 1 or len(raw) < 6 + count * 16:
        return None
    w = raw[6] if raw[6] else 256
    h = raw[7] if raw[7] else 256
    return (w, h)


def _check_dimensions(dims: tuple, result: dict):
    w, h = dims
    if w < MIN_DIM or h < MIN_DIM:
        result["evidence"].append(evidence(
            "image_zero_dimensions",
            f"Dimensiones inválidas: {w}x{h}", 50,
        ))
        result["score"] = max(result["score"], 50)
        return
    if w > MAX_DIM or h > MAX_DIM:
        result["evidence"].append(evidence(
            "image_extreme_dimensions",
            f"Dimensiones extremas: {w}x{h}", 30,
        ))
        result["score"] = max(result["score"], 30)


def _check_size_vs_dimensions(filepath: str, dims: tuple, result: dict):
    """Detecta tamaño anómalo (posible stego: archivo muy grande para su resolución)."""
    try:
        size = os.path.getsize(filepath)
        w, h = dims
        pixels = w * h
        if pixels == 0:
            return
        bytes_per_pixel = size / pixels
        if bytes_per_pixel > 10:
            result["evidence"].append(evidence(
                "image_size_anomaly",
                f"Tamaño anómalo: {size//1024}KB para {w}x{h} ({bytes_per_pixel:.1f} bytes/px)",
                25,
            ))
            result["score"] = max(result["score"], 25)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  3. SVG analysis
# ═══════════════════════════════════════════════════════════════════════

SVG_PATTERNS = [
    (re.compile(rb'<script[\s>]', re.IGNORECASE), 85, "image_svg_script", "SVG con <script> — JavaScript embebido"),
    (re.compile(rb'on(load|error|click|mouseover|focus|submit|change)\s*=', re.IGNORECASE), 80, "image_svg_handler", "SVG con event handler"),
    (re.compile(rb'<foreignObject[\s>]', re.IGNORECASE), 65, "image_svg_foreign", "SVG con <foreignObject> — puede contener HTML/JS"),
    (re.compile(rb'data\s*:\s*text/javascript', re.IGNORECASE), 85, "image_svg_data_js", "SVG con data:text/javascript"),
    (re.compile(rb'(href|src)\s*=\s*["\']\s*https?://', re.IGNORECASE), 40, "image_svg_external", "SVG con referencia HTTP externa"),
    (re.compile(rb'<image\s+[^>]*href\s*=\s*["\']\s*https?://', re.IGNORECASE), 50, "image_svg_ext_image", "SVG con <image> desde URL externa"),
    (re.compile(rb'<use\s+[^>]*href\s*=\s*["\']\s*https?://', re.IGNORECASE), 50, "image_svg_ext_use", "SVG con <use> desde URL externa"),
    (re.compile(rb'<set\s+[^>]*attributeName\s*=', re.IGNORECASE), 30, "image_svg_animate", "SVG con animación que puede modificar atributos"),
    (re.compile(rb'push\s+(graphics|defs|pattern)', re.IGNORECASE), 70, "image_svg_mvg", "SVG con contenido MVG — posible ImageMagick exploit"),
]


def _analyze_svg(raw: bytes, result: dict):
    for pattern, severity, etype, detail in SVG_PATTERNS:
        if pattern.search(raw):
            result["evidence"].append(evidence(etype, detail, severity))
            result["score"] = max(result["score"], severity)


# ═══════════════════════════════════════════════════════════════════════
#  4. EXIF metadata analysis (JPEG, TIFF, WebP)
# ═══════════════════════════════════════════════════════════════════════

def _analyze_exif(filepath: str, result: dict):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return

    try:
        img = Image.open(filepath)
        exif = img.getexif()
    except Exception:
        return

    if not exif:
        return

    # Revisar campos EXIF sospechosos
    for tag_id, value in exif.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        val_str = str(value)

        if tag_name == "ImageDescription" and len(val_str) > 500:
            result["evidence"].append(evidence(
                "image_exif_long_desc",
                f"EXIF ImageDescription muy largo ({len(val_str)} chars)", 25,
            ))
            result["score"] = max(result["score"], 25)

        if tag_name == "UserComment" and len(val_str) > 300:
            result["evidence"].append(evidence(
                "image_exif_long_comment",
                f"EXIF UserComment muy largo ({len(val_str)} chars)", 30,
            ))
            result["score"] = max(result["score"], 30)

        if tag_name == "Software":
            if any(kw in val_str.lower() for kw in ("exploit", "inject", "payload", "backdoor", "malware")):
                result["evidence"].append(evidence(
                    "image_exif_suspicious_software",
                    f"EXIF Software sospechoso: {val_str[:100]}", 75,
                ))
                result["score"] = max(result["score"], 75)

        if tag_name == "GPSInfo" and val_str != "{}":
            result["evidence"].append(evidence(
                "image_exif_gps",
                "EXIF contiene coordenadas GPS", 5,
            ))
            result["score"] = max(result["score"], 5)

    img.close()


# ═══════════════════════════════════════════════════════════════════════
#  5. Trailing data after end marker
# ═══════════════════════════════════════════════════════════════════════

def _check_trailing_data(raw: bytes, ext: str) -> Optional[bytes]:
    marker = END_MARKERS.get(ext)
    if marker is None:
        return None
    idx = raw.rfind(marker)
    if idx == -1:
        return None
    after = raw[idx + len(marker):]
    if len(after) > 0:
        return after
    return None
