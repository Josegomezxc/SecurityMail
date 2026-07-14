
import re
import zlib
from .base import empty_result, evidence

PDF_INDICATORS = [
    (rb'/JS\b',                    "Acción /JS (JavaScript embebido)",                75),
    (rb'/JavaScript\b',            "Bloque /JavaScript embebido",                     75),
    (rb'/AA\b',                    "Acción adicional /AA (auto al evento)",            70),
    (rb'/OpenAction\b',            "/OpenAction — ejecuta acción al abrir",            80),
    (rb'/Launch\b',                "/Launch — abre ejecutable externo",                90),
    (rb'/SubmitForm\b',            "/SubmitForm — envío de datos del formulario",      55),
    (rb'/ImportData\b',            "/ImportData — carga datos externos",               55),
    (rb'/RichMedia\b',             "/RichMedia — embed de Flash/audio/vídeo (CVE)",    65),
    (rb'/EmbeddedFile\b',          "/EmbeddedFile — archivo embebido",                 60),
    (rb'/XFA\b',                   "/XFA — Adobe XML Forms (vector clásico de exploit)", 70),
    (rb'/AcroForm\b',              "/AcroForm — formulario interactivo",               40),
    (rb'eval\(',                   "Llamada eval() en JavaScript del PDF",             80),
    (rb'unescape\(',               "Llamada unescape() (heap-spray clásico)",          75),
    (rb'String\.fromCharCode',     "String.fromCharCode (ofuscación JS)",              60),
    (rb'app\.alert',               "app.alert (interacción con Acrobat)",              30),
    (rb'this\.exportDataObject',   "exportDataObject (extracción de datos embebidos)", 70),
    (rb'util\.printd',             "util.printd (común en exploits)",                  45),
]


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("pdf")

    try:
        with open(filepath, "rb") as f:
            raw = f.read(20 * 1024 * 1024)
    except Exception as e:
        result["evidence"].append(evidence("read_error", str(e), 30))
        return result

    if not raw.startswith(b"%PDF-"):
        return result

    result["evidence"].append(evidence("format", "Documento PDF detectado", 5))

    decoded = raw + b"\n" + _decode_flate_streams(raw)

    for pattern, detail, sev in PDF_INDICATORS:
        matches = re.findall(pattern, decoded)
        if matches:
            count = len(matches)
            full_detail = f"{detail} (×{count})" if count > 1 else detail
            result["evidence"].append(evidence(
                "pdf_pattern", full_detail, sev,
            ))
            result["score"] = max(result["score"], sev)


    n_obj = len(re.findall(rb'\bobj\b', decoded))
    n_stream = len(re.findall(rb'\bstream\b', decoded))
    if n_obj > 0:
        ratio = n_stream / n_obj if n_obj else 0
        if ratio > 0.7 and n_stream > 5:
            result["evidence"].append(evidence(
                "pdf_structure",
                f"Alto ratio stream/obj ({n_stream}/{n_obj}) — potencial ofuscación",
                40,
            ))

    urls = re.findall(
        rb'https?://[^\s<>"\'()\[\]]+',
        decoded,
    )
    for u in list(dict.fromkeys(urls))[:25]:
        try:
            url_str = u.decode("ascii", errors="ignore")
            result["iocs"]["urls"].append(url_str)
            result["evidence"].append(evidence(
                "ioc_url", f"URL hardcoded en PDF: {url_str}", 50,
            ))
            result["score"] = max(result["score"], 50)
        except Exception:
            continue

    if result["score"] >= 80:
        result["threat"] = "PDF con acciones automáticas peligrosas"
    elif result["score"] >= 60:
        result["threat"] = "PDF con JavaScript embebido"
    elif result["score"] >= 40:
        result["threat"] = "PDF con elementos sospechosos"

    return result


def _decode_flate_streams(raw: bytes) -> bytes:

    out = b""

    for match in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.DOTALL):
        chunk = match.group(1)
        try:
            decompressed = zlib.decompress(chunk)
            out += decompressed + b"\n"
        except Exception:
            continue
    return out
