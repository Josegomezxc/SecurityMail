"""
DockerShield — Orquestador de análisis dentro del sandbox Docker.

Este script se ejecuta como entrypoint del contenedor. Recibe la ruta de
un fichero, detecta su tipo REAL (no por extensión) y delega en los
analizadores especializados de `analyzers/`.

Salida: JSON único en stdout con el formato:
{
    "filename":         "factura.pdf.exe",
    "size":             123456,
    "sha256":           "...",
    "md5":              "...",
    "real_mime":        "application/x-dosexec",
    "extension":        ".exe",
    "extension_spoof":  true,
    "category":         "executable",
    "risk_score":       0..100,
    "risk_level":       "safe" | "warning" | "danger" | "malware",
    "threat_name":      "Ejecutable Windows con APIs de inyección",
    "evidence":         [ { "type": "...", "detail": "...", "severity": 0..100 }, ... ],
    "iocs":             { "urls": [...], "ips": [...], "domains": [...], "hashes": [...] },
    "analyzers_run":    ["yara", "executable", ...],

    # Compatibilidad con el modelo SandboxAnalysis existente:
    "yara_matches":         [...]
    "network_connections":  [...]
    "child_processes":      [...]
    "file_writes":          [...]
}
"""
import sys
import os
import json
import hashlib
import traceback

from analyzers import (
    executable_analyzer,
    office_analyzer,
    pdf_analyzer,
    archive_analyzer,
    script_analyzer,
    yara_analyzer,
    dynamic_executor,
)


# ───────────────────────────────────────────────────────────────────────
#  Mapas de extensiones → categoría
# ───────────────────────────────────────────────────────────────────────

EXT_EXECUTABLE = {".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".msi", ".efi"}
EXT_OFFICE     = {".doc", ".docx", ".docm", ".dot", ".dotm",
                  ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltm",
                  ".ppt", ".pptx", ".pptm", ".pps", ".ppsm",
                  ".rtf"}
EXT_PDF        = {".pdf"}
EXT_ARCHIVE    = {".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".bz2", ".xz", ".cab"}
EXT_SCRIPT     = {".sh", ".bash", ".zsh", ".ps1", ".psm1",
                  ".vbs", ".vbe", ".wsf", ".wsh",
                  ".js", ".jse",
                  ".bat", ".cmd",
                  ".hta", ".lnk", ".reg", ".jar",
                  ".py", ".pl", ".rb", ".php"}

# Extensiones siempre peligrosas (incluso sin más análisis)
ALWAYS_RISKY = {
    ".exe": 88, ".scr": 90, ".com": 85, ".pif": 90, ".cpl": 80,
    ".bat": 75, ".cmd": 75, ".ps1": 80, ".vbs": 80, ".vbe": 85,
    ".js":  70, ".jse": 80, ".wsf": 80, ".wsh": 80,
    ".hta": 85, ".lnk": 80, ".reg": 70, ".chm": 75,
    ".jar": 65, ".msi": 70, ".dll": 75, ".sys": 75,
    ".iso": 60, ".vhd": 60, ".vhdx": 60, ".img": 60,
    ".ace": 65,
}

# Extensiones que parecen documentos pero suelen esconder ejecutables
DOUBLE_EXT_TRAP = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".jpg.exe", ".png.exe",
    ".pdf.scr", ".pdf.cmd", ".pdf.bat", ".pdf.js",
}


# ───────────────────────────────────────────────────────────────────────
#  Funciones auxiliares
# ───────────────────────────────────────────────────────────────────────

def hash_file(filepath: str):
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def detect_real_mime(filepath: str) -> str:
    try:
        import magic
        return magic.from_file(filepath, mime=True)
    except Exception:
        return "application/octet-stream"


def is_extension_spoofed(ext: str, mime: str) -> bool:
    """Detecta extension-spoofing (ej. factura.pdf que en realidad es PE)."""
    spoof_map = {
        ".pdf":  ("application/pdf",),
        ".doc":  ("application/msword", "application/vnd.openxmlformats", "application/vnd.ms"),
        ".docx": ("application/vnd.openxmlformats", "application/zip"),
        ".xlsx": ("application/vnd.openxmlformats", "application/zip"),
        ".jpg":  ("image/jpeg",),
        ".jpeg": ("image/jpeg",),
        ".png":  ("image/png",),
        ".gif":  ("image/gif",),
        ".mp3":  ("audio/mpeg",),
        ".mp4":  ("video/",),
    }
    expected = spoof_map.get(ext.lower())
    if not expected:
        return False
    return not any(mime.startswith(e) for e in expected)


def to_risk_level(score: int) -> str:
    if score <= 30:  return "safe"
    if score <= 60:  return "warning"
    if score <= 80:  return "danger"
    return "malware"


# ───────────────────────────────────────────────────────────────────────
#  Orquestador principal
# ───────────────────────────────────────────────────────────────────────

def analyze(filepath: str, depth: int = 0) -> dict:
    """Devuelve el reporte canónico. `depth` se usa para recursión de archivos."""
    report = {
        "filename":        os.path.basename(filepath),
        "size":            0,
        "sha256":          "",
        "md5":             "",
        "real_mime":       "",
        "extension":       "",
        "extension_spoof": False,
        "category":        "unknown",
        "risk_score":      0,
        "risk_level":      "safe",
        "threat_name":     "",
        "evidence":        [],
        "iocs":            {"urls": [], "ips": [], "domains": [], "hashes": []},
        "analyzers_run":   [],

        # Campos legacy del modelo SandboxAnalysis:
        "yara_matches":        [],
        "network_connections": [],
        "child_processes":     [],
        "file_writes":         [],
    }

    if not os.path.exists(filepath):
        report["threat_name"] = "Archivo no encontrado"
        return report

    try:
        report["size"] = os.path.getsize(filepath)
        report["sha256"], report["md5"] = hash_file(filepath)
        report["iocs"]["hashes"].extend([report["sha256"], report["md5"]])
    except Exception as e:
        report["evidence"].append({
            "type": "hash_error", "detail": str(e), "severity": 30,
        })

    # Tipo real
    mime = detect_real_mime(filepath)
    report["real_mime"] = mime

    # Extensión y posibles trampas
    name_lower = os.path.basename(filepath).lower()
    ext = os.path.splitext(name_lower)[1]
    report["extension"] = ext

    # Detección de extensión doble (ej. factura.pdf.exe)
    matched_double = None
    for double_ext in DOUBLE_EXT_TRAP:
        if name_lower.endswith(double_ext):
            matched_double = double_ext
            break
    if matched_double:
        report["evidence"].append({
            "type": "double_extension",
            "detail": f"Doble extensión detectada: '{matched_double}' — clásico engaño de phishing",
            "severity": 90,
        })
        report["risk_score"] = max(report["risk_score"], 90)
        report["threat_name"] = "Doble extensión engañosa"

    # Extension spoofing (parece pdf pero no es)
    if is_extension_spoofed(ext, mime):
        report["extension_spoof"] = True
        report["evidence"].append({
            "type": "extension_spoof",
            "detail": f"Extensión '{ext}' no coincide con MIME real ({mime}) — posible engaño",
            "severity": 80,
        })
        report["risk_score"] = max(report["risk_score"], 80)
        if not report["threat_name"]:
            report["threat_name"] = "Extensión engañosa"

    # Castigo por extensión "siempre peligrosa"
    if ext in ALWAYS_RISKY:
        sev = ALWAYS_RISKY[ext]
        report["evidence"].append({
            "type": "dangerous_extension",
            "detail": f"Extensión '{ext}' siempre peligrosa para usuarios finales",
            "severity": sev,
        })
        report["risk_score"] = max(report["risk_score"], sev)

    # ── DISPATCH a analizadores ────────────────────────────────────────
    sub_results = []

    # YARA siempre se ejecuta (es barato)
    try:
        yr = yara_analyzer.analyze(filepath, mime)
        if yr.get("evidence") or yr.get("score"):
            report["analyzers_run"].append("yara")
            sub_results.append(yr)
            for ev in yr.get("evidence", []):
                if ev.get("type", "").startswith("yara_"):
                    report["yara_matches"].append({
                        "rule":     ev.get("detail", "").split(":")[0].replace("YARA `", "").replace("`", "").strip(),
                        "category": ev.get("type", "yara_").replace("yara_", ""),
                        "severity": ev.get("severity", 0),
                    })
    except Exception as e:
        report["evidence"].append({
            "type": "analyzer_error", "detail": f"yara: {e}", "severity": 20,
        })

    # Por categoría
    if _is_executable(ext, mime):
        sub_results.append(_run(report, "executable", executable_analyzer.analyze, filepath, mime))

    elif _is_office(ext, mime):
        sub_results.append(_run(report, "office", office_analyzer.analyze, filepath, mime))

    elif _is_pdf(ext, mime):
        sub_results.append(_run(report, "pdf", pdf_analyzer.analyze, filepath, mime))

    elif _is_archive(ext, mime):
        # archivo comprimido — pasamos la función recursiva
        try:
            ar = archive_analyzer.analyze(
                filepath, mime,
                recurse_fn=lambda p, depth=depth+1: analyze(p, depth=depth),
                depth=depth,
            )
            report["analyzers_run"].append("archive")
            sub_results.append(ar)
        except Exception as e:
            report["evidence"].append({
                "type": "analyzer_error", "detail": f"archive: {e}", "severity": 20,
            })

    elif _is_script(ext, mime):
        sub_results.append(_run(report, "script", script_analyzer.analyze, filepath, mime))
        # Ejecución DINÁMICA real si el script es compatible con Linux (sh/bash/py)
        if dynamic_executor.can_execute(filepath):
            sub_results.append(_run(report, "dynamic", dynamic_executor.run, filepath))

    # Si no encajó en nada, intenta detectar como script genérico
    elif _looks_like_text(mime):
        sub_results.append(_run(report, "script", script_analyzer.analyze, filepath, mime))
        if dynamic_executor.can_execute(filepath):
            sub_results.append(_run(report, "dynamic", dynamic_executor.run, filepath))

    # ── Merge de todos los sub-reportes ────────────────────────────────
    for sr in sub_results:
        if not sr:
            continue
        report["risk_score"] = max(report["risk_score"], int(sr.get("score", 0)))
        if sr.get("threat") and not report["threat_name"]:
            report["threat_name"] = sr["threat"]
        report["evidence"].extend(sr.get("evidence", []))
        for key in ("urls", "ips", "domains", "hashes"):
            for item in sr.get("iocs", {}).get(key, []):
                if item not in report["iocs"][key]:
                    report["iocs"][key].append(item)
        if sr.get("category") and report["category"] == "unknown":
            report["category"] = sr["category"]

    # Si tras todo no hay threat name pero hay score, derivamos uno
    if not report["threat_name"]:
        if report["risk_score"] >= 81:
            report["threat_name"] = "Archivo malicioso"
        elif report["risk_score"] >= 61:
            report["threat_name"] = "Archivo de alto riesgo"
        elif report["risk_score"] >= 31:
            report["threat_name"] = "Archivo sospechoso"

    # Llenar campos legacy según evidencia (incluye dynamic_* del executor real)
    for ev in report["evidence"]:
        t = ev.get("type", "")
        d = ev.get("detail", "")
        # Conexiones de red (estáticas por IOCs o dinámicas por strace)
        if t.startswith("ioc_url") or t == "dynamic_network" or t == "dynamic_socket" or "url" in t.lower():
            if d not in report["network_connections"]:
                report["network_connections"].append(d)
        # Procesos (llamadas a APIs, patrones de ejecución o execve del strace)
        elif (t.startswith("vba_") or t.startswith("script_pattern")
              or t == "dynamic_process" or t == "dynamic_stdout" or t == "dynamic_forks"
              or "process" in t.lower() or "exec" in t.lower()):
            if d not in report["child_processes"]:
                report["child_processes"].append(d)
        # Archivos (accesos, eliminaciones, chmods del strace o IOCs de archivo)
        elif (t.startswith("dynamic_file_") or t == "dynamic_chmod"
              or "file" in t.lower() or "write" in t.lower() or "ole" in t.lower()):
            if d not in report["file_writes"]:
                report["file_writes"].append(d)

    report["risk_level"] = to_risk_level(report["risk_score"])
    return report


def _run(report, name, fn, *args, **kwargs):
    """Helper: corre un analizador y captura excepciones."""
    try:
        report["analyzers_run"].append(name)
        return fn(*args, **kwargs)
    except Exception as e:
        report["evidence"].append({
            "type": "analyzer_error",
            "detail": f"{name}: {e}",
            "severity": 20,
        })
        return None


# ── Detectores de tipo ─────────────────────────────────────────────────

def _is_executable(ext, mime):
    if ext in EXT_EXECUTABLE:
        return True
    return mime in (
        "application/x-dosexec",
        "application/x-msdownload",
        "application/x-executable",
        "application/x-sharedlib",
        "application/x-mach-binary",
        "application/vnd.microsoft.portable-executable",
    )

def _is_office(ext, mime):
    if ext in EXT_OFFICE:
        return True
    return any(m in mime for m in (
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument",
    ))

def _is_pdf(ext, mime):
    return ext in EXT_PDF or mime == "application/pdf"

def _is_archive(ext, mime):
    if ext in EXT_ARCHIVE:
        return True
    return mime in (
        "application/zip",
        "application/x-7z-compressed",
        "application/x-rar",
        "application/vnd.rar",
        "application/x-tar",
        "application/gzip",
    )

def _is_script(ext, mime):
    if ext in EXT_SCRIPT:
        return True
    return mime in (
        "text/x-shellscript",
        "application/x-sh",
        "text/x-python",
        "application/javascript",
    )

def _looks_like_text(mime):
    return mime.startswith("text/") or mime == "application/javascript"


# ───────────────────────────────────────────────────────────────────────
#  Entry point
# ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Uso: run_analysis.py <ruta_archivo>"}))
        sys.exit(1)
    try:
        out = analyze(sys.argv[1])
        print(json.dumps(out, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc(),
        }))
        sys.exit(2)
