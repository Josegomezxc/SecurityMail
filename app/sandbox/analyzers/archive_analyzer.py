"""
Analizador de archivos comprimidos (.zip, .rar, .7z, .iso).
Extrae el contenido en un directorio temporal con límites estrictos
(profundidad máxima, tamaño máximo, número de ficheros máximo) y delega
el análisis a la función pasada por el orquestador.

NOTA: requiere `recurse_fn(path, mime)` que devuelve el dict canónico,
para evitar dependencias circulares con run_analysis.py.
"""
import os
import tempfile
import zipfile
import shutil
from .base import empty_result, evidence

MAX_DEPTH        = 2          # No anidar contenedores más allá de 2 niveles
MAX_FILES        = 50         # Límite de ficheros a extraer
MAX_TOTAL_BYTES  = 50 * 1024 * 1024   # 50 MB descomprimidos máximo (anti zip-bomb)
MAX_FILE_BYTES   = 20 * 1024 * 1024   # 20 MB por fichero individual

# Extensiones que SIEMPRE son alarmantes dentro de un comprimido
INSIDE_DANGEROUS_EXT = {
    ".exe": 88, ".scr": 88, ".com": 85, ".pif": 85, ".cpl": 80,
    ".dll": 75, ".sys": 80, ".msi": 75, ".bat": 80, ".cmd": 80,
    ".ps1": 80, ".vbs": 80, ".vbe": 80, ".js": 75, ".jse": 80,
    ".wsf": 80, ".wsh": 80, ".hta": 85, ".jar": 70, ".lnk": 85,
    ".reg": 70, ".chm": 75, ".iso": 65, ".vhd": 65, ".vhdx": 65,
    ".img": 60, ".ace": 70,
}


def analyze(filepath: str, mime: str = "", recurse_fn=None, depth: int = 0) -> dict:
    result = empty_result("archive")

    if depth >= MAX_DEPTH:
        result["evidence"].append(evidence(
            "archive_depth", f"Profundidad máxima ({MAX_DEPTH}) alcanzada — no se descomprime más", 30,
        ))
        return result

    # Decidir tipo de archivo
    ext = os.path.splitext(filepath)[1].lower()

    extract_dir = tempfile.mkdtemp(prefix="sandbox_arc_")
    try:
        try:
            extracted = _extract(filepath, ext, extract_dir, result)
        except _ZipBombError as zb:
            result["score"] = max(result["score"], 90)
            result["threat"] = "Posible zip-bomb"
            result["evidence"].append(evidence(
                "zip_bomb", str(zb), 90,
            ))
            return result
        except _ProtectedError:
            # Archivos comprimidos con contraseña son SOSPECHOSOS por diseño
            # (técnica clásica de evasión de antivirus)
            result["score"] = max(result["score"], 75)
            result["threat"] = "Archivo comprimido protegido con contraseña"
            result["evidence"].append(evidence(
                "password_protected",
                "El archivo está cifrado/protegido — es una técnica común para evadir antivirus",
                75,
            ))
            return result
        except Exception as e:
            result["evidence"].append(evidence(
                "extract_error", f"No se pudo extraer ({ext}): {e}", 35,
            ))
            return result

        if not extracted:
            result["evidence"].append(evidence(
                "empty_archive", "El archivo comprimido está vacío", 20,
            ))
            return result

        result["evidence"].append(evidence(
            "archive_contents",
            f"{len(extracted)} elemento(s) descomprimido(s)",
            10,
        ))

        # Analiza cada fichero extraído
        for inner_path in extracted:
            inner_ext = os.path.splitext(inner_path)[1].lower()
            inner_name = os.path.basename(inner_path)

            # Marcador rápido por extensión
            if inner_ext in INSIDE_DANGEROUS_EXT:
                sev = INSIDE_DANGEROUS_EXT[inner_ext]
                result["evidence"].append(evidence(
                    "dangerous_inside",
                    f"Ejecutable dentro del comprimido: {inner_name}",
                    sev,
                ))
                result["score"] = max(result["score"], sev)
                result["threat"] = f"Comprimido contiene ejecutable peligroso ({inner_ext})"

            # Análisis profundo si tenemos la función recursiva
            if recurse_fn:
                try:
                    sub = recurse_fn(inner_path, depth=depth + 1)
                    if sub:
                        result["score"] = max(result["score"], int(sub.get("score", 0)))
                        for ev in sub.get("evidence", [])[:10]:
                            ev["detail"] = f"[{inner_name}] {ev.get('detail', '')}"
                            result["evidence"].append(ev)
                        if sub.get("threat") and not result["threat"]:
                            result["threat"] = sub["threat"]
                        for key in ("urls", "ips", "domains", "hashes"):
                            for item in sub.get("iocs", {}).get(key, []):
                                if item not in result["iocs"][key]:
                                    result["iocs"][key].append(item)
                except Exception as e:
                    result["evidence"].append(evidence(
                        "recurse_error",
                        f"Error analizando {inner_name}: {e}",
                        30,
                    ))

    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)

    return result


# ───────────────────────────────────────────────────────────────────────
#  Extracción
# ───────────────────────────────────────────────────────────────────────

class _ZipBombError(Exception):
    pass

class _ProtectedError(Exception):
    pass


def _extract(filepath: str, ext: str, dest: str, result: dict) -> list:
    """Devuelve la lista de paths extraídos (solo ficheros, no directorios)."""
    if ext == ".zip" or _looks_like_zip(filepath):
        return _extract_zip(filepath, dest)
    if ext == ".7z":
        return _extract_7z(filepath, dest)
    if ext in (".rar",):
        return _extract_rar(filepath, dest)
    raise Exception(f"formato '{ext}' no soportado")


def _looks_like_zip(filepath: str) -> bool:
    try:
        with open(filepath, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except Exception:
        return False


def _extract_zip(filepath: str, dest: str) -> list:
    extracted = []
    total_bytes = 0

    with zipfile.ZipFile(filepath, "r") as z:
        # ¿Cifrado?
        for info in z.infolist():
            if info.flag_bits & 0x1:
                raise _ProtectedError("ZIP con contraseña")

        # Comprueba ratio de compresión
        compressed = sum(i.compress_size for i in z.infolist())
        uncompressed = sum(i.file_size for i in z.infolist())
        if compressed > 0 and uncompressed / compressed > 100 and uncompressed > 10 * 1024 * 1024:
            raise _ZipBombError(
                f"Ratio de compresión sospechoso: {uncompressed/compressed:.0f}x"
            )

        for info in z.infolist()[:MAX_FILES]:
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_BYTES:
                continue
            total_bytes += info.file_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise _ZipBombError(
                    f"Tamaño descomprimido > {MAX_TOTAL_BYTES//1024//1024} MB"
                )
            # Path traversal protection
            target = os.path.normpath(os.path.join(dest, info.filename))
            if not target.startswith(dest):
                continue
            try:
                z.extract(info, dest)
                extracted.append(target)
            except Exception:
                continue
    return extracted


def _extract_7z(filepath: str, dest: str) -> list:
    try:
        import py7zr
    except Exception:
        raise Exception("py7zr no disponible")
    try:
        with py7zr.SevenZipFile(filepath, mode="r") as z:
            if z.needs_password():
                raise _ProtectedError("7z con contraseña")
            z.extractall(path=dest)
    except _ProtectedError:
        raise
    except Exception as e:
        raise Exception(f"7z error: {e}")
    return _walk_files(dest)


def _extract_rar(filepath: str, dest: str) -> list:
    try:
        import rarfile
    except Exception:
        raise Exception("rarfile no disponible")
    try:
        with rarfile.RarFile(filepath) as r:
            if r.needs_password():
                raise _ProtectedError("RAR con contraseña")
            r.extractall(path=dest)
    except _ProtectedError:
        raise
    except Exception as e:
        raise Exception(f"rar error: {e}")
    return _walk_files(dest)


def _walk_files(root: str) -> list:
    out = []
    for base, _dirs, files in os.walk(root):
        for f in files:
            out.append(os.path.join(base, f))
            if len(out) >= MAX_FILES:
                return out
    return out
