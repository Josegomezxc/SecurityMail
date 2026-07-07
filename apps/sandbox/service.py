"""
Servicio que invoca el sandbox Docker desde Django.
Recibe un EmailMessage, devuelve el reporte canónico.
"""
import subprocess
import json
import os

SANDBOX_IMAGE = "email_seguro_sandbox"

# Empty report en el formato nuevo (compatible con el orquestador)
EMPTY_REPORT = {
    "filename":            "",
    "size":                0,
    "sha256":              "",
    "md5":                 "",
    "real_mime":           "",
    "extension":           "",
    "extension_spoof":     False,
    "category":            "unknown",
    "risk_score":          0,
    "risk_level":          "safe",
    "threat_name":         "",
    "evidence":            [],
    "iocs":                {"urls": [], "ips": [], "domains": [], "hashes": []},
    "analyzers_run":       [],
    "yara_matches":        [],
    "network_connections": [],
    "child_processes":     [],
    "file_writes":         [],
    # Compatibilidad con código viejo:
    "real_mime":           "",
}


def _empty(error: str = "") -> dict:
    out = dict(EMPTY_REPORT)
    out["iocs"] = {"urls": [], "ips": [], "domains": [], "hashes": []}
    if error:
        out["evidence"] = [{"type": "service_error", "detail": error, "severity": 30}]
    return out


def run_sandbox_analysis(email_message) -> dict:
    """Punto de entrada. Devuelve el dict canónico del reporte."""
    filepath = email_message.attachment_path

    if not filepath or not os.path.exists(filepath):
        return _empty("No hay adjunto que analizar")

    # Convertir ruta Windows → Docker (C:\foo → /c/foo)
    docker_path = filepath.replace("\\", "/")
    if len(docker_path) > 1 and docker_path[1] == ":":
        drive = docker_path[0].lower()
        docker_path = "/" + drive + docker_path[2:]

    container_path = "/tmp/" + os.path.basename(filepath)

    try:
        print(f"[sandbox] docker run — {os.path.basename(filepath)} ({os.path.getsize(filepath)//1024} KB)", flush=True)
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",          # SIN red — ningún script puede llamar fuera
                "--memory", "1g",             # RAM para archivos grandes (oletools/pefile)
                "--cpus", "2.0",
                "--read-only",                # filesystem de solo lectura
                "--tmpfs", "/tmp:size=512m",  # /tmp escribible pero efímero
                "-v", f"{docker_path}:{container_path}:ro",
                SANDBOX_IMAGE,
                "python", "/app/sandbox/run_analysis.py", container_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",                 # ← fuerza UTF-8 (Windows usa cp1252 por defecto
                                              #    y rompe acentos como "detección" → "detecciÃ³n")
            errors="replace",                 # nunca crashea por bytes raros del sandbox
            timeout=120,                      # por adjunto — previene hang en lotes
        )

        if result.returncode != 0 and not result.stdout:
            print("SANDBOX ERROR:", result.stderr[:500])
            return _empty(f"Sandbox falló (rc={result.returncode}): {result.stderr[:200]}")

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("SANDBOX BAD JSON:", result.stdout[:500])
            return _empty("Sandbox devolvió JSON inválido")

        # Backwards compat: si el sandbox antiguo devuelve sólo `score` interno
        if "risk_score" not in report and "score" in report:
            report["risk_score"] = report["score"]

        report = _normalize(report)
        print(f"[sandbox] → score:{report['risk_score']} yara:{len(report.get('yara_matches',[]))} amenaza:{report.get('threat_name','')[:40]}", flush=True)
        return report

    except subprocess.TimeoutExpired:
        print(f"[sandbox] ⏱ timeout — {os.path.basename(filepath)}", flush=True)
        return _empty_timeout()
    except FileNotFoundError:
        print("[sandbox] ❌ Docker no disponible en el sistema", flush=True)
        return _empty("Docker no disponible en el sistema")
    except Exception as e:
        print("SANDBOX EXCEPTION:", e)
        return _empty(str(e))


def run_sandbox_with_password(filepath: str, password: str) -> dict:
    """Ejecuta el sandbox Docker con una contraseña para descomprimir archivos protegidos."""
    safe_password = password.replace('\n', '').replace('\r', '').replace('\x00', '')
    if safe_password != password:
        print("[sandbox] password sanitizada (se eliminaron caracteres de control)", flush=True)

    if not filepath or not os.path.exists(filepath):
        return _empty("No hay archivo que analizar")

    docker_path = filepath.replace("\\", "/")
    if len(docker_path) > 1 and docker_path[1] == ":":
        drive = docker_path[0].lower()
        docker_path = "/" + drive + docker_path[2:]
    container_path = "/tmp/" + os.path.basename(filepath)

    try:
        print(f"[sandbox] docker run (con password) — {os.path.basename(filepath)}", flush=True)
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", "1g",
                "--cpus", "2.0",
                "--read-only",
                "--tmpfs", "/tmp:size=512m",
                "-e", f"SANDBOX_PASSWORD={safe_password}",
                "-v", f"{docker_path}:{container_path}:ro",
                SANDBOX_IMAGE,
                "python", "/app/sandbox/run_analysis.py", container_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

        if result.returncode != 0 and not result.stdout:
            print("SANDBOX ERROR:", result.stderr[:500])
            return _empty(f"Sandbox falló (rc={result.returncode}): {result.stderr[:200]}")

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("SANDBOX BAD JSON:", result.stdout[:500])
            return _empty("Sandbox devolvió JSON inválido")

        if "risk_score" not in report and "score" in report:
            report["risk_score"] = report["score"]

        report = _normalize(report)
        print(f"[sandbox] → score:{report['risk_score']} amenaza:{report.get('threat_name','')[:40]}", flush=True)
        return report

    except subprocess.TimeoutExpired:
        print(f"[sandbox] ⏱ timeout — {os.path.basename(filepath)}", flush=True)
        return _empty_timeout()
    except FileNotFoundError:
        print("[sandbox] ❌ Docker no disponible en el sistema", flush=True)
        return _empty("Docker no disponible en el sistema")
    except Exception as e:
        print("SANDBOX EXCEPTION:", e)
        return _empty(str(e))


def _empty_timeout() -> dict:
    """Cuando el análisis excede el timeout, lo marcamos como advertencia."""
    out = _empty()
    out["risk_score"] = 50
    out["risk_level"] = "warning"
    out["threat_name"] = "Análisis interrumpido por timeout"
    out["evidence"] = [{
        "type": "timeout",
        "detail": "El sandbox excedió el tiempo máximo — comportamiento sospechoso por sí solo",
        "severity": 50,
    }]
    return out


def _normalize(report: dict) -> dict:
    """Garantiza que todas las claves esperadas existen."""
    base = _empty()
    for k, v in base.items():
        if k not in report or report.get(k) is None:
            report[k] = v
    return report
