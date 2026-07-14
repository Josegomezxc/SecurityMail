
import subprocess
import json
import os

SANDBOX_IMAGE = "email_seguro_sandbox"

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
    "real_mime":           "",
}


def _empty(error: str = "") -> dict:
    out = dict(EMPTY_REPORT)
    out["iocs"] = {"urls": [], "ips": [], "domains": [], "hashes": []}
    if error:
        out["evidence"] = [{"type": "service_error", "detail": error, "severity": 30}]
    return out


def _empty_timeout() -> dict:
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

    base = _empty()
    for k, v in base.items():
        if k not in report or report.get(k) is None:
            report[k] = v
    return report


def scan_attachment(filepath: str) -> dict:

    if not filepath or not os.path.exists(filepath):
        return _empty("No hay adjunto que analizar")

    docker_path = filepath.replace("\\", "/")
    if len(docker_path) > 1 and docker_path[1] == ":":
        drive = docker_path[0].lower()
        docker_path = "/" + drive + docker_path[2:]

    container_path = "/tmp/" + os.path.basename(filepath)

    try:
        print(f"[attachment-scan] docker run — {os.path.basename(filepath)} ({os.path.getsize(filepath)//1024} KB)", flush=True)
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",
                "--memory", "256m",
                "--cpus", "1.0",
                "--read-only",
                "--tmpfs", "/tmp:size=64m",
                "-v", f"{docker_path}:{container_path}:ro",
                SANDBOX_IMAGE,
                "python", "/app/sandbox/run_analysis.py", container_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=25,
        )

        if result.returncode != 0 and not result.stdout:
            print("[attachment-scan] SANDBOX ERROR:", result.stderr[:500])
            return _empty(f"Sandbox falló (rc={result.returncode}): {result.stderr[:200]}")

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("[attachment-scan] SANDBOX BAD JSON:", result.stdout[:500])
            return _empty("Sandbox devolvió JSON inválido")

        if "risk_score" not in report and "score" in report:
            report["risk_score"] = report["score"]

        report = _normalize(report)


        score = report.get("risk_score", 0)
        if score > 0 and report.get("risk_level") in ("safe", "unknown"):
            if score >= 90:
                report["risk_level"] = "critical"
            elif score >= 70:
                report["risk_level"] = "high"
            elif score >= 40:
                report["risk_level"] = "medium"
            else:
                report["risk_level"] = "low"

        if report.get("risk_level") in ("malware", "danger"):
            report["risk_level"] = "critical"
        elif report.get("risk_level") in ("suspicious", "warning"):
            report["risk_level"] = "high"

        print(f"[attachment-scan] → score:{report['risk_score']} level:{report['risk_level']} yara:{len(report.get('yara_matches',[]))} amenaza:{report.get('threat_name','')[:40]}", flush=True)
        return report

    except subprocess.TimeoutExpired:
        print(f"[attachment-scan] ⏱ timeout — {os.path.basename(filepath)}", flush=True)
        return _empty_timeout()
    except FileNotFoundError:
        print("[attachment-scan] ❌ Docker no disponible en el sistema", flush=True)
        return _empty("Docker no disponible en el sistema")
    except Exception as e:
        print("[attachment-scan] SANDBOX EXCEPTION:", e)
        return _empty(str(e))
