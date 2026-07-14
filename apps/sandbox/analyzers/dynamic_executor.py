
import os
import subprocess
import re
import signal
from .base import empty_result, evidence



EXEC_TIMEOUT = 5

EXECUTABLE_EXTS = {
    ".sh":   ["bash"],
    ".bash": ["bash"],
    ".py":   ["python3"],
}


def can_execute(filepath: str) -> bool:
    ext = os.path.splitext(filepath)[1].lower()
    return ext in EXECUTABLE_EXTS


def run(filepath: str) -> dict:
    result = empty_result("dynamic")

    ext = os.path.splitext(filepath)[1].lower()
    interp = EXECUTABLE_EXTS.get(ext)
    if not interp:
        return result

    try:
        os.chmod(filepath, 0o755)
    except OSError:
        pass

    strace_cmd = [
        "strace", "-f",
        "-e", "trace=network,openat,execve,connect,socket,unlink,chmod,clone,fork,vfork",
        "-s", "128",
    ] + interp + [filepath]

    try:
        proc = subprocess.run(
            strace_cmd,
            capture_output=True,
            text=True,
            timeout=EXEC_TIMEOUT,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        rc     = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or b"").decode(errors="ignore") if e.stdout else ""
        stderr = (e.stderr or b"").decode(errors="ignore") if e.stderr else ""
        rc     = -signal.SIGTERM
        timed_out = True
        result["evidence"].append(evidence(
            "dynamic_timeout",
            f"Ejecución interrumpida tras {EXEC_TIMEOUT}s — comportamiento prolongado sospechoso",
            65,
        ))
        result["score"] = max(result["score"], 65)
    except FileNotFoundError:
        return _run_fallback(filepath, interp)
    except Exception as e:
        result["evidence"].append(evidence(
            "dynamic_error", f"Error durante la ejecución: {e}", 30,
        ))
        return result

    _parse_strace(stderr, result)      
    _parse_stdout(stdout, result)
    _score_behavior(rc, timed_out, result)

    return result

RE_CONNECT    = re.compile(r'connect\([^,]+,\s*\{[^\}]*?inet_addr\("([^"]+)"\)[^}]*sin_port=htons\((\d+)\)')
RE_CONNECT_ALT= re.compile(r'connect\([^,]+,\s*\{[^\}]*?inet_addr\("([^"]+)"\)')
RE_SOCKET     = re.compile(r'socket\(([^,]+),')
RE_EXECVE     = re.compile(r'execve\("([^"]+)"')
RE_OPEN_FILE  = re.compile(r'openat\([^,]+,\s*"([^"]+)"')
RE_CLONE      = re.compile(r'\b(clone|fork|vfork)\(')
RE_UNLINK     = re.compile(r'unlink(?:at)?\([^,"]*"?([^"\)]+)')
RE_CHMOD      = re.compile(r'(?:f?chmod(?:at)?)\([^,]+,\s*"([^"]+)"?,?\s*(\d+)?')


def _parse_strace(text: str, result: dict) -> None:
    connections = set()
    for m in RE_CONNECT.finditer(text):
        ip, port = m.group(1), m.group(2)
        connections.add(f"{ip}:{port}")
    for m in RE_CONNECT_ALT.finditer(text):
        connections.add(m.group(1))

    for c in list(connections)[:20]:
        result["evidence"].append(evidence(
            "dynamic_network",
            f"Intento de conexión de red observado: {c}",
            85,
        ))
        result["iocs"]["ips"].append(c.split(":")[0])
        result["score"] = max(result["score"], 85)


    sock_families = set(RE_SOCKET.findall(text))
    dangerous_fams = {"AF_INET", "AF_INET6", "AF_NETLINK"}
    if sock_families & dangerous_fams:
        result["evidence"].append(evidence(
            "dynamic_socket",
            f"Sockets de red creados: {', '.join(sock_families & dangerous_fams)}",
            65,
        ))
        result["score"] = max(result["score"], 65)


    execs = [m.group(1) for m in RE_EXECVE.finditer(text)]
    suspicious_bins = {
        "/bin/nc", "/usr/bin/nc", "/bin/ncat", "/usr/bin/ncat",
        "/bin/curl", "/usr/bin/curl", "/bin/wget", "/usr/bin/wget",
        "/bin/sh", "/usr/bin/sh",
        "/usr/bin/python", "/usr/bin/python3",
        "/usr/bin/perl", "/usr/bin/ruby",
        "/usr/bin/ssh", "/usr/bin/scp",
    }
    spawned = set()
    for e in execs[1:]:   
        spawned.add(e)
    for child in list(spawned)[:15]:
        sev = 80 if child in suspicious_bins else 55
        reason = " — binario sospechoso" if child in suspicious_bins else ""
        result["evidence"].append(evidence(
            "dynamic_process",
            f"Proceso hijo: {child}{reason}",
            sev,
        ))
        result["score"] = max(result["score"], sev)

    
    clones = len(RE_CLONE.findall(text))
    if clones > 15:
        result["evidence"].append(evidence(
            "dynamic_forks",
            f"{clones} fork/clone detectados (posible fork bomb)",
            90,
        ))
        result["score"] = max(result["score"], 90)


    sensitive = [
        ("/etc/passwd",   "Lectura de /etc/passwd",                        80),
        ("/etc/shadow",   "Lectura de /etc/shadow (hashes de contraseñas)", 95),
        ("/root/",        "Acceso al home de root",                         75),
        ("/.ssh/",        "Acceso a claves SSH",                             85),
        ("/.bashrc",      "Lectura/escritura de .bashrc (persistencia)",    60),
        ("/cron.d/",      "Modificación de cron",                           80),
        ("/var/log/",     "Acceso a logs del sistema",                      50),
        ("/proc/self/",   "Introspección del proceso",                      45),
    ]
    files_seen = set()
    for m in RE_OPEN_FILE.finditer(text):
        path = m.group(1)
        for needle, detail, sev in sensitive:
            if needle in path and path not in files_seen:
                files_seen.add(path)
                result["evidence"].append(evidence(
                    "dynamic_file_access", f"{detail}: {path}", sev,
                ))
                result["score"] = max(result["score"], sev)

    
    for m in RE_UNLINK.finditer(text):
        target = m.group(1).strip()
        if target and target not in files_seen:
            files_seen.add(target)
            result["evidence"].append(evidence(
                "dynamic_file_delete", f"Eliminación de archivo: {target}", 55,
            ))
            result["score"] = max(result["score"], 55)

    for m in RE_CHMOD.finditer(text):
        target = m.group(1)
        mode   = m.group(2)
        if mode and "0777" in mode:
            result["evidence"].append(evidence(
                "dynamic_chmod",
                f"chmod 0777 a {target} (relajación de permisos)",
                60,
            ))
            result["score"] = max(result["score"], 60)


def _parse_stdout(text: str, result: dict) -> None:
    if not text.strip():
        return
    lines = [l.strip() for l in text.splitlines() if l.strip()][:3]
    for line in lines:
        result["evidence"].append(evidence(
            "dynamic_stdout",
            f"Salida del script: {line[:120]}",
            25,
        ))


def _score_behavior(rc: int, timed_out: bool, result: dict) -> None:
    if timed_out:
        result["threat"] = result["threat"] or "Script con ejecución prolongada (posible backdoor/loop)"
    elif rc != 0 and not timed_out and result["score"] < 30:
        result["evidence"].append(evidence(
            "dynamic_exit",
            f"El script terminó con código {rc}",
            15,
        ))

    if result["score"] >= 81:
        result["threat"] = "Script con comportamiento malicioso confirmado"
    elif result["score"] >= 61:
        result["threat"] = "Script con comportamiento de alto riesgo"
    elif result["score"] >= 31:
        result["threat"] = "Script con comportamiento sospechoso"


def _run_fallback(filepath: str, interp) -> dict:
    result = empty_result("dynamic")
    try:
        proc = subprocess.run(
            interp + [filepath],
            capture_output=True, text=True, timeout=EXEC_TIMEOUT,
        )
        if proc.stdout:
            result["evidence"].append(evidence(
                "dynamic_stdout",
                f"Salida: {proc.stdout.strip()[:200]}",
                20,
            ))
        if proc.returncode != 0:
            result["evidence"].append(evidence(
                "dynamic_exit",
                f"Proceso terminó con código {proc.returncode}",
                15,
            ))
    except subprocess.TimeoutExpired:
        result["evidence"].append(evidence(
            "dynamic_timeout",
            f"Ejecución superó {EXEC_TIMEOUT}s",
            65,
        ))
        result["score"] = max(result["score"], 65)
    except Exception as e:
        result["evidence"].append(evidence(
            "dynamic_error", f"Error ejecutando: {e}", 25,
        ))
    return result
