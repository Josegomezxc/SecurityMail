
import os
from .base import empty_result, evidence

SUSPICIOUS_PE_IMPORTS = {
    "VirtualAllocEx":      ("Reserva memoria en otro proceso (inyección)", 70),
    "WriteProcessMemory":  ("Escribe en memoria de otro proceso (inyección)", 75),
    "CreateRemoteThread":  ("Crea hilos en otro proceso (inyección clásica)", 80),
    "NtQueueApcThread":    ("APC injection — técnica de evasión", 75),
    "SetWindowsHookEx":    ("Hook global — keylogger potencial", 65),
    "GetAsyncKeyState":    ("Lectura de teclas — keylogger potencial", 60),
    "InternetOpenUrl":     ("Descarga de internet sin restricciones", 55),
    "URLDownloadToFile":   ("Descargador (downloader)", 70),
    "WinExec":             ("Ejecución de comandos del sistema", 60),
    "ShellExecute":        ("Ejecución de comandos del sistema", 55),
    "CreateProcess":       ("Lanza nuevos procesos", 40),
    "RegSetValue":         ("Modifica el registro de Windows", 50),
    "RegCreateKey":        ("Crea claves de registro (persistencia)", 55),
    "CryptEncrypt":        ("Cifrado nativo — posible ransomware", 65),
    "BitBlt":              ("Captura de pantalla (spyware)", 60),
    "IsDebuggerPresent":   ("Comprueba si hay debugger (anti-análisis)", 50),
    "CheckRemoteDebuggerPresent": ("Anti-debug avanzado", 60),
    "VirtualProtect":      ("Cambio de permisos de memoria (shellcode)", 55),
    "LoadLibrary":         ("Carga DLL en runtime", 30),
    "GetProcAddress":      ("Resolución dinámica de API (evasión estática)", 35),
}

KNOWN_PACKERS = {
    "UPX":          ("Empaquetado con UPX", 45),
    "MPRESS":       ("Empaquetado con MPRESS", 50),
    "ASPack":       ("Empaquetado con ASPack", 55),
    "PECompact":    ("Empaquetado con PECompact", 55),
    "FSG":          ("Empaquetado con FSG", 60),
    "Themida":      ("Protegido con Themida (anti-análisis)", 70),
    "VMProtect":    ("Protegido con VMProtect (anti-análisis)", 70),
    "Enigma":       ("Protegido con Enigma", 65),
}


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("executable")

    try:
        with open(filepath, "rb") as f:
            head = f.read(16)
    except Exception as e:
        result["evidence"].append(evidence("read_error", str(e), 30))
        return result

    if head.startswith(b"MZ"):
        return _analyze_pe(filepath, result)
    if head.startswith(b"\x7fELF"):
        return _analyze_elf(filepath, head, result)
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        result["score"] = 75
        result["threat"] = "Ejecutable Mach-O (macOS)"
        result["evidence"].append(evidence("binary", "Binario Mach-O detectado", 75))
        return result

    return result


def _analyze_pe(filepath: str, result: dict) -> dict:
    result["category"] = "executable"
    result["score"] = 75
    result["threat"] = "Ejecutable Windows (PE)"
    result["evidence"].append(evidence(
        "binary", "Binario PE de Windows detectado (.exe/.dll/.scr)", 75,
    ))

    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])
    except Exception as e:
        result["evidence"].append(evidence(
            "pe_parse_error", f"No se pudo parsear el PE: {e}", 60,
        ))
        return result


    suspicious_found = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode("ascii", errors="ignore")
                if name in SUSPICIOUS_PE_IMPORTS:
                    detail, sev = SUSPICIOUS_PE_IMPORTS[name]
                    suspicious_found.append((name, detail, sev))

    for name, detail, sev in suspicious_found[:15]:       
        result["evidence"].append(evidence(
            "suspicious_import", f"{name}: {detail}", sev,
        ))
        result["score"] = max(result["score"], sev)

    if len(suspicious_found) >= 5:
        result["threat"] = "Ejecutable Windows con APIs de inyección/evasión"
        result["score"] = max(result["score"], 88)

    section_names = []
    for section in pe.sections:
        try:
            sname = section.Name.decode("ascii", errors="ignore").rstrip("\x00")
            section_names.append(sname)
        except Exception:
            continue

    for packer, (detail, sev) in KNOWN_PACKERS.items():
        if any(packer.upper() in s.upper() for s in section_names):
            result["evidence"].append(evidence("packer", detail, sev))
            result["score"] = max(result["score"], sev)

    weird_sections = [
        s for s in section_names
        if s and s not in (".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc",
                           ".idata", ".edata", ".pdata", ".tls", ".CRT", ".debug")
    ]
    if weird_sections:
        result["evidence"].append(evidence(
            "anomalous_sections",
            f"Secciones con nombres no estándar: {', '.join(weird_sections[:8])}",
            55,
        ))
        result["score"] = max(result["score"], 55)

    high_entropy_sections = []
    for section in pe.sections:
        try:
            ent = section.get_entropy()
            if ent > 7.5:
                sname = section.Name.decode("ascii", errors="ignore").rstrip("\x00")
                high_entropy_sections.append(f"{sname}({ent:.2f})")
        except Exception:
            continue
    if high_entropy_sections:
        result["evidence"].append(evidence(
            "high_entropy",
            f"Secciones con entropía >7.5 (probable empaquetado): {', '.join(high_entropy_sections)}",
            60,
        ))
        result["score"] = max(result["score"], 60)

    try:
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].Size == 0:
            result["evidence"].append(evidence(
                "unsigned",
                "Ejecutable sin firma digital",
                40,
            ))
    except Exception:
        pass

    return result


def _analyze_elf(filepath: str, head: bytes, result: dict) -> dict:
    result["category"] = "executable"
    result["score"] = 70
    result["threat"] = "Ejecutable Linux (ELF)"
    result["evidence"].append(evidence(
        "binary", "Binario ELF de Linux detectado", 70,
    ))

    try:
        with open(filepath, "rb") as f:
            data = f.read(2 * 1024 * 1024)            
    except Exception:
        return result

    suspicious_strings = [
        (b"/etc/passwd",     "Acceso a /etc/passwd",                       70),
        (b"/etc/shadow",     "Acceso a hashes de contraseñas",              90),
        (b"/bin/sh",         "Llamada a shell del sistema",                 50),
        (b"socket",          "Uso de sockets (red)",                        40),
        (b"connect",         "Conexión de red embebida",                    45),
        (b"reverse_shell",   "Cadena 'reverse_shell' literal",              90),
        (b"crypt",           "Funciones criptográficas (posible ransom)",   45),
    ]
    for needle, detail, sev in suspicious_strings:
        if needle in data:
            result["evidence"].append(evidence(
                "suspicious_string",
                f"{detail} (literal `{needle.decode(errors='ignore')}`)",
                sev,
            ))
            result["score"] = max(result["score"], sev)

    return result
