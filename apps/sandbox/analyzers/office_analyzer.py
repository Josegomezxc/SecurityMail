
import re
from .base import empty_result, evidence

VBA_AUTO_EXEC = {
    "AutoOpen":           ("Auto-ejecuta al abrir el documento", 80),
    "Auto_Open":          ("Auto-ejecuta al abrir el documento", 80),
    "AutoClose":          ("Auto-ejecuta al cerrar el documento", 70),
    "Auto_Close":         ("Auto-ejecuta al cerrar el documento", 70),
    "AutoExec":           ("Auto-ejecución detectada", 85),
    "AutoNew":            ("Auto-ejecuta al crear documento nuevo", 75),
    "Document_Open":      ("Auto-ejecuta al abrir el documento", 80),
    "Document_Close":     ("Auto-ejecuta al cerrar el documento", 70),
    "Workbook_Open":      ("Auto-ejecuta al abrir el libro de Excel", 80),
    "Workbook_Activate":  ("Auto-ejecuta al activar el libro", 75),
    "Worksheet_Activate": ("Auto-ejecuta al activar la hoja", 70),
}

VBA_DANGEROUS = {
    "Shell":              ("Ejecuta comandos del sistema",                 80),
    "WScript.Shell":      ("Acceso a Windows Script Host (shell)",          80),
    "CreateObject":       ("Instanciación de objetos COM",                 50),
    "GetObject":          ("Acceso a objetos COM externos",                50),
    "URLDownloadToFile":  ("Descarga de archivos desde internet",          85),
    "WinHttp":            ("Solicitudes HTTP nativas",                     65),
    "MSXML2.XMLHTTP":     ("HTTP request via XMLHTTP",                     65),
    "ADODB.Stream":       ("Escritura de archivos binarios en disco",      75),
    "Powershell":         ("Invocación de PowerShell desde la macro",      90),
    "powershell":         ("Invocación de PowerShell desde la macro",      90),
    "cmd.exe":            ("Invocación de cmd.exe",                         85),
    "regsvr32":           ("Ejecución vía regsvr32 (LOLBAS)",               85),
    "mshta":              ("Ejecución vía mshta (LOLBAS)",                  85),
    "rundll32":           ("Ejecución vía rundll32 (LOLBAS)",               80),
    "bitsadmin":          ("Descarga vía bitsadmin (LOLBAS)",               80),
    "certutil":           ("Decode/download vía certutil (LOLBAS)",         80),
    "Kernel32":           ("Llamada directa a Kernel32 (Win32 API)",        65),
    "VirtualAlloc":       ("Reserva de memoria — posible shellcode",       80),
    "RtlMoveMemory":      ("Inyección/movimiento de memoria",              80),
    "CallByName":         ("Invocación dinámica (evasión estática)",       55),
    "Environ(":           ("Lectura de variables de entorno",              35),
}


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("office")

    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    except Exception as e:
        result["evidence"].append(evidence(
            "oletools_missing", f"oletools no disponible: {e}", 30,
        ))
        return _fallback_string_scan(filepath, result)

    try:
        vba = VBA_Parser(filepath)
    except Exception as e:
        result["evidence"].append(evidence(
            "office_parse_error", f"No se pudo abrir como Office: {e}", 20,
        ))
        return _fallback_string_scan(filepath, result)

    file_type = vba.type or "desconocido"
    type_name = {
        TYPE_OLE: "OLE (Office 97-2003)",
        TYPE_OpenXML: "OOXML (Office 2007+)",
        TYPE_Word2003_XML: "Word 2003 XML",
        TYPE_MHTML: "MHTML",
    }.get(file_type, str(file_type))

    result["evidence"].append(evidence(
        "format", f"Documento Office ({type_name})", 10,
    ))

    if not vba.detect_vba_macros():
        _scan_ole_objects(vba, result)
        try:
            vba.close()
        except Exception:
            pass
        return result

    result["evidence"].append(evidence("vba_macros", "Macros VBA detectadas", 60))
    result["score"] = max(result["score"], 60)
    result["threat"] = "Documento Office con macros"

    all_macro_code = ""
    try:
        for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if not vba_code:
                continue
            all_macro_code += "\n" + vba_code

            for kw, (detail, sev) in VBA_AUTO_EXEC.items():
                if kw in vba_code:
                    result["evidence"].append(evidence(
                        "vba_autoexec", f"{kw}() — {detail}", sev,
                    ))
                    result["score"] = max(result["score"], sev)
                    result["threat"] = "Macro VBA con auto-ejecución"

            for kw, (detail, sev) in VBA_DANGEROUS.items():
                if kw in vba_code:
                    result["evidence"].append(evidence(
                        "vba_dangerous_call", f"`{kw}` — {detail}", sev,
                    ))
                    result["score"] = max(result["score"], sev)

    except Exception as e:
        result["evidence"].append(evidence(
            "vba_extract_error", f"Error al extraer macros: {e}", 50,
        ))

    try:
        results = vba.analyze_macros()
        for kw_type, keyword, description in results[:25]:
            sev = {"AutoExec": 80, "Suspicious": 70, "IOC": 50, "Hex String": 55,
                   "Base64 String": 60, "Dridex String": 90, "VBA string": 30}.get(kw_type, 40)
            result["evidence"].append(evidence(
                f"olevba_{kw_type.lower().replace(' ', '_')}",
                f"{keyword} — {description}",
                sev,
            ))
            result["score"] = max(result["score"], sev)
    except Exception:
        pass

    if all_macro_code:
        urls = re.findall(r'https?://[^\s"\'<>)]+', all_macro_code)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_macro_code)
        for u in list(dict.fromkeys(urls))[:20]:
            result["iocs"]["urls"].append(u)
            result["evidence"].append(evidence(
                "ioc_url", f"URL hardcoded en macro: {u}", 65,
            ))
            result["score"] = max(result["score"], 65)
        for ip in list(dict.fromkeys(ips))[:20]:
            result["iocs"]["ips"].append(ip)

    _scan_ole_objects(vba, result)

    try:
        vba.close()
    except Exception:
        pass

    return result


def _scan_ole_objects(vba, result: dict) -> None:
    try:
        ole_objs = vba.get_olestreams()
        if ole_objs and len(ole_objs) > 0:
            result["evidence"].append(evidence(
                "ole_objects",
                f"{len(ole_objs)} stream(s) OLE encontrados",
                40,
            ))
    except Exception:
        pass


def _fallback_string_scan(filepath: str, result: dict) -> dict:
    try:
        with open(filepath, "rb") as f:
            data = f.read(5 * 1024 * 1024)
    except Exception:
        return result

    text = data.decode("latin-1", errors="ignore")
    for kw, (detail, sev) in VBA_DANGEROUS.items():
        if kw in text:
            result["evidence"].append(evidence(
                "string_match", f"`{kw}` encontrado en bytes — {detail}", sev,
            ))
            result["score"] = max(result["score"], sev)
    return result
