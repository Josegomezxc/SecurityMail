"""
Analizador de scripts (.sh, .ps1, .vbs, .js, .jse, .wsf, .py, .bat, .cmd,
.hta, .lnk, .reg).

NUNCA ejecuta el script. Sólo análisis estático: lee el contenido, busca
patrones maliciosos y técnicas de ofuscación.
"""
import os
import re
from .base import empty_result, evidence

# Patrones por familia de script.
# Formato: (regex, descripción legible, severidad)

POWERSHELL_PATTERNS = [
    (r'IEX\s*\(',                        "PowerShell IEX (Invoke-Expression) — ejecución dinámica", 85),
    (r'Invoke-Expression',               "Invoke-Expression — ejecución dinámica de string", 85),
    (r'Invoke-WebRequest',               "Descarga vía Invoke-WebRequest", 70),
    (r'Net\.WebClient',                  "Descarga vía System.Net.WebClient", 75),
    (r'DownloadString',                  "DownloadString — patrón clásico de loader", 85),
    (r'DownloadFile',                    "DownloadFile — descarga remota", 80),
    (r'-(EncodedCommand|enc|e)\s',       "PowerShell con -EncodedCommand (base64) — ofuscación", 90),
    (r'-(NoProfile|NoP)\s',              "Flag -NoProfile (evasión de perfil)", 50),
    (r'-(WindowStyle|w)\s+Hidden',       "Ventana oculta (-WindowStyle Hidden)", 60),
    (r'-(ExecutionPolicy|ep)\s+Bypass',  "Bypass de ExecutionPolicy", 75),
    (r'FromBase64String',                "Decodificación base64 — ofuscación", 70),
    (r'Add-MpPreference.*Exclusion',     "Excluye carpeta de Defender", 90),
    (r'Set-MpPreference.*Disable',       "Deshabilita Defender", 95),
    (r'Reflection\.Assembly',            "Carga de assembly reflectivo", 80),
    (r'Start-Process',                   "Inicia un proceso", 50),
    (r'Out-File.*\.exe',                 "Escribe un .exe en disco", 80),
    (r'New-Object\s+Net\.Sockets',       "Conexión TCP raw (reverse shell)", 90),
]

VBS_PATTERNS = [
    (r'CreateObject\(\s*"WScript\.Shell"', "WScript.Shell — ejecuta comandos del sistema", 80),
    (r'CreateObject\(\s*"Shell\.Application"', "Shell.Application — abre ventanas/programas", 70),
    (r'CreateObject\(\s*"Scripting\.FileSystemObject"', "FileSystemObject — manipulación de archivos", 50),
    (r'CreateObject\(\s*"MSXML2\.XMLHTTP"', "XMLHTTP — descargas HTTP", 70),
    (r'CreateObject\(\s*"ADODB\.Stream"', "ADODB.Stream — escritura binaria", 80),
    (r'\.Run\s*\(',                       "Ejecución vía .Run()", 70),
    (r'\.Exec\s*\(',                      "Ejecución vía .Exec()", 75),
    (r'powershell',                       "Llamada a PowerShell desde VBS", 85),
    (r'cmd\.exe',                         "Llamada a cmd.exe desde VBS", 80),
]

JS_PATTERNS = [
    (r'eval\s*\(',                        "Llamada eval() — ejecución dinámica", 75),
    (r'ActiveXObject',                    "ActiveXObject (legacy IE/WSH) — peligroso", 80),
    (r'WScript\.Shell',                   "Acceso a WScript.Shell desde JS", 85),
    (r'WScript\.CreateObject',            "Creación de objetos COM desde JS", 80),
    (r'String\.fromCharCode\([\d,\s]{40,}\)', "Cadena larga vía fromCharCode (ofuscación)", 65),
    (r'unescape\(',                       "unescape — patrón clásico de exploit", 65),
    (r'document\.write\s*\(',             "document.write con contenido dinámico", 40),
]

BAT_PATTERNS = [
    (r'powershell',                       "Llamada a PowerShell desde batch", 80),
    (r'curl ',                            "Descarga con curl",                   60),
    (r'certutil.*-decode',                "Decodificación con certutil (LOLBAS)",70),
    (r'certutil.*-urlcache',              "Descarga con certutil (LOLBAS)",      80),
    (r'bitsadmin',                        "Descarga con bitsadmin (LOLBAS)",     75),
    (r'mshta',                            "Llamada a mshta (LOLBAS)",            80),
    (r'rundll32',                         "Llamada a rundll32 (LOLBAS)",         70),
    (r'reg add ',                         "Modifica el registro de Windows",     60),
    (r'schtasks /create',                 "Crea tarea programada (persistencia)",80),
    (r'attrib \+h',                       "Oculta archivos (atributo +h)",       50),
    (r'del /[fq]',                        "Borrado forzoso de archivos",         50),
]

SH_PATTERNS = [
    (r'curl\s+(-[a-zA-Z]+\s+)*(http|https)', "Descarga HTTP con curl",            55),
    (r'wget\s+(-[a-zA-Z]+\s+)*(http|https)', "Descarga HTTP con wget",            55),
    (r'\bnc\s', "Netcat — posible reverse shell o backdoor", 85),
    (r'\bncat\b', "Ncat — posible reverse shell o backdoor", 85),
    (r'/etc/passwd',                       "Acceso a /etc/passwd",                70),
    (r'/etc/shadow',                       "Acceso a /etc/shadow",                90),
    (r'\brm\s+-rf\s+(/|\$|~)',             "Borrado masivo desde raíz/home",      85),
    (r'chmod\s+777',                       "Permisos 777 (relajación de seguridad)", 50),
    (r'\bbase64\s+-d\b',                   "Decodificación base64 (ofuscación)",  60),
    (r'(>&|0>&)\s*/dev/tcp/',              "Reverse shell via /dev/tcp",          95),
    (r'crontab\s+',                        "Modifica crontab (persistencia)",     65),
    (r'\bssh-keygen\b',                    "Genera claves SSH (posible persistencia)", 50),
    (r'\bsudo\s',                          "Uso de sudo",                          30),
]

# LNK = Windows Shortcut. No tiene texto, su análisis es a nivel binario.
LNK_TARGETS_DANGEROUS = [
    (b"powershell",     "LNK que apunta a PowerShell", 85),
    (b"cmd.exe",        "LNK que apunta a cmd.exe",    75),
    (b"mshta",          "LNK que apunta a mshta",      80),
    (b"rundll32",       "LNK que apunta a rundll32",   75),
    (b"-EncodedCommand","LNK con PowerShell base64",   95),
    (b"http://",        "LNK con URL embebida",        70),
    (b"https://",       "LNK con URL embebida",        70),
]


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("script")
    ext = os.path.splitext(filepath)[1].lower()

    # LNK = binario, tratar aparte
    if ext == ".lnk":
        return _analyze_lnk(filepath, result)

    # HTA = HTML application — puede contener cualquier script
    if ext == ".hta":
        result["evidence"].append(evidence(
            "format", "HTML Application (.hta) — ejecuta como app local con permisos completos", 80,
        ))
        result["score"] = max(result["score"], 80)
        result["threat"] = "HTML Application — ejecuta scripts con permisos elevados"

    # REG = clave de registro
    if ext == ".reg":
        result["evidence"].append(evidence(
            "format", "Archivo .reg — modifica el registro de Windows al doble click", 65,
        ))
        result["score"] = max(result["score"], 65)
        result["threat"] = "Modificación del registro al ejecutarse"

    # JAR = ejecutable Java
    if ext == ".jar":
        result["evidence"].append(evidence(
            "format", "Archivo .jar — ejecutable Java", 70,
        ))
        result["score"] = max(result["score"], 70)
        result["threat"] = "Ejecutable Java"

    # Lee contenido (asumimos texto)
    try:
        with open(filepath, "rb") as f:
            raw = f.read(2 * 1024 * 1024)
    except Exception as e:
        result["evidence"].append(evidence("read_error", str(e), 30))
        return result

    # Heurística de codificación
    text = raw.decode("utf-8", errors="ignore")
    if not text.strip():
        text = raw.decode("utf-16", errors="ignore")

    # Selecciona los patrones según extensión / contenido
    patterns = []
    if ext in (".ps1", ".psm1"):
        patterns = POWERSHELL_PATTERNS
    elif ext in (".vbs", ".vbe", ".wsf"):
        patterns = VBS_PATTERNS
    elif ext in (".js", ".jse"):
        patterns = JS_PATTERNS
    elif ext in (".bat", ".cmd"):
        patterns = BAT_PATTERNS
    elif ext in (".sh",):
        patterns = SH_PATTERNS
    elif ext in (".hta",):
        patterns = JS_PATTERNS + VBS_PATTERNS
    else:
        # Mezcla: prueba todo (pueden ser scripts sin extensión clara)
        patterns = POWERSHELL_PATTERNS + VBS_PATTERNS + JS_PATTERNS + BAT_PATTERNS + SH_PATTERNS

    # Aplica los patrones
    for pattern, detail, sev in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                result["evidence"].append(evidence("script_pattern", detail, sev))
                result["score"] = max(result["score"], sev)
        except re.error:
            continue

    # Heurística general: longitud / ofuscación
    long_lines = [l for l in text.splitlines() if len(l) > 800]
    if long_lines:
        result["evidence"].append(evidence(
            "obfuscation",
            f"{len(long_lines)} línea(s) > 800 caracteres — sugiere ofuscación",
            55,
        ))
        result["score"] = max(result["score"], 55)

    # Cantidad de variables tipo $a$b$c (ofuscación PowerShell típica)
    var_obf = len(re.findall(r'\$[a-zA-Z_]\w?\b', text))
    if var_obf > 200:
        result["evidence"].append(evidence(
            "obfuscation",
            f"Cantidad masiva de variables cortas ({var_obf}) — ofuscación",
            60,
        ))
        result["score"] = max(result["score"], 60)

    # Extracción de IOCs (URLs / IPs)
    # Nota: list() es necesario — dict.fromkeys() devuelve un dict que no
    # soporta slicing, dispara KeyError(slice(None, 20, None)).
    for u in list(dict.fromkeys(re.findall(r'https?://[^\s"\'<>)]+', text)))[:20]:
        result["iocs"]["urls"].append(u)
    for ip in list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:20]:
        result["iocs"]["ips"].append(ip)

    if not result["threat"]:
        if result["score"] >= 80:
            result["threat"] = "Script malicioso — múltiples indicadores"
        elif result["score"] >= 60:
            result["threat"] = "Script de alto riesgo"
        elif result["score"] >= 30:
            result["threat"] = "Script con elementos sospechosos"

    return result


def _analyze_lnk(filepath: str, result: dict) -> dict:
    """Análisis de un Windows Shortcut (.lnk) — formato binario."""
    result["evidence"].append(evidence(
        "format", "Windows Shortcut (.lnk) — puede ejecutar comandos arbitrarios al doble click", 70,
    ))
    result["score"] = 70
    result["threat"] = "Acceso directo (.lnk) — vector clásico de malware"

    try:
        with open(filepath, "rb") as f:
            data = f.read(64 * 1024)
    except Exception as e:
        result["evidence"].append(evidence("read_error", str(e), 30))
        return result

    for needle, detail, sev in LNK_TARGETS_DANGEROUS:
        if needle.lower() in data.lower():
            result["evidence"].append(evidence("lnk_target", detail, sev))
            result["score"] = max(result["score"], sev)

    return result
