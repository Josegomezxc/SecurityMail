import re

from django import template

register = template.Library()

_UNICODE_CONTROL = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f'
    '\u202a\u202b\u202c\u202d\u202e'
    '\u2060\u2061\u2062\u2063\u2064'
    '\u2066\u2067\u2068\u2069'
    '\ufffe\uffff]'
)

_EVIDENCE_TYPE_LABELS = {
    # ── Archive/compressed ──
    "archive_depth":         "Anidamiento",
    "zip_bomb":              "Zip bomb",
    "password_protected":    "Cifrado",
    "extract_error":         "Error extracción",
    "empty_archive":         "Archivo vacío",
    "archive_contents":      "Contenido",
    "dangerous_inside":      "Ejecutable embebido",
    "recurse_error":         "Error análisis interno",
    # ── URL ──
    "url_parse_error":       "URL inválida",
    "url_credentials_in_url":"Credenciales en URL",
    "url_ip_host":           "URL con IP",
    "url_shortener":         "Acortador",
    "url_suspicious_tld":    "TLD sospechoso",
    "url_brand_impersonation":"Suplantación de marca",
    "url_idn_homograph":     "Homógrafo IDN",
    "url_excessive_length":  "URL extensa",
    "url_many_subdomains":   "Múltiples subdominios",
    "url_underscore_host":   "Guion bajo en host",
    # ── YARA ──
    "yara_unavailable":      "YARA no disponible",
    "yara_no_rules":         "Sin reglas YARA",
    "yara_error":            "Error YARA",
    # yara_* → "Regla YARA" (catch-all below)
    # ── PDF ──
    "format":                "Formato",
    "pdf_pattern":           "Patrón PDF",
    "pdf_structure":         "Estructura PDF",
    "ioc_url":               "URL embebida",
    # ── Script / LNK ──
    "script_pattern":        "Patrón script",
    "lnk_target":            "Acceso directo LNK",
    # ── Office ──
    "oletools_missing":      "oletools no disponible",
    "office_parse_error":    "Error parseo Office",
    "vba_macros":            "Macros VBA",
    "vba_autoexec":          "Auto-ejecución VBA",
    "vba_dangerous_call":    "Llamada peligrosa VBA",
    "vba_extract_error":     "Error extracción VBA",
    "ole_objects":           "Objeto OLE",
    "string_match":          "Cadena sospechosa",
    # olevba_* → "Análisis olevba" (catch-all below)
    # ── Executable ──
    "binary":                "Binario",
    "pe_parse_error":        "Error parseo PE",
    "suspicious_import":     "API sospechosa",
    "anomalous_sections":    "Sección anómala",
    "high_entropy":          "Alta entropía",
    "unsigned":              "Sin firma digital",
    "suspicious_string":     "Cadena sospechosa",
    # ── Dynamic analysis ──
    "dynamic_timeout":       "Timeout ejecución",
    "dynamic_error":         "Error ejecución",
    "dynamic_network":       "Conexión de red",
    "dynamic_socket":        "Socket creado",
    "dynamic_process":       "Proceso hijo",
    "dynamic_forks":         "Fork bomba",
    "dynamic_file_access":   "Acceso a archivo",
    "dynamic_file_delete":   "Eliminación archivo",
    "dynamic_chmod":         "Cambio permisos",
    "dynamic_stdout":        "Salida script",
    "dynamic_exit":          "Código salida",
    # ── Obfuscation ──
    "obfuscation":           "Ofuscación",
    # ── General ──
    "read_error":            "Error de lectura",
}


@register.filter
def translate_evidence_type(value):
    if not value:
        return ""
    if value in _EVIDENCE_TYPE_LABELS:
        return _EVIDENCE_TYPE_LABELS[value]
    if value.startswith("yara_"):
        return "Regla YARA"
    if value.startswith("olevba_"):
        return "Análisis olevba"
    return value.replace("_", " ").title()


@register.filter
def sanitize_text(value):
    if not value:
        return ""
    return _UNICODE_CONTROL.sub("", str(value))
