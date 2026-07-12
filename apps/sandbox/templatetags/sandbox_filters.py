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
    "archive_depth":         "Anidamiento",
    "zip_bomb":              "Zip bomb",
    "password_protected":    "Cifrado",
    "extract_error":         "Error extracción",
    "empty_archive":         "Archivo vacío",
    "archive_contents":      "Contenido",
    "dangerous_inside":      "Ejecutable embebido",
    "recurse_error":         "Error análisis interno",
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
    "yara_unavailable":      "YARA no disponible",
    "yara_no_rules":         "Sin reglas YARA",
    "yara_error":            "Error YARA",
    "format":                "Formato",
    "pdf_pattern":           "Patrón PDF",
    "pdf_structure":         "Estructura PDF",
    "ioc_url":               "URL embebida",
    "script_pattern":        "Patrón script",
    "lnk_target":            "Acceso directo LNK",
    "oletools_missing":      "oletools no disponible",
    "office_parse_error":    "Error parseo Office",
    "vba_macros":            "Macros VBA",
    "vba_autoexec":          "Auto-ejecución VBA",
    "vba_dangerous_call":    "Llamada peligrosa VBA",
    "vba_extract_error":     "Error extracción VBA",
    "ole_objects":           "Objeto OLE",
    "string_match":          "Cadena sospechosa",
    "binary":                "Binario",
    "pe_parse_error":        "Error parseo PE",
    "suspicious_import":     "API sospechosa",
    "anomalous_sections":    "Sección anómala",
    "high_entropy":          "Alta entropía",
    "unsigned":              "Sin firma digital",
    "suspicious_string":     "Cadena sospechosa",
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
    "obfuscation":           "Ofuscación",
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


_YARA_RULE_TRANSLATIONS = [
    (re.compile(r'_+'),                                      ' '),
    (re.compile(r'^suspicious launch action\b', re.I),       'Acción de lanzamiento sospechosa'),
    (re.compile(r'^invalid trailer structure\b', re.I),      'Estructura de tráiler inválida'),
    (re.compile(r'^invalid xobject js\b', re.I),             'XObject JS inválido'),
    (re.compile(r'^invalid xref numbers\b', re.I),           'Números de referencia inválidos'),
    (re.compile(r'^multiple versions\b', re.I),              'Versiones múltiples'),
    (re.compile(r'^multiple filtering\b', re.I),             'Filtrado múltiple'),
    (re.compile(r'^possible exploit\b', re.I),               'Posible exploit'),
    (re.compile(r'^pdf embedded js action\b', re.I),         'PDF con JavaScript en acción al abrir'),
    (re.compile(r'^pdf embedded exe\b', re.I),               'PDF con ejecutable embebido'),
    (re.compile(r'^office macro loader\b', re.I),            'Cargador de macros de Office'),
    (re.compile(r'^office dde exploit\b', re.I),             'Exploit DDE de Office'),
    (re.compile(r'^office dde field\b', re.I),               'Campo DDE de Office'),
    (re.compile(r'^office ddeauto field\b', re.I),           'Campo DDEAUTO de Office'),
    (re.compile(r'^office ole dde\b', re.I),                 'OLE DDE de Office'),
    (re.compile(r'^office ole ddeauto\b', re.I),             'OLE DDEAUTO de Office'),
    (re.compile(r'^suspicious obfuscation\b', re.I),         'Ofuscación sospechosa'),
    (re.compile(r'^suspicious embed\b', re.I),               'Contenido embebido sospechoso'),
    (re.compile(r'^suspicious js\b', re.I),                  'JavaScript sospechoso'),
    (re.compile(r'^suspicious author\b', re.I),              'Autor sospechoso'),
    (re.compile(r'^suspicious creation\b', re.I),            'Creación sospechosa'),
    (re.compile(r'^suspicious creator\b', re.I),             'Creador sospechoso'),
    (re.compile(r'^suspicious version\b', re.I),             'Versión sospechosa'),
    (re.compile(r'^suspicious title\b', re.I),               'Título sospechoso'),
    (re.compile(r'^suspicious producer\b', re.I),            'Productor sospechoso'),
    (re.compile(r'^contains vba macro code\b', re.I),        'Contiene código de macro VBA'),
    (re.compile(r'^contains vbe file\b', re.I),              'Contiene archivo VBE'),
    (re.compile(r'^contains dde protocol\b', re.I),          'Contiene protocolo DDE'),
    (re.compile(r'^contains userform object\b', re.I),       'Contiene objeto UserForm'),
    (re.compile(r'^contains hidden pe file', re.I),          'Contiene PE oculto en secuencia numérica'),
    (re.compile(r'^maldoc suspicious ole target\b', re.I),   'OLE sospechoso en documento'),
    (re.compile(r'^suspicious base64 pe header\b', re.I),    'Cabecera PE en Base64 sospechosa'),
    (re.compile(r'^suspicious powershell loader\b', re.I),   'Cargador de PowerShell sospechoso'),
    (re.compile(r'^powershell encoded command\b', re.I),     'Comando PowerShell codificado'),
    (re.compile(r'^reverse shell bash\b', re.I),             'Reverse shell (Bash)'),
    (re.compile(r'^reverse shell netcat\b', re.I),           'Reverse shell (Netcat)'),
    (re.compile(r'^powershell susp parameter combo\b', re.I),'Combinación de parámetros PowerShell sospechosa'),
    (re.compile(r'^susp powershell caret obfuscation 2\b', re.I),'Ofuscación PowerShell con caret'),
    (re.compile(r'^susp obfuscted powershell code\b', re.I), 'Código PowerShell ofuscado'),
    (re.compile(r'^susp obfusc powershell true', re.I),      'PowerShell ofuscado'),
    (re.compile(r'^susp powershell isesteroids obfuscation\b', re.I),'Ofuscación PowerShell ISESteroids'),
    (re.compile(r'^javascript run suspicious\b', re.I),      'JavaScript sospechoso'),
    (re.compile(r'^js suspicious mshta bypass\b', re.I),     'JS con bypass de MSHTA'),
    (re.compile(r'^js suspicious obfuscation dropbox\b', re.I),'JS ofuscado (Dropbox)'),
    (re.compile(r'^hta embedded\b', re.I),                   'HTA embebido'),
    (re.compile(r'^hta with wscript shell\b', re.I),         'HTA con WScript.Shell'),
    (re.compile(r'^malware js powershell obfuscated\b', re.I),'JS/PowerShell ofuscado'),
    (re.compile(r'^ps amsi bypass\b', re.I),                 'Bypass de AMSI en PowerShell'),
    (re.compile(r'^certutil decode or download\b', re.I),    'Certutil (decode/download)'),
    (re.compile(r'^vbs obfuscated mal', re.I),               'VBS ofuscado'),
    (re.compile(r'^susp bad pdf\b', re.I),                   'PDF sospechoso'),
    (re.compile(r'^susp zip lnk phishattachment', re.I),     'ZIP/LNK en adjunto phishing'),
    (re.compile(r'^susp zip iso phishattachment', re.I),     'ZIP/ISO en adjunto phishing'),
    (re.compile(r'^susp archive phishing attachment', re.I), 'Archivo adjunto phishing'),
    (re.compile(r'^susp excel4macro autoopen\b', re.I),      'Macro Excel 4.0 auto-ejecutable'),
    (re.compile(r'^susp maldoc excelmacro\b', re.I),         'Macro Excel sospechosa'),
    (re.compile(r'^susp macro staroffice\b', re.I),          'Macro StarOffice sospechosa'),
    (re.compile(r'^susp doc windowsinstaller call', re.I),   'Llamada a Windows Installer en documento'),
    (re.compile(r'^gen excel auto open evasion\b', re.I),    'Macro Excel con evasión'),
    (re.compile(r'^gen excel xll addin suspicious\b', re.I), 'Add-in XLL de Excel sospechoso'),
    (re.compile(r'^gen excel xor obfuscation', re.I),        'Ofuscación XOR en Excel'),
    (re.compile(r'^gen macro shellexecute action\b', re.I),  'Macro con ShellExecute'),
    (re.compile(r'^mal sharpshooter excel4\b', re.I),        'Sharpshooter (Excel 4.0)'),
    (re.compile(r'^browser credential theft\b', re.I),       'Robo de credenciales de navegador'),
    (re.compile(r'^mimikatz credential dumper\b', re.I),     'Dumper de credenciales (Mimikatz)'),
    (re.compile(r'^phishing credentials form\b', re.I),      'Formulario de phishing'),
    (re.compile(r'^phishing kit indicators\b', re.I),        'Indicadores de kit phishing'),
    (re.compile(r'^ransomware indicators\b', re.I),          'Indicadores de ransomware'),
    (re.compile(r'^cobaltstrike beacon strings\b', re.I),    'CobaltStrike Beacon'),
    (re.compile(r'^asyncrat quasar rat strings\b', re.I),    'AsyncRAT / QuasarRAT'),
    (re.compile(r'^njrat indicators\b', re.I),               'Indicadores de NjRAT'),
    (re.compile(r'^discord webhook exfiltration\b', re.I),   'Exfiltración vía webhook de Discord'),
    (re.compile(r'^telegram bot exfiltration\b', re.I),      'Exfiltración vía bot de Telegram'),
    (re.compile(r'^amsi bypass patterns\b', re.I),           'Patrones de bypass de AMSI'),
    (re.compile(r'^uac bypass fodhelper\b', re.I),           'Bypass de UAC (FodHelper)'),
    (re.compile(r'^anti vm sandbox detection\b', re.I),      'Detección de VM/sandbox'),
    (re.compile(r'^process injection api combo\b', re.I),    'Combo de APIs de inyección'),
    (re.compile(r'^reflective dll loader\b', re.I),          'Cargador reflectivo de DLL'),
    (re.compile(r'^dll injector lynx\b', re.I),              'Inyector DLL (Lynx)'),
    (re.compile(r'^persistence registry run\b', re.I),       'Persistencia en Run del registro'),
    (re.compile(r'^persistence scheduled task\b', re.I),     'Persistencia en tarea programada'),
    (re.compile(r'^wmi persistence\b', re.I),                'Persistencia en WMI'),
    (re.compile(r'^defender tampering\b', re.I),             'Manipulación de Windows Defender'),
    (re.compile(r'^lolbas living off the land\b', re.I),     'LOLBAS (Living Off The Land)'),
    (re.compile(r'^cve 2022 30190 follina\b', re.I),         'CVE-2022-30190 (Follina)'),
    (re.compile(r'^cryptominer xmrig\b', re.I),              'Criptominero (XMRig)'),
    (re.compile(r'^eicar test file\b', re.I),                'Archivo de prueba EICAR'),
    (re.compile(r'^shellcode blob metadata\b', re.I),        'Shellcode blob'),
    (re.compile(r'^brooxml hunting\b', re.I),                'Detección de XML malicioso'),
    (re.compile(r'^brooxml phishing\b', re.I),               'XML de phishing'),
    (re.compile(r'^mime mso activemime base64\b', re.I),     'ActiveMime en MSO (Base64)'),
    (re.compile(r'^malrtf ole2link\b', re.I),                'OLE2Link en RTF malicioso'),
    (re.compile(r'^word 2007 xml flat opc\b', re.I),         'Word 2007 XML Flat OPC'),
    (re.compile(r'^rtf objdata urlmoniker http\b', re.I),    'URLMoniker HTTP en RTF'),
    (re.compile(r'^susp ps1 msdt execution\b', re.I),        'Ejecución de msdt en PowerShell'),
    (re.compile(r'^susp doc wordxmlrels\b', re.I),           'Word XML Relationships sospechoso'),
    (re.compile(r'^susp doc rtf externalresource\b', re.I),  'Recurso externo en RTF'),
    (re.compile(r'^expl follina cve 2022 30190', re.I),      'CVE-2022-30190 (Follina)'),
    (re.compile(r'^susp doc rtf ole2link\b', re.I),          'OLE2Link en RTF'),
    (re.compile(r'^susp msdt artefact\b', re.I),             'Artefacto de msdt'),
    (re.compile(r'^susp lnk follina\b', re.I),               'LNK relacionado con Follina'),
    (re.compile(r'^susp email suspicious onenote', re.I),    'OneNote sospechoso en email'),
    (re.compile(r'^susp onenote embedded filedatastoreobject\b', re.I),'OneNote con FileDataStoreObject embebido'),
    (re.compile(r'^malicious author\b', re.I),               'Autor malicioso'),
    (re.compile(r'^xdp embedded pdf\b', re.I),               'XDP con PDF embebido'),
    (re.compile(r'^blackhole v2\b', re.I),                   'BlackHole v2'),
    (re.compile(r'^js wrong version\b', re.I),               'Versión incorrecta de JS'),
    (re.compile(r'^jbig2 wrong version\b', re.I),            'Versión incorrecta de JBIG2'),
    (re.compile(r'^flatedecode wrong version\b', re.I),      'Versión incorrecta de FlateDecode'),
    (re.compile(r'^embed wrong version\b', re.I),            'Versión incorrecta de embed'),
    (re.compile(r'^js splitting\b', re.I),                   'JS fragmentado'),
    (re.compile(r'^header evasion\b', re.I),                 'Evasión de cabecera'),
    (re.compile(r'^ppaction\b', re.I),                       'PPAction'),
    (re.compile(r'^mal cmd script obfuscated feb19', re.I),  'Script CMD ofuscado'),
    (re.compile(r'^susp obfusc indiators xml', re.I),        'XML ofuscado en Office'),
    (re.compile(r'^susp expl msg cve 2023 23397', re.I),     'CVE-2023-23397 en mensaje'),
    (re.compile(r'^expl susp outlook cve 2023 23397', re.I), 'CVE-2023-23397 en Outlook'),
    (re.compile(r'^expl cve 2024 21413 microsoft outlook', re.I),'CVE-2024-21413 (Outlook RCE)'),
    (re.compile(r'^ext expl zth lnk exploit a\b', re.I),     'Exploit LNK'),
    (re.compile(r'^suspicious ', re.I),                      'Sospechoso: '),
    (re.compile(r'^invalid ', re.I),                         'Inválido: '),
    (re.compile(r'^malicious ', re.I),                       'Malicioso: '),
    (re.compile(r'^possible ', re.I),                        'Posible '),
    (re.compile(r'^contains ', re.I),                        'Contiene '),
    (re.compile(r'^embedded ', re.I),                        'Embebido: '),
    (re.compile(r'^hidden ', re.I),                          'Oculto: '),
    (re.compile(r'^obfuscat\w+ ', re.I),                     'Ofuscado '),
    (re.compile(r'^mal ', re.I),                             'Malware: '),
    (re.compile(r'^expl ', re.I),                            'Exploit: '),
    (re.compile(r'^susp ', re.I),                            'Sospechoso: '),
    (re.compile(r'^ext ', re.I),                             'Ext: '),
    (re.compile(r'^office ', re.I),                          'Office: '),
    (re.compile(r'^pdf ', re.I),                             'PDF: '),
    (re.compile(r'^hta ', re.I),                             'HTA: '),
    (re.compile(r'^powershell ', re.I),                      'PowerShell: '),
    (re.compile(r'^vbs(cript)? ', re.I),                     'VBScript: '),
    (re.compile(r'^java ?script ', re.I),                    'JavaScript: '),
    (re.compile(r'^php ', re.I),                             'PHP: '),
    (re.compile(r'^asp(\.net)? ', re.I),                     'ASP: '),
    (re.compile(r'^jsp ', re.I),                             'JSP: '),
    (re.compile(r'^webshell ', re.I),                        'Webshell: '),
    (re.compile(r'^reflective ', re.I),                      'Reflectivo: '),
    (re.compile(r'\bCVE (\d{4}) (\d{4,})\b'),               r'CVE-\1-\2'),
    (re.compile(r'\bCVE (\d{4}) (\d+) (\w+)\b'),            r'CVE-\1-\2 (\3)'),
]


_YARA_EVI_RE = re.compile(r"^YAR[EA]? `(.+?)`: (.+)$", re.DOTALL)


@register.filter
def format_evidence_detail(detail, ev_type):
    detail = _UNICODE_CONTROL.sub("", str(detail))
    if str(ev_type).startswith("yara_"):
        m = _YARA_EVI_RE.match(detail)
        if m:
            rule_name = m.group(1)
            desc = m.group(2)
            detail = f"{translate_yara_rule(rule_name)}: {desc}"
        else:
            detail = translate_yara_rule(detail)
    return detail


@register.filter
def has_evidence_type(items, type_name):
    return any(ev.get('type') == type_name for ev in items)


@register.filter
def translate_yara_rule(value):
    if not value:
        return ""
    s = str(value).strip()
    for pattern, replacement in _YARA_RULE_TRANSLATIONS:
        s = pattern.sub(replacement, s)
    s = re.sub(r'\s+', ' ', s).strip()
    if s:
        s = s[0].upper() + s[1:]
    return s
