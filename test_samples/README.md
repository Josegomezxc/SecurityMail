# Kit de pruebas del sandbox

Prueba **todo el flujo nuevo** (analizadores especializados + YARA + body analysis + reporte enriquecido) con 11 casos de prueba que disparan cada uno de los detectores.

## Preparación (una sola vez)

Abre **PowerShell** en la raíz del proyecto (`c:\Users\adria\Desktop\email_seguro`):

```powershell
# 1. Aplicar la migración (campos nuevos de SandboxAnalysis)
python manage.py migrate

# 2. Reconstruir la imagen Docker con los nuevos analizadores
docker build -t email_seguro_sandbox -f Dockerfile.sandbox .

# 3. (si no lo tienes) instalar requests
pip install requests
```

## Correr los tests

Necesitas tener el servidor Django corriendo en una terminal:

```powershell
python manage.py runserver
```

Y un **alias creado** desde la web (`http://127.0.0.1:8000/alias/`). Copia la dirección del alias.

En **otra terminal**, ejecuta el script de tests:

```powershell
python test_samples/run_tests.py --alias TU_ALIAS_AQUI@securemail.com
```

Si tu alias es, por ejemplo, `prueba_x7k2m1@securemail.com`:

```powershell
python test_samples/run_tests.py --alias prueba_x7k2m1@securemail.com
```

## Lo que debería pasar

El script envía **11 correos** distintos al webhook `/webhook/inbound/` — cada uno con un adjunto o cuerpo que dispara un detector diferente:

| # | Test | Adjunto | Score esperado | Qué detecta |
|---|---|---|---|---|
| 01 | PowerShell loader | `update.ps1` | 80-100 | YARA loader + IEX + DownloadString + -EncodedCommand + Defender tampering |
| 02 | Reverse shell bash | `reverse.sh` | 80-100 | YARA /dev/tcp + netcat -e + /etc/shadow |
| 03 | Batch con LOLBAS | `install.bat` | 80-100 | certutil + bitsadmin + schtasks + reg add |
| 04 | PDF con JavaScript | `factura_2026.pdf` | 70-100 | /JS + /OpenAction + eval + util.printd |
| 05 | Doble extensión | `factura.pdf.exe` | 85-100 | double_extension + extension_spoof + .exe risky |
| 06 | Archivo limpio | `pedido.txt` | 0-30 | (debería salir seguro) |
| 07 | HTML phishing form | `verifica.html` | 70-100 | formulario credenciales + TLD sospechoso + brand impersonation |
| 08 | ZIP con fake .exe | `actualizacion.zip` | 80-100 | extracción + ejecutable dentro + nombre .exe |
| 09 | VBA macro stub | `documento_importante.docx` | 70-100 | AutoOpen + Shell + powershell en bytes |
| 10 | LNK fake con PS | `receipt.pdf.lnk` | 75-100 | .lnk → powershell + -EncodedCommand embebido |
| 11 | Solo cuerpo (phishing) | (ninguno) | 70-100 | link_spoofing + brand_impersonation + phishing_language + form |
| 12 | **2 adjuntos maliciosos** | `reverse.sh` + `install.bat` | 80-100 | evidencia **por archivo** + veredicto agregado |
| 13 | **3 URLs en el body** | (ninguno) | 55-100 | shortener + brand impersonation + IP-host + TLDs sospechosos |
| 14 | **3 adjuntos maliciosos** | `.ps1` + `.sh` + `.bat` | 85-100 | 3 reportes individuales · score = MAX |

## Dónde ver los resultados

Abre en el navegador:

- **`http://127.0.0.1:8000/bandeja/`** — verás los 11 correos recibidos, con badges de riesgo y filtros
- **`http://127.0.0.1:8000/sandbox/`** — lista de análisis con filtros por severidad (Malware / Alto riesgo / Sospechoso / Seguro) y búsqueda
- **Click en cualquier análisis** → ves el reporte completo con:
  - Score + ring animado
  - Identificación del archivo (MIME real, hashes, flag de extensión engañosa)
  - **Evidencia detectada** (cada indicador con pill de severidad CRÍTICO/ALTO/MEDIO/BAJO)
  - **Reglas YARA** coincidentes
  - **IOCs** (URLs/IPs/dominios) con botón "copiar"
  - **Análisis del cuerpo del correo**
  - **Analizadores ejecutados** (chips)
  - **Veredicto IA** con explicación y recomendación

## Comandos útiles

```powershell
# Correr un solo test (útil para depurar)
python test_samples/run_tests.py --alias TU_ALIAS --only 3

# Ejecutar más lento (2s entre tests) si tu máquina es lenta
python test_samples/run_tests.py --alias TU_ALIAS --sleep 2

# Apuntar a otro host (ngrok, servidor remoto, etc.)
python test_samples/run_tests.py --alias TU_ALIAS --url https://xxxxx.ngrok-free.app/webhook/inbound/
```

## Troubleshooting

**"no se pudo conectar a http://127.0.0.1:8000"**
→ Inicia `python manage.py runserver` en otra terminal.

**"Sandbox falló (rc=…)"**
→ Reconstruye la imagen: `docker build -t email_seguro_sandbox -f Dockerfile.sandbox .`
→ Verifica que Docker Desktop esté corriendo (`docker ps`).

**"Timeout interrumpió el análisis"**
→ La primera vez que corres Docker tras reiniciar es lenta. Prueba con `--sleep 3`.

**Los correos no aparecen en la bandeja**
→ El alias no coincide. Copia exactamente el address del alias desde la web.

**Un test marca `score = 0` cuando debería ser alto**
→ La imagen Docker no se reconstruyó tras los cambios:
  `docker build -t email_seguro_sandbox -f Dockerfile.sandbox .`
  y vuelve a correr.

## Seguridad

Todos los archivos generados son **inocuos**: contienen solo *strings* que los analizadores reconocen como indicadores de malware, pero ninguno ejecuta nada real. Se escriben a `%TEMP%/securemail_samples/` y se pueden borrar sin riesgo.
