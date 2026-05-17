# Reglas YARA — DockerShield Sandbox

Este directorio contiene todas las reglas YARA que el sandbox carga al
arrancar. El analizador en `apps/sandbox/analyzers/yara_analyzer.py`
carga **todos los archivos `*.yar`** y los compila como un único set.

## Archivos

| Archivo | Reglas | Descripción |
|---------|-------:|-------------|
| `malware.yar` | 30 | Reglas propias del proyecto (escritas a mano por el equipo) |
| `maldocs.yar` | 74 | Documentos Office, PDF, OneNote, RTF con macros o exploits |
| `loaders.yar` | 26 | PowerShell ofuscado, scripts batch, HTA, JS droppers |
| `ransomware.yar` | 37 | Familias de ransomware modernas (Conti, REvil, LockBit, etc.) |
| `credstealers.yar` | 25 | Banking trojans, info-stealers, RATs (Emotet, Trickbot, HawkEye, etc.) |
| `webshells.yar` | 668 | Webshells PHP, JSP, ASP comunes |
| `exploits_office.yar` | 10 | CVEs específicos de Office y Outlook usados en phishing |
| **Total** | **~870** | |

Compilación medida en local: ~110 ms.
Scan por archivo: ~1-3 ms.

## Fuentes de las reglas importadas

Las reglas marcadas con `Source:` en su header provienen de:

### 1. `signature-base` — Florian Roth / Nextron Systems
- **Repo**: https://github.com/Neo23x0/signature-base
- **Licencia**: CC BY-NC 4.0 (uso no comercial)
- **Mantenimiento**: activo (commits semanales)
- **Calidad**: alta — usado como base de THOR/LOKI scanner

### 2. `Yara-Rules/rules` (carpeta `maldocs/` + `webshells/`)
- **Repo**: https://github.com/Yara-Rules/rules
- **Licencia**: GPL-2.0
- **Mantenimiento**: parcial (commits esporádicos)
- **Calidad**: variable — solo se importaron reglas curadas

## Convenciones del proyecto

Cada regla debe tener:

```yara
rule Nombre_Descriptivo {
    meta:
        description = "Qué detecta y por qué"
        severity    = 70           // o "score" — entero 0-100
        category    = "loader"     // categoría libre (loader, ransom, rat, etc.)
    strings:
        $a = "..."
        $b = "..."
    condition:
        2 of them                  // exigente, no "any of them"
}
```

El analizador (`yara_analyzer.py`) lee `meta.severity` (o `meta.score`)
para puntuar el riesgo del archivo. Si no está definido usa 70 por
defecto.

## Cómo agregar nuevas reglas

### Opción 1: Reglas propias
Edita `malware.yar` directamente.

### Opción 2: Importar reglas externas
1. Verificar la licencia del origen.
2. Crear o agregar al archivo de categoría correspondiente.
3. Agregar header con `Source: <repo>/<file> — <license>`.
4. Verificar sintaxis: `python -c "import yara; yara.compile(filepath='X.yar')"`.
5. Probar con un archivo legítimo conocido (PDF normal, ZIP de cliente,
   factura escaneada) para validar que no genera falsos positivos.

## Actualización periódica recomendada

- **Cada 3 meses**: revisar si `signature-base` agregó reglas para
  amenazas nuevas (nuevos CVEs en Outlook/Office, nuevas familias
  de ransomware activas).
- **Tras cada incidente real**: agregar regla específica en
  `malware.yar` con `meta.source = "incident-YYYY-MM-DD"`.

## Comandos útiles

```bash
# Validar todas las reglas sin compilar todo el sandbox
python -c "
import yara, glob, os
files = glob.glob('apps/sandbox/analyzers/rules/*.yar')
rules = yara.compile(filepaths={os.path.basename(p): p for p in files})
print(f'Compiladas {sum(1 for _ in rules)} reglas OK')
"

# Test con EICAR
echo -n 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
# (luego se invoca el sandbox normal con el adjunto eicar.txt)
```

## Licencias

Al usar este sandbox en producción comercial, validar las licencias:

- **CC BY-NC 4.0** (signature-base): permite uso, modificación y
  distribución, pero **prohíbe uso comercial directo**. Para uso
  académico o defensivo dentro de tu organización está permitido.
- **GPL-2.0** (yara-rules-old): cualquier distribución del código que
  incluya estas reglas debe ser bajo GPL-2.0 también.
- **Reglas propias** (`malware.yar`): pertenecen al proyecto y siguen
  la licencia general del repositorio.

---

Última actualización del set: **2026-05-17**
