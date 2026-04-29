"""
app/sandbox/auth_check.py
──────────────────────────────────────────────────────────────────────
Verificación de autenticidad criptográfica del remitente.

Lee los resultados de SPF / DKIM / DMARC que SendGrid Inbound Parse
ya calcula automáticamente y los entrega en el POST del webhook.

  • SPF:   ¿El servidor que envió el correo está autorizado por el
           dueño del dominio (vía DNS) a hablar en su nombre?
  • DKIM:  ¿La firma criptográfica del header coincide con la clave
           pública publicada en DNS por el dominio remitente?
  • DMARC: ¿La política del dominio combina SPF+DKIM y está alineada
           con el From visible?

VEREDICTO:
  • verified   → DKIM pass Y el dominio firmado coincide con el From
                 (el correo es AUTÉNTICO de ese dominio).
                 → reducimos el score un 65% (las URLs raras de Netflix,
                   Google, etc. ya no disparan falsos positivos).
  • unverified → No hay firma DKIM o no podemos verificar.
                 → no tocamos el score.
  • spoofed    → DKIM fail / DMARC fail / dominio NO alineado.
                 → forzamos el score a 75 mínimo (entra en "danger").

Phisher típico: pone "From: support@netflix.com" pero NO tiene la
clave privada de Netflix → DKIM falla → lo detectamos como spoof.
"""
import re
import json


# ── Resultados estándar de cada chequeo ──────────────────────────────
PASS    = 'pass'
FAIL    = 'fail'
SOFTFAIL = 'softfail'
NEUTRAL = 'neutral'
NONE    = 'none'

# ── Veredictos finales ───────────────────────────────────────────────
VERIFIED   = 'verified'
UNVERIFIED = 'unverified'
SPOOFED    = 'spoofed'


def check_authentication(post_data, sender_email: str) -> dict:
    """
    Lee los campos de SendGrid Inbound Parse y devuelve un veredicto.

    Args:
        post_data: request.POST (QueryDict) del webhook
        sender_email: dirección del From extraída ('Netflix <info@netflix.com>')

    Returns:
        dict con:
          spf, dkim, dmarc      → resultado de cada chequeo
          dkim_domain           → dominio que firmó (d= del DKIM)
          sender_domain         → dominio del From
          aligned               → True si dkim_domain == sender_domain
          verdict               → 'verified' | 'unverified' | 'spoofed'
          evidence              → str humano explicando el veredicto
          score_multiplier      → float para multiplicar el score final
          score_floor           → int mínimo al que forzar el score
    """
    sender_domain = _extract_domain(sender_email)

    spf  = _parse_spf(post_data.get('SPF', '') or post_data.get('spf', ''))
    dkim_raw = post_data.get('dkim', '') or post_data.get('DKIM', '')
    dkim, dkim_domain = _parse_dkim(dkim_raw)

    # DMARC no viene como campo directo — lo extraemos del Authentication-Results
    headers_str = post_data.get('headers', '') or ''
    dmarc = _parse_dmarc_from_headers(headers_str)

    # Si no había dkim_domain del campo dkim, intentamos sacarlo del header
    if not dkim_domain and headers_str:
        dkim_domain = _parse_dkim_domain_from_headers(headers_str)

    aligned = bool(
        dkim == PASS
        and dkim_domain
        and sender_domain
        and _domains_align(dkim_domain, sender_domain)
    )

    verdict, evidence, multiplier, floor = _decide(
        spf=spf, dkim=dkim, dmarc=dmarc,
        aligned=aligned,
        dkim_domain=dkim_domain,
        sender_domain=sender_domain,
    )

    return {
        'spf':              spf,
        'dkim':             dkim,
        'dmarc':            dmarc,
        'dkim_domain':      dkim_domain,
        'sender_domain':    sender_domain,
        'aligned':          aligned,
        'verdict':          verdict,
        'evidence':         evidence,
        'score_multiplier': multiplier,
        'score_floor':      floor,
    }


# ──────────────────────────────────────────────────────────────────────
#  Helpers de parsing
# ──────────────────────────────────────────────────────────────────────

def _extract_domain(email: str) -> str:
    """ 'Netflix <info@netflix.com>' → 'netflix.com'. """
    if not email:
        return ''
    if '<' in email and '>' in email:
        email = email.split('<')[-1].split('>')[0]
    if '@' not in email:
        return ''
    return email.split('@')[-1].strip().lower().rstrip('>').strip()


def _parse_spf(value: str) -> str:
    """
    SendGrid manda SPF como 'pass' / 'fail' / 'softfail' / 'neutral' / 'none'.
    A veces viene con paréntesis: 'pass (sender IP is X)'.
    """
    if not value:
        return NONE
    v = value.strip().lower().split()[0]   # toma la 1ra palabra
    if v in (PASS, FAIL, SOFTFAIL, NEUTRAL, NONE):
        return v
    return NONE


def _parse_dkim(value: str) -> tuple:
    """
    SendGrid manda DKIM como '{@netflix.com : pass}' o '{none}'.
    También puede venir como 'pass' a secas.

    Devuelve (resultado, dominio_que_firmo).
    """
    if not value:
        return NONE, ''
    v = value.strip()

    # Caso 1: '{@dominio : pass}' o '{@dominio:pass}'
    m = re.search(r'@([a-zA-Z0-9.\-]+)\s*[:=]\s*(pass|fail|none)', v, re.IGNORECASE)
    if m:
        return m.group(2).lower(), m.group(1).lower()

    # Caso 2: viene en JSON como {"@netflix.com": "pass"}
    if v.startswith('{') and ':' in v:
        try:
            data = json.loads(v)
            if isinstance(data, dict) and data:
                first_key = next(iter(data))
                domain = first_key.lstrip('@').lower()
                result = str(data[first_key]).lower()
                if result in (PASS, FAIL, NONE):
                    return result, domain
        except Exception:
            pass

    # Caso 3: 'pass' / 'fail' / 'none' a secas
    low = v.lower()
    for k in (PASS, FAIL, NONE):
        if k in low:
            return k, ''

    return NONE, ''


def _parse_dmarc_from_headers(headers: str) -> str:
    """
    Busca el resultado DMARC dentro del Authentication-Results.

    Formato típico:
      Authentication-Results: mx.sendgrid.net;
        spf=pass smtp.mailfrom=netflix.com;
        dkim=pass header.d=netflix.com;
        dmarc=pass action=none header.from=netflix.com;
    """
    if not headers:
        return NONE
    # Busca 'dmarc=valor' tolerando saltos y espacios
    m = re.search(r'\bdmarc\s*=\s*(pass|fail|bestguesspass|none)\b',
                  headers, re.IGNORECASE)
    if not m:
        return NONE
    val = m.group(1).lower()
    # 'bestguesspass' lo tratamos como pass relajado
    if val == 'bestguesspass':
        return PASS
    return val if val in (PASS, FAIL, NONE) else NONE


def _parse_dkim_domain_from_headers(headers: str) -> str:
    """
    Si el campo 'dkim' viene vacío o sin dominio, lo intentamos extraer
    del Authentication-Results buscando 'header.d=dominio.com'.
    """
    if not headers:
        return ''
    m = re.search(r'\bheader\.d\s*=\s*([a-zA-Z0-9.\-]+)', headers, re.IGNORECASE)
    return m.group(1).lower() if m else ''


def _domains_align(dkim_domain: str, sender_domain: str) -> bool:
    """
    DMARC alignment relajado: el dominio que firmó debe ser el sender
    o un subdominio del sender (o viceversa).

    netflix.com firmó por accounts.netflix.com → align ✓
    netflix.com firmó por netflix.com          → align ✓
    sendgrid.net firmó por netflix.com         → NO align ✗ (spoof potencial)
    """
    if not dkim_domain or not sender_domain:
        return False
    d = dkim_domain.lower()
    s = sender_domain.lower()
    if d == s:
        return True
    # Subdominio en cualquier dirección
    if d.endswith('.' + s) or s.endswith('.' + d):
        return True
    # Mismo dominio organizativo (heurística simple: últimos 2 labels)
    return _organizational_domain(d) == _organizational_domain(s)


def _organizational_domain(d: str) -> str:
    """
    Heurística simple para sacar el dominio organizativo:
      mail.netflix.com  → netflix.com
      a.b.c.example.uk  → example.uk
    No es un PSL completo (Public Suffix List) pero cubre el 95% de casos.
    """
    parts = d.split('.')
    if len(parts) <= 2:
        return d
    # TLDs de 2 partes comunes (.co.uk, .com.mx, etc.)
    tld_2 = {'co.uk', 'co.jp', 'com.mx', 'com.ar', 'com.br', 'com.au',
             'co.nz', 'co.za', 'com.tr', 'com.cn'}
    last2 = '.'.join(parts[-2:])
    last3 = '.'.join(parts[-3:])
    if last2 in tld_2 and len(parts) >= 3:
        return last3
    return last2


# ──────────────────────────────────────────────────────────────────────
#  Lógica del veredicto
# ──────────────────────────────────────────────────────────────────────

def _decide(spf, dkim, dmarc, aligned, dkim_domain, sender_domain):
    """
    Política de decisión. Devuelve (verdict, evidence, multiplier, floor).

    Filosofía:
      - DKIM pass + alineado = el correo es 100% auténtico → bajamos score 65%.
      - DKIM/DMARC fail = es un spoof claro → forzamos score a 75 mínimo.
      - DMARC pass solo (sin DKIM) = SPF dijo OK pero sin firma → confianza media.
      - Sin nada (none) = no podemos verificar → score sin tocar.
    """
    # ── Caso "verificado": el remitente es 100% legítimo ──
    if dkim == PASS and aligned:
        if dmarc == PASS:
            return (
                VERIFIED,
                f'Remitente verificado criptográficamente · DKIM pass · DMARC pass · firmado por {dkim_domain}',
                0.35,   # baja el score un 65% — Netflix con URLs raras pasa de 70 a 24
                0,      # sin floor mínimo
            )
        # DKIM ok pero DMARC no se reportó → confianza alta igual
        return (
            VERIFIED,
            f'Remitente verificado por DKIM · firmado por {dkim_domain}',
            0.45,
            0,
        )

    # ── Caso "spoof claro": detectamos suplantación ──
    # DMARC fail es el indicador más fuerte de spoof
    if dmarc == FAIL:
        return (
            SPOOFED,
            f'Suplantación detectada · DMARC fail · El remitente no controla {sender_domain}',
            1.0,
            75,        # fuerza score a danger mínimo
        )
    # DKIM fail con dominio no alineado también es sospechoso fuerte
    if dkim == FAIL:
        msg = f'Firma DKIM inválida · posible suplantación de {sender_domain}'
        return (SPOOFED, msg, 1.0, 70)

    # SPF fail solo (sin DKIM) — más débil pero relevante
    if spf == FAIL and dkim in (NONE, ''):
        return (
            SPOOFED,
            f'SPF fail · IP del remitente no autorizada por {sender_domain}',
            1.0,
            65,
        )

    # ── Caso intermedio: SPF pass + DKIM none ──
    # El servidor SMTP está en la whitelist del dominio pero no firmó.
    # Tipico de listas de correo y newsletters mal configuradas.
    if spf == PASS and dkim in (NONE, ''):
        return (
            UNVERIFIED,
            f'SPF pass pero sin firma DKIM · autenticidad parcial',
            0.85,      # leve descuento
            0,
        )

    # ── Caso "no verificable": sin información ──
    return (
        UNVERIFIED,
        'Sin información de autenticación (SPF/DKIM/DMARC ausentes)',
        1.0,           # no toca el score
        0,
    )


# ──────────────────────────────────────────────────────────────────────
#  Aplicar el veredicto al score
# ──────────────────────────────────────────────────────────────────────

def apply_to_score(base_score: int, auth_result: dict) -> tuple:
    """
    Combina el score base con el veredicto de autenticación.

    Returns:
        (final_score, ajuste_evidence_dict | None)
    """
    multiplier = float(auth_result.get('score_multiplier', 1.0))
    floor      = int(auth_result.get('score_floor', 0))
    verdict    = auth_result.get('verdict', UNVERIFIED)

    adjusted = int(round(base_score * multiplier))
    final    = max(adjusted, floor)
    final    = max(0, min(100, final))

    # Solo generamos evidencia si HUBO cambio real
    if final == base_score:
        return final, None

    if verdict == VERIFIED:
        ev = {
            'type':     'auth_verified',
            'detail':   f'✓ {auth_result.get("evidence", "")} · score reducido de {base_score} a {final}',
            'severity': -30,
        }
    elif verdict == SPOOFED:
        ev = {
            'type':     'auth_spoofed',
            'detail':   f'⚠ {auth_result.get("evidence", "")} · score elevado de {base_score} a {final}',
            'severity': 70,
        }
    else:
        ev = {
            'type':     'auth_partial',
            'detail':   f'{auth_result.get("evidence", "")} · score ajustado de {base_score} a {final}',
            'severity': 5,
        }

    return final, ev
