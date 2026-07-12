
import re
import json


PASS    = 'pass'
FAIL    = 'fail'
SOFTFAIL = 'softfail'
NEUTRAL = 'neutral'
NONE    = 'none'

VERIFIED   = 'verified'
UNVERIFIED = 'unverified'
SPOOFED    = 'spoofed'


def check_authentication(post_data, sender_email: str) -> dict:

    sender_domain = _extract_domain(sender_email)

    spf  = _parse_spf(post_data.get('SPF', '') or post_data.get('spf', ''))
    dkim_raw = post_data.get('dkim', '') or post_data.get('DKIM', '')
    dkim, dkim_domain = _parse_dkim(dkim_raw)

    headers_str = post_data.get('headers', '') or ''
    dmarc = _parse_dmarc_from_headers(headers_str)

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



def _extract_domain(email: str) -> str:

    if not email:
        return ''
    if '<' in email and '>' in email:
        email = email.split('<')[-1].split('>')[0]
    if '@' not in email:
        return ''
    return email.split('@')[-1].strip().lower().rstrip('>').strip()


def _parse_spf(value: str) -> str:
   
    if not value:
        return NONE
    v = value.strip().lower().split()[0]  
    if v in (PASS, FAIL, SOFTFAIL, NEUTRAL, NONE):
        return v
    return NONE


def _parse_dkim(value: str) -> tuple:
   
    if not value:
        return NONE, ''
    v = value.strip()

    
    m = re.search(r'@([a-zA-Z0-9.\-]+)\s*[:=]\s*(pass|fail|none)', v, re.IGNORECASE)
    if m:
        return m.group(2).lower(), m.group(1).lower()

   
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


    low = v.lower()
    for k in (PASS, FAIL, NONE):
        if k in low:
            return k, ''

    return NONE, ''


def _parse_dmarc_from_headers(headers: str) -> str:

    if not headers:
        return NONE
    m = re.search(r'\bdmarc\s*=\s*(pass|fail|bestguesspass|none)\b',
                  headers, re.IGNORECASE)
    if not m:
        return NONE
    val = m.group(1).lower()
    if val == 'bestguesspass':
        return PASS
    return val if val in (PASS, FAIL, NONE) else NONE


def _parse_dkim_domain_from_headers(headers: str) -> str:

    if not headers:
        return ''
    m = re.search(r'\bheader\.d\s*=\s*([a-zA-Z0-9.\-]+)', headers, re.IGNORECASE)
    return m.group(1).lower() if m else ''


def _domains_align(dkim_domain: str, sender_domain: str) -> bool:

    if not dkim_domain or not sender_domain:
        return False
    d = dkim_domain.lower()
    s = sender_domain.lower()
    if d == s:
        return True

    if d.endswith('.' + s) or s.endswith('.' + d):
        return True

    return _organizational_domain(d) == _organizational_domain(s)


def _organizational_domain(d: str) -> str:
    parts = d.split('.')
    if len(parts) <= 2:
        return d

    tld_2 = {'co.uk', 'co.jp', 'com.mx', 'com.ar', 'com.br', 'com.au',
             'co.nz', 'co.za', 'com.tr', 'com.cn'}
    last2 = '.'.join(parts[-2:])
    last3 = '.'.join(parts[-3:])
    if last2 in tld_2 and len(parts) >= 3:
        return last3
    return last2



def _decide(spf, dkim, dmarc, aligned, dkim_domain, sender_domain):

    if dkim == PASS and aligned:
        if dmarc == PASS:
            return (
                VERIFIED,
                f'Remitente verificado criptográficamente · DKIM pass · DMARC pass · firmado por {dkim_domain}',
                0.35,   
                0,     
            )

        return (
            VERIFIED,
            f'Remitente verificado por DKIM · firmado por {dkim_domain}',
            0.45,
            0,
        )

    if dmarc == FAIL:
        return (
            SPOOFED,
            f'Suplantación detectada · DMARC fail · El remitente no controla {sender_domain}',
            1.0,
            75,       
        )

    if dkim == FAIL:
        msg = f'Firma DKIM inválida · posible suplantación de {sender_domain}'
        return (SPOOFED, msg, 1.0, 70)
    if spf == FAIL and dkim in (NONE, ''):
        return (
            SPOOFED,
            f'SPF fail · IP del remitente no autorizada por {sender_domain}',
            1.0,
            65,
        )

    if spf == PASS and dkim in (NONE, ''):
        return (
            UNVERIFIED,
            f'SPF pass pero sin firma DKIM · autenticidad parcial',
            0.85,
            0,
        )

    return (
        UNVERIFIED,
        'Sin información de autenticación (SPF/DKIM/DMARC ausentes)',
        1.0,
        0,
    )


def apply_to_score(base_score: int, auth_result: dict) -> tuple:
    multiplier = float(auth_result.get('score_multiplier', 1.0))
    floor      = int(auth_result.get('score_floor', 0))
    verdict    = auth_result.get('verdict', UNVERIFIED)

    adjusted = int(round(base_score * multiplier))
    final    = max(adjusted, floor)
    final    = max(0, min(100, final))

    if final == base_score:
        return final, None

    if verdict == VERIFIED:
        ev = {
            'type':     'auth_verified',
            'detail':   f'{auth_result.get("evidence", "")} · score reducido de {base_score} a {final}',
            'severity': -30,
        }
    elif verdict == SPOOFED:
        ev = {
            'type':     'auth_spoofed',
            'detail':   f'{auth_result.get("evidence", "")} · score elevado de {base_score} a {final}',
            'severity': 70,
        }
    else:
        ev = {
            'type':     'auth_partial',
            'detail':   f'{auth_result.get("evidence", "")} · score ajustado de {base_score} a {final}',
            'severity': 5,
        }

    return final, ev
