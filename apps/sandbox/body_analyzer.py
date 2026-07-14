
import re
import html as htmllib
from urllib.parse import urlparse


def _empty():
    return {
        "category": "body",
        "score": 0,
        "threat": "",
        "evidence": [],
        "iocs": {"urls": [], "ips": [], "domains": [], "hashes": []},
    }


def _ev(etype, detail, severity):
    return {"type": etype, "detail": detail[:500], "severity": max(0, min(100, severity))}



URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "bc.vc", "adf.ly", "tiny.cc",
    "lnkd.in", "trib.al", "soo.gd",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "click", "loan", "win",
    "review", "country", "stream", "kim", "men", "racing", "download",
    "zip", "mov",
}
KNOWN_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "outlook", "office365", "hotmail", "gmail",
    "linkedin", "twitter", "whatsapp", "telegram", "spotify", "youtube",
    "dropbox", "github", "binance", "coinbase",
}

PHISHING_KEYWORDS = [
    # Español
    ("verifica tu cuenta",       65),
    ("verificar cuenta",         60),
    ("suspendida",               55),
    ("suspendido",               55),
    ("confirma tu identidad",    65),
    ("haga clic aquí",           45),
    ("haz clic aquí",            45),
    ("urgente",                  35),
    ("actualiza tus datos",      55),
    ("contraseña vencida",       60),
    ("paquete retenido",         60),
    ("ganador",                  50),
    ("premio",                   45),
    ("bitcoin",                  40),
    ("transferencia pendiente",  55),
    ("factura adjunta",          40),
    ("verify your account",      65),
    ("account suspended",        65),
    ("click here to confirm",    55),
    ("update your password",     55),
    ("invoice attached",         40),
    ("payment pending",          50),
    ("you have won",             55),
    ("limited time offer",       30),
]


def analyze(body_text: str = "", body_html: str = "",
            from_addr: str = "", reply_to: str = "",
            subject: str = "",
            dkim_status: str = "", spf_status: str = "") -> dict:

    result = _empty()

    body_text = body_text or ""
    body_html = body_html or ""
    combined = f"{subject}\n{body_text}\n{body_html}".lower()

    urls_text = re.findall(r'https?://[^\s<>"\']+', body_text)
    urls_html_raw = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', body_html, re.IGNORECASE)
    
    urls_html = [
        u for u in urls_html_raw
        if not u.strip().lower().startswith(
            ("mailto:", "tel:", "cid:", "sms:", "callto:", "xmpp:", "skype:")
        )
    ]
    all_urls = list(dict.fromkeys(urls_text + urls_html))

    for url in all_urls[:30]:
        sub = _analyze_url(url)
        result["score"] = max(result["score"], sub["score"])
        result["evidence"].extend(sub["evidence"])
        for k in ("urls", "ips", "domains"):
            for item in sub["iocs"][k]:
                if item not in result["iocs"][k]:
                    result["iocs"][k].append(item)


    if body_html:
        for match in re.finditer(
            r'<a[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            body_html, re.IGNORECASE | re.DOTALL,
        ):
            href = match.group(1).strip()
            text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
            text = htmllib.unescape(text)

            if re.match(r'^https?://', text):
                href_host = (urlparse(href).hostname or "").lower()
                text_host = (urlparse(text).hostname or "").lower()
                if href_host and text_host and href_host != text_host:
                    
                    sender_domain = _email_domain(from_addr) if from_addr else ""
                    text_primary = ".".join(text_host.split(".")[-2:])
                    sender_primary = ".".join(sender_domain.split(".")[-2:]) if sender_domain else ""
                    is_legit_tracking = (
                        text_primary and sender_primary
                        and text_primary == sender_primary
                        and dkim_status.upper() == "PASS"
                        and spf_status.upper() == "PASS"
                    )
                    if not is_legit_tracking:
                        result["evidence"].append(_ev(
                            "link_spoofing",
                            f"El enlace dice '{text_host}' pero apunta a '{href_host}' — phishing clásico",
                            90,
                        ))
                        result["score"] = max(result["score"], 90)

    
    if body_html:
        if re.search(r'<iframe\b', body_html, re.IGNORECASE):
            result["evidence"].append(_ev(
                "html_iframe",
                "Cuerpo HTML con <iframe> — puede cargar contenido de terceros",
                65,
            ))
            result["score"] = max(result["score"], 65)

        if re.search(r'<script\b', body_html, re.IGNORECASE):
            result["evidence"].append(_ev(
                "html_script",
                "Cuerpo HTML con <script> — los clientes serios lo bloquean, pero es indicador",
                70,
            ))
            result["score"] = max(result["score"], 70)


        if re.search(r'<form\b[^>]*>', body_html, re.IGNORECASE) \
                and re.search(r'type\s*=\s*["\']password["\']', body_html, re.IGNORECASE):
            result["evidence"].append(_ev(
                "html_credential_form",
                "Formulario en el correo que pide contraseña — phishing de credenciales",
                85,
            ))
            result["score"] = max(result["score"], 85)

        # Pixel tracker / web bug
        if re.search(r'<img[^>]+(width\s*=\s*["\']?1["\']?|height\s*=\s*["\']?1["\']?)',
                     body_html, re.IGNORECASE):
            result["evidence"].append(_ev(
                "html_tracking_pixel",
                "Pixel de seguimiento (1×1) — el remitente sabrá si abriste el correo",
                10,
            ))

    
    triggered_keywords = []
    for kw, sev in PHISHING_KEYWORDS:
        if kw in combined:
            triggered_keywords.append((kw, sev))

    if len(triggered_keywords) >= 2:
        max_sev = max(s for _, s in triggered_keywords)
        kw_list = ", ".join(f'"{k}"' for k, _ in triggered_keywords[:5])
        result["evidence"].append(_ev(
            "phishing_language",
            f"Lenguaje típico de phishing: {kw_list}",
            max_sev,
        ))
        result["score"] = max(result["score"], max_sev)
    elif len(triggered_keywords) == 1:
        kw, sev = triggered_keywords[0]
        result["evidence"].append(_ev(
            "phishing_language",
            f'Frase típica de phishing: "{kw}"',
            min(sev, 40),
        ))
        result["score"] = max(result["score"], min(sev, 40))

    if from_addr and reply_to:
        from_dom = _email_domain(from_addr)
        reply_dom = _email_domain(reply_to)
        if from_dom and reply_dom and not _domains_align(from_dom, reply_dom):
            result["evidence"].append(_ev(
                "header_mismatch",
                f"Reply-To ({reply_dom}) en dominio distinto al From ({from_dom})",
                75,
            ))
            result["score"] = max(result["score"], 75)


    display_name_match = re.match(r'^"?([^"<]+)"?\s*<[^>]+>$', from_addr or "")
    if display_name_match:
        display = display_name_match.group(1).strip().lower()
        from_dom = _email_domain(from_addr)
        for brand in KNOWN_BRANDS:
            if brand in display and brand not in from_dom:
                result["evidence"].append(_ev(
                    "from_brand_impersonation",
                    f"El nombre del remitente menciona '{brand}' pero el dominio es '{from_dom}'",
                    80,
                ))
                result["score"] = max(result["score"], 80)
                break

    if subject:
        subj_lower = subject.lower()
        if any(c in subject for c in ["⚠", "🚨", "‼", "❗", "❓"]) and \
                any(w in subj_lower for w in ("urgente", "alert", "warning", "security")):
            result["evidence"].append(_ev(
                "subject_alarmism",
                "Asunto con emojis de alarma + palabras urgentes — táctica de phishing",
                55,
            ))
            result["score"] = max(result["score"], 55)

    if result["score"] >= 80:
        result["threat"] = "Phishing — alta confianza"
    elif result["score"] >= 60:
        result["threat"] = "Posible phishing"
    elif result["score"] >= 30:
        result["threat"] = "Cuerpo con elementos sospechosos"

    return result


def _email_domain(addr: str) -> str:
    m = re.search(r'<([^>]+)>', addr or "")
    email = m.group(1) if m else addr
    return (email or "").split("@")[-1].strip().lower()


def _domains_align(d1: str, d2: str) -> bool:

    if d1 == d2:
        return True
    p1 = d1.lower().split(".")
    p2 = d2.lower().split(".")
    return len(p1) >= 2 and len(p2) >= 2 and p1[-2:] == p2[-2:]


def _analyze_url(url: str) -> dict:

    result = _empty()
    result["iocs"]["urls"].append(url)

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return result

    host = (parsed.hostname or "").lower()
    if host:
        result["iocs"]["domains"].append(host)

    if "@" in (parsed.netloc or ""):
        result["evidence"].append(_ev(
            "url_credentials_in_url",
            f"URL con credenciales embebidas: {url[:100]}",
            85,
        ))
        result["score"] = max(result["score"], 85)

    if host and re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
        result["iocs"]["ips"].append(host)
        result["evidence"].append(_ev(
            "url_ip_host",
            f"URL apunta a IP en lugar de dominio: {host}",
            70,
        ))
        result["score"] = max(result["score"], 70)

    if host in URL_SHORTENERS:
        result["evidence"].append(_ev(
            "url_shortener",
            f"Servicio acortador ({host}) — destino real desconocido",
            55,
        ))
        result["score"] = max(result["score"], 55)

    tld = host.rsplit(".", 1)[-1] if host else ""
    if tld in SUSPICIOUS_TLDS:
        result["evidence"].append(_ev(
            "url_suspicious_tld",
            f"TLD sospechoso (.{tld}) frecuente en phishing",
            60,
        ))
        result["score"] = max(result["score"], 60)

    if host:
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain = ".".join(parts[:-2])
            for brand in KNOWN_BRANDS:
                if brand in subdomain and brand not in parts[-2]:
                    result["evidence"].append(_ev(
                        "url_brand_impersonation",
                        f"Marca '{brand}' usada como subdominio de {parts[-2]}.{parts[-1]} — suplantación",
                        80,
                    ))
                    result["score"] = max(result["score"], 80)
                    break

    if any(ord(c) > 127 for c in host):
        result["evidence"].append(_ev(
            "url_idn_homograph",
            f"Dominio con caracteres no-ASCII (homógrafo): {host}",
            75,
        ))
        result["score"] = max(result["score"], 75)

    if len(url) > 200:
        result["evidence"].append(_ev(
            "url_excessive_length",
            f"URL muy larga ({len(url)} chars) — posible ofuscación",
            20,
        ))
        result["score"] = max(result["score"], 20)

    if host.count(".") >= 4:
        result["evidence"].append(_ev(
            "url_many_subdomains",
            f"{host.count('.')} niveles de subdominio en {host}",
            30,
        ))
        result["score"] = max(result["score"], 30)

    return result
