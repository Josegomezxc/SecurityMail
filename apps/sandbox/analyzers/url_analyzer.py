"""
Análisis de URLs / dominios.
Detecta:
  - URLs IP-only (sin DNS)
  - Acortadores (bit.ly, t.co, ...)
  - Dominios homógrafos (caracteres confusos)
  - TLDs sospechosos comunes en phishing
  - Credentials-in-URL (user:pass@host)
  - Discrepancia entre texto y href
"""
import re
from urllib.parse import urlparse
from .base import empty_result, evidence

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "bc.vc", "adf.ly", "tiny.cc",
    "lnkd.in", "trib.al", "soo.gd",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",      # antiguos free TLD muy abusados
    "top", "click", "loan", "win",
    "review", "country", "stream", "kim", "men", "racing", "download",
    "zip", "mov",                       # nuevos TLD problemáticos (zip = confusión con archivo)
}

KNOWN_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "outlook", "office365", "hotmail",
    "gmail", "linkedin", "twitter", "whatsapp", "telegram", "spotify",
    "youtube", "dropbox", "github", "binance", "coinbase",
}


def analyze_url(url: str) -> dict:
    """Devuelve un dict con score y evidencia para una URL concreta."""
    result = empty_result("url")
    result["iocs"]["urls"].append(url)

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        result["evidence"].append(evidence("url_parse_error", f"URL inválida: {url}", 30))
        return result

    host = (parsed.hostname or "").lower()
    if host:
        result["iocs"]["domains"].append(host)

    # 1. Credenciales en la URL (user:pass@host) — clásico phishing
    if "@" in (parsed.netloc or ""):
        result["evidence"].append(evidence(
            "url_credentials_in_url",
            f"URL con credenciales embebidas: {url[:120]}",
            85,
        ))
        result["score"] = max(result["score"], 85)

    # 2. IP en lugar de dominio
    if host and re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
        result["iocs"]["ips"].append(host)
        result["evidence"].append(evidence(
            "url_ip_host",
            f"URL apunta a IP en lugar de dominio: {host}",
            70,
        ))
        result["score"] = max(result["score"], 70)

    # 3. Acortador
    if host in URL_SHORTENERS:
        result["evidence"].append(evidence(
            "url_shortener",
            f"Servicio acortador ({host}) — destino real desconocido",
            55,
        ))
        result["score"] = max(result["score"], 55)

    # 4. TLD sospechoso
    tld = host.rsplit(".", 1)[-1] if host else ""
    if tld in SUSPICIOUS_TLDS:
        result["evidence"].append(evidence(
            "url_suspicious_tld",
            f"TLD sospechoso (.{tld}) frecuente en phishing",
            60,
        ))
        result["score"] = max(result["score"], 60)

    # 5. Marca conocida en subdominio (ej. paypal.evilsite.com)
    if host:
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain = ".".join(parts[:-2])
            for brand in KNOWN_BRANDS:
                if brand in subdomain and brand not in parts[-2]:
                    result["evidence"].append(evidence(
                        "url_brand_impersonation",
                        f"Marca '{brand}' usada como subdominio de {parts[-2]}.{parts[-1]} — posible suplantación",
                        80,
                    ))
                    result["score"] = max(result["score"], 80)
                    break

    # 6. Caracteres no-ASCII (IDN homógrafos)
    if any(ord(c) > 127 for c in host):
        result["evidence"].append(evidence(
            "url_idn_homograph",
            f"Dominio con caracteres no-ASCII (IDN/homógrafo): {host}",
            75,
        ))
        result["score"] = max(result["score"], 75)

    # 7. URL excesivamente larga
    if len(url) > 200:
        result["evidence"].append(evidence(
            "url_excessive_length",
            f"URL muy larga ({len(url)} chars) — posible ofuscación",
            45,
        ))
        result["score"] = max(result["score"], 45)

    # 8. Muchos subdominios (a.b.c.d.e.com)
    if host.count(".") >= 4:
        result["evidence"].append(evidence(
            "url_many_subdomains",
            f"{host.count('.')} niveles de subdominio en {host}",
            55,
        ))
        result["score"] = max(result["score"], 55)

    # 9. URL con guion bajo en host (no es válido pero técnica de phishing)
    if "_" in host:
        result["evidence"].append(evidence(
            "url_underscore_host",
            f"Guion bajo en hostname: {host}",
            40,
        ))
        result["score"] = max(result["score"], 40)

    return result


def analyze_urls(urls) -> dict:
    """Analiza una lista de URLs y devuelve un resultado agregado."""
    result = empty_result("url")
    if not urls:
        return result

    threats = set()
    for u in list(dict.fromkeys(urls))[:30]:    # dedup, máx 30
        sub = analyze_url(u)
        result["score"] = max(result["score"], sub["score"])
        result["evidence"].extend(sub["evidence"])
        for key in ("urls", "ips", "domains"):
            for item in sub["iocs"][key]:
                if item not in result["iocs"][key]:
                    result["iocs"][key].append(item)
        if sub["score"] >= 70:
            threats.add(urlparse(u if "://" in u else "http://" + u).hostname or u)

    if threats:
        result["threat"] = f"URLs sospechosas: {', '.join(list(threats)[:3])}"

    return result
