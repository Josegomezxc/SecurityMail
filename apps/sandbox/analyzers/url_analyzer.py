
import re
from urllib.parse import urlparse
from .base import empty_result, evidence

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "bc.vc", "adf.ly", "tiny.cc",
    "lnkd.in", "trib.al", "soo.gd",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",     
    "top", "click", "loan", "win",
    "review", "country", "stream", "kim", "men", "racing", "download",
    "zip", "mov",                       
}

KNOWN_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "outlook", "office365", "hotmail",
    "gmail", "linkedin", "twitter", "whatsapp", "telegram", "spotify",
    "youtube", "dropbox", "github", "binance", "coinbase",
}


def analyze_url(url: str) -> dict:
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

    
    if "@" in (parsed.netloc or ""):
        result["evidence"].append(evidence(
            "url_credentials_in_url",
            f"URL con credenciales embebidas: {url[:120]}",
            85,
        ))
        result["score"] = max(result["score"], 85)

    
    if host and re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
        result["iocs"]["ips"].append(host)
        result["evidence"].append(evidence(
            "url_ip_host",
            f"URL apunta a IP en lugar de dominio: {host}",
            70,
        ))
        result["score"] = max(result["score"], 70)

    
    if host in URL_SHORTENERS:
        result["evidence"].append(evidence(
            "url_shortener",
            f"Servicio acortador ({host}) — destino real desconocido",
            55,
        ))
        result["score"] = max(result["score"], 55)

    
    tld = host.rsplit(".", 1)[-1] if host else ""
    if tld in SUSPICIOUS_TLDS:
        result["evidence"].append(evidence(
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
                    result["evidence"].append(evidence(
                        "url_brand_impersonation",
                        f"Marca '{brand}' usada como subdominio de {parts[-2]}.{parts[-1]} — posible suplantación",
                        80,
                    ))
                    result["score"] = max(result["score"], 80)
                    break

    
    if any(ord(c) > 127 for c in host):
        result["evidence"].append(evidence(
            "url_idn_homograph",
            f"Dominio con caracteres no-ASCII (IDN/homógrafo): {host}",
            75,
        ))
        result["score"] = max(result["score"], 75)

    
    if len(url) > 200:
        result["evidence"].append(evidence(
            "url_excessive_length",
            f"URL muy larga ({len(url)} chars) — posible ofuscación",
            20,
        ))
        result["score"] = max(result["score"], 20)

    
    if host.count(".") >= 4:
        result["evidence"].append(evidence(
            "url_many_subdomains",
            f"{host.count('.')} niveles de subdominio en {host}",
            30,
        ))
        result["score"] = max(result["score"], 30)

    
    if "_" in host:
        result["evidence"].append(evidence(
            "url_underscore_host",
            f"Guion bajo en hostname: {host}",
            40,
        ))
        result["score"] = max(result["score"], 40)

    return result


def analyze_urls(urls) -> dict:
    result = empty_result("url")
    if not urls:
        return result

    threats = set()
    for u in list(dict.fromkeys(urls))[:30]:   
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
