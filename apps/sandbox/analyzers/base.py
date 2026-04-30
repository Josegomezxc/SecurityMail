"""
Estructura común que devuelven todos los analizadores.

    {
        "category":   "executable" | "office" | "pdf" | "archive" | "script" | "url" | "yara" | "unknown",
        "score":      0..100,                # contribución de este analizador
        "threat":     "Nombre corto de la amenaza" | "",
        "evidence":   [ {"type": "...", "detail": "...", "severity": 0..100}, ... ],
        "iocs":       { "urls": [...], "ips": [...], "domains": [...], "hashes": [...] },
    }
"""
from typing import List, Dict, Any


def empty_result(category: str = "unknown") -> Dict[str, Any]:
    """Devuelve un resultado vacío con el formato canónico."""
    return {
        "category": category,
        "score": 0,
        "threat": "",
        "evidence": [],
        "iocs": {"urls": [], "ips": [], "domains": [], "hashes": []},
    }


def evidence(etype: str, detail: str, severity: int) -> Dict[str, Any]:
    """Crea un item de evidencia con campos validados."""
    return {
        "type": etype,
        "detail": detail[:500],            # cap de seguridad
        "severity": max(0, min(100, severity)),
    }


def merge(*results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combina varios resultados en uno.
    El score final es el MÁXIMO de los individuales (no se suman para no
    superar 100 con falsos positivos), y la evidencia + IOCs se concatena.
    """
    merged = empty_result("aggregate")
    threats: List[str] = []

    for r in results:
        if not r:
            continue
        merged["score"] = max(merged["score"], int(r.get("score", 0)))
        if r.get("threat"):
            threats.append(r["threat"])
        merged["evidence"].extend(r.get("evidence", []))

        iocs = r.get("iocs", {})
        for key in ("urls", "ips", "domains", "hashes"):
            for item in iocs.get(key, []):
                if item not in merged["iocs"][key]:
                    merged["iocs"][key].append(item)

    merged["threat"] = " · ".join(dict.fromkeys(threats))   # dedup preservando orden
    return merged
