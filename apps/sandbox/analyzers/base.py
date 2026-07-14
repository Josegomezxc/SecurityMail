
from typing import List, Dict, Any


def empty_result(category: str = "unknown") -> Dict[str, Any]:
    return {
        "category": category,
        "score": 0,
        "threat": "",
        "evidence": [],
        "iocs": {"urls": [], "ips": [], "domains": [], "hashes": []},
    }


def evidence(etype: str, detail: str, severity: int) -> Dict[str, Any]:
    return {
        "type": etype,
        "detail": detail[:500],            
        "severity": max(0, min(100, severity)),
    }


def merge(*results: Dict[str, Any]) -> Dict[str, Any]:
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

    merged["threat"] = " · ".join(dict.fromkeys(threats))   
    return merged
