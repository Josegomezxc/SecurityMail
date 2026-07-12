
import os
import glob
from .base import empty_result, evidence

_RULES = None
_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def _load_rules():
    global _RULES
    if _RULES is not None:
        return _RULES
    try:
        import yara
    except Exception:
        _RULES = False  
        return _RULES

    rule_files = glob.glob(os.path.join(_RULES_DIR, "*.yar"))
    if not rule_files:
        _RULES = False
        return _RULES

    sources = {os.path.basename(p): p for p in rule_files}
    try:
        _RULES = yara.compile(filepaths=sources)
    except Exception:
        _RULES = False
    return _RULES


def analyze(filepath: str, mime: str = "") -> dict:
    result = empty_result("yara")

    rules = _load_rules()
    if rules is False:
        result["evidence"].append(evidence("yara_unavailable", "YARA no está disponible en este entorno", 0))
        return result
    if rules is None or rules == []:
        result["evidence"].append(evidence("yara_no_rules", "No se encontraron reglas YARA", 0))
        return result

    try:
        matches = rules.match(filepath, timeout=10)
    except Exception as e:
        result["evidence"].append(evidence("yara_error", f"YARA falló: {e}", 20))
        return result

    if not matches:
        return result

    threats = []
    for m in matches[:20]:
        meta = m.meta or {}
        sev = int(meta.get("severity", 70))
        category = meta.get("category", "yara")
        description = meta.get("description", m.rule)

        result["evidence"].append(evidence(
            f"yara_{category}",
            f"YARA `{m.rule}`: {description}",
            sev,
        ))
        result["score"] = max(result["score"], sev)
        threats.append(m.rule)

    result["threat"] = "Coincidencia YARA: " + ", ".join(threats[:3])
    return result
