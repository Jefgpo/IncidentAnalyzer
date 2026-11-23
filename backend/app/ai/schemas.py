"""Esquemas JSON de salida estructurada para la IA."""

CLAIM = {
    "type": "object",
    "properties": {
        "text": {"type": "string"},
        "kind": {"type": "string", "enum": ["hecho_observado", "inferencia", "hipotesis", "recomendacion"]},
        "row_ids": {"type": "array", "items": {"type": "string"}},
        "finding_ids": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["text", "kind", "row_ids", "finding_ids"],
    "additionalProperties": False,
}
CLAIMS = {"type": "array", "items": CLAIM}

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": CLAIMS,
        "technical": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"finding_id": {"type": "string"}, "claims": CLAIMS},
                "required": ["finding_id", "claims"],
                "additionalProperties": False,
            },
        },
        "impact": CLAIMS,
        "action_plan": {
            "type": "object",
            "properties": {"investigate": CLAIMS, "contain": CLAIMS, "remediate": CLAIMS},
            "required": ["investigate", "contain", "remediate"],
            "additionalProperties": False,
        },
        "recommendations": CLAIMS,
    },
    "required": ["executive_summary", "technical", "impact", "action_plan", "recommendations"],
    "additionalProperties": False,
}

CHAT_SCHEMA = {
    "type": "object",
    "properties": {"claims": CLAIMS, "no_evidence": {"type": "boolean"}},
    "required": ["claims", "no_evidence"],
    "additionalProperties": False,
}
