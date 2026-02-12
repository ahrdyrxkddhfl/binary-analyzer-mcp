def get_exploit_mitigation_info(protection: str, target_vuln: str):
    if not protection or not target_vuln:
        return {
            "ok": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "protection and target_vuln are required",
                "hint": "Provide both fields",
                "retryable": False
            }
        }

    difficulty = "Medium"

    if "NX" in protection and "Canary" in protection and "PIE" in protection:
        difficulty = "High"
    elif "NX" in protection:
        difficulty = "Medium"
    else:
        difficulty = "Low"

    return {
        "ok": True,
        "protection": protection,
        "target_vulnerability": target_vuln,
        "difficulty": difficulty,
        "analysis": f"Exploit difficulty estimated as {difficulty} due to protections: {protection}"
    }
