"""
WebAudit Security Scoring System
Metode: CVSS v3.1 Simplified → Grade A-F
Kontribusi original untuk TA
"""

# Risk weights per severity
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}

def calculate_grade(findings: list[dict]) -> dict:
    """
    Hitung security grade berdasarkan temuan.
    
    Args:
        findings: list of dict dengan key 'severity' 
                  (CRITICAL/HIGH/MEDIUM/LOW/INFO)
    
    Returns:
        dict dengan grade (A-F), score, dan summary
    """
    if not findings:
        return {"grade": "A", "score": 100, "summary": "Tidak ada temuan"}

    total_deduction = 0
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding in findings:
        severity = finding.get("severity", "INFO")
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        total_deduction += weight
        severity_count[severity] += 1

    # Score 0-100 (100 = perfect, 0 = very bad)
    score = max(0, 100 - total_deduction)

    # Grade mapping
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_count[sev] > 0:
            summary_parts.append(f"{severity_count[sev]} {sev}")

    summary = ", ".join(summary_parts) if summary_parts else "Aman"

    return {
        "grade": grade,
        "score": score,
        "severity_count": severity_count,
        "summary": summary
    }


def grade_color(grade: str) -> str:
    """Return ANSI color code for grade display."""
    colors = {
        "A": "\033[92m",  # Green
        "B": "\033[96m",  # Cyan
        "C": "\033[93m",  # Yellow
        "D": "\033[91m",  # Red
        "F": "\033[95m",  # Magenta (critical)
    }
    return colors.get(grade, "\033[0m")


RESET_COLOR = "\033[0m"
