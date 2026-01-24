"""CVSS 3.1 score calculator utility."""

from typing import Tuple
from cvss import CVSS3


def calculate_cvss_score(vector: str) -> Tuple[float, str]:
    """Calculate CVSS 3.1 base score and severity from vector string."""
    try:
        c = CVSS3(vector)
        score = c.base_score
        severity = get_severity_rating(score)
        return score, severity
    except Exception as e:
        print(f"Warning: Could not parse CVSS vector '{vector}': {e}")
        return 0.0, "Unknown"


def get_severity_rating(score: float) -> str:
    """Get severity rating from CVSS base score."""
    if score == 0.0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


def get_severity_color(severity: str) -> str:
    """Get hex color for severity rating."""
    colors = {
        "None": "#53aa33",
        "Low": "#ffcb0d",
        "Medium": "#f9a009",
        "High": "#df3d03",
        "Critical": "#cc0500",
        "Unknown": "#808080",
    }
    return colors.get(severity, "#808080")
