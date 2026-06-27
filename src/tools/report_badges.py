SEVERITY_COLORS = {
    "CRITICAL": "D32F2F",
    "HIGH": "F57C00",
    "MEDIUM": "FBC02D",
    "LOW": "388E3C",
    "INFO": "757575",
}

STATUS_COLORS = {
    "미흡": "D32F2F",
    "적정": "388E3C",
    "점검필요": "757575",
}

PRIORITY_COLORS = {
    "즉시": "D32F2F",
    "단기": "F57C00",
    "중기": "FBC02D",
    "장기": "757575",
}

FRAMEWORK_COLORS = {
    "ISMS-P": "1565C0",
    "EFT": "E65100",
}


def severity_badge(severity: str, label: str | None = None) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "757575")
    text = label or severity.upper()
    return f"![{text}](https://img.shields.io/badge/{_encode(text)}-{color}?style=flat-square)"


def status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status, "757575")
    return f"![{status}](https://img.shields.io/badge/진단결과-{_encode(status)}-{color}?style=flat-square)"


def priority_badge(priority: str) -> str:
    color = PRIORITY_COLORS.get(priority, "757575")
    return f"![{priority}](https://img.shields.io/badge/조치우선순위-{_encode(priority)}-{color}?style=flat-square)"


def framework_badge(framework: str) -> str:
    if framework == "EFT":
        return f"![EFT](https://img.shields.io/badge/-{_encode('전자금융')}-{FRAMEWORK_COLORS['EFT']}?style=flat-square)"
    return f"![ISMS-P](https://img.shields.io/badge/-ISMS--P-{FRAMEWORK_COLORS['ISMS-P']}?style=flat-square)"


def metric_badge(label: str, value: int, color: str) -> str:
    return f"![{label}](https://img.shields.io/badge/{_encode(label)}-{value}-{color}?style=flat-square)"


def _encode(value: str) -> str:
    return value.replace(" ", "_").replace("-", "--")
