import re


def detect_sql_injection(data):
    patterns = [
        r"(\bor\b|\band\b).*=.*",
        r"(--|\#)",
        r"(union\s+select)",
        r"(drop\s+table)",
        r"(insert\s+into)",
    ]

    for pattern in patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False


def detect_xss(data):
    patterns = [
        r"<script.*?>.*?</script>",
        r"on\w+\s*=",
        r"javascript:",
        r"alert\(",
    ]

    for pattern in patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False