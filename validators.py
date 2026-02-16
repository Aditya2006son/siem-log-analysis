from datetime import datetime
from dateutil import parser as dtparser


def _parse_ts(ts: str) -> datetime | None:
    try:
        return dtparser.parse(ts)
    except Exception:
        return None


def validate_event(event: dict) -> tuple[bool, str | None]:
    """
    Returns (ok, reason_if_not_ok)

    "Incorrect logs" are ones that fail validation:
    - missing required fields
    - timestamp not parseable
    - obvious type issues
    """
    if not isinstance(event, dict):
        return False, "event_not_dict"

    ts = event.get("timestamp")
    if not ts or not isinstance(ts, str) or _parse_ts(ts) is None:
        return False, "missing_or_bad_timestamp"

    # If it’s syslog-derived, we expect these:
    fmt = event.get("source_format")
    if fmt == "syslog":
        for k in ("host", "app", "message"):
            if not event.get(k) or not isinstance(event.get(k), str):
                return False, f"missing_or_bad_{k}"

    # If severity exists, do a small sanity check (common SIEM field)
    sev = event.get("severity")
    if sev is not None:
        if not isinstance(sev, int):
            return False, "severity_not_int"
        if sev < 0 or sev > 10:
            return False, "severity_out_of_range"

    return True, None
