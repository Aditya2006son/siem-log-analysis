import json
import re
from dataclasses import dataclass
from datetime import datetime
from dateutil import parser as dtparser


@dataclass
class ParseResult:
    ok: bool
    event: dict | None
    error: str | None
    raw: str


_SYSLOG_RE = re.compile(
    r"""
    ^\s*
    (?P<ts>[^ ]+\s+[^ ]+\s+[^ ]+)      # pretty forgiving timestamp chunk
    \s+
    (?P<host>[^ ]+)
    \s+
    (?P<app>[^ :]+)
    (?:
        \[(?P<pid>\d+)\]
    )?
    :
    \s*
    (?P<msg>.*)
    $
    """,
    re.VERBOSE,
)


def _parse_timestamp(ts: str) -> datetime | None:
    try:
        return dtparser.parse(ts, fuzzy=True)
    except Exception:
        return None


def parse_syslog_line(line: str) -> ParseResult:
    raw = line.rstrip("\n")
    if not raw.strip():
        return ParseResult(False, None, "empty_line", raw)

    m = _SYSLOG_RE.match(raw)
    if not m:
        return ParseResult(False, None, "syslog_regex_no_match", raw)

    ts = _parse_timestamp(m.group("ts"))
    if ts is None:
        return ParseResult(False, None, "bad_timestamp", raw)

    event = {
        "timestamp": ts.isoformat(),
        "host": m.group("host"),
        "app": m.group("app"),
        "pid": int(m.group("pid")) if m.group("pid") else None,
        "message": m.group("msg"),
        "source_format": "syslog",
        "raw": raw,
    }
    return ParseResult(True, event, None, raw)


def parse_jsonl_line(line: str) -> ParseResult:
    raw = line.rstrip("\n")
    if not raw.strip():
        return ParseResult(False, None, "empty_line", raw)

    try:
        obj = json.loads(raw)
    except Exception:
        return ParseResult(False, None, "json_decode_error", raw)

    if not isinstance(obj, dict):
        return ParseResult(False, None, "json_not_object", raw)

    # We don’t force a schema here — validator does that.
    obj.setdefault("source_format", "jsonl")
    obj.setdefault("raw", raw)
    return ParseResult(True, obj, None, raw)
