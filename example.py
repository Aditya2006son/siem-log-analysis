import re

def parse_failed_login(log_line):
    pattern = r'Failed password for (\w+) from ([\d\.]+)'
    match = re.search(pattern, log_line)

    if match:
        return {
            "event": "failed_login",
            "username": match.group(1),
            "ip_address": match.group(2)
        }
    return None
