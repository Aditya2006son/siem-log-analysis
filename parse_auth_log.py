import re

def parse_auth_log(log_file_path):
    login_events = []

    # This pattern grabs the timestamp and the IP address for login attempts
    log_pattern = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*'
        r'(Failed|Accepted) password.*from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    )

    # Open the log file and scan through line by line
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = log_pattern.search(line)
            if match:
                # Decide whether the line is a failure or success
                if "Failed" in line:
                    status = "Failed"
                else:
                    status = "Accepted"  # Assumes anything matched is one or the other

                login_events.append({
                    "timestamp": match.group("timestamp"),
                    "ip": match.group("ip"),
                    "status": status
                })

            # else:
            #     print("Skipping unrelated line:", line.strip())  # I used this for debugging

    return login_events
