import csv
import re
from collections import Counter
from pathlib import Path


LOG_FILE = Path("sample_auth.log")
REPORT_DIRECTORY = Path("reports")
REPORT_FILE = REPORT_DIRECTORY / "security_report.csv"

FAILED_LOGIN_LIMIT = 3

FAILED_LOGIN_PATTERN = re.compile(
    r"LOGIN_FAILED\s+user=(?P<username>\S+)\s+ip=(?P<ip>\S+)"
)


def read_failed_logins(log_file: Path) -> list[dict[str, str]]:
    """Read the log file and return all failed-login events."""

    failed_logins = []

    try:
        with log_file.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                match = FAILED_LOGIN_PATTERN.search(line)

                if match:
                    failed_logins.append(
                        {
                            "line_number": str(line_number),
                            "username": match.group("username"),
                            "ip_address": match.group("ip"),
                        }
                    )

    except FileNotFoundError:
        print(f"Error: Could not find {log_file}.")
        return []

    return failed_logins


def count_failures_by_ip(events: list[dict[str, str]]) -> Counter:
    """Count the number of failed logins from each IP address."""

    return Counter(event["ip_address"] for event in events)


def determine_status(failure_count: int) -> str:
    """Assign a status based on the number of failed attempts."""

    if failure_count >= FAILED_LOGIN_LIMIT:
        return "SUSPICIOUS"

    return "NORMAL"


def create_report(failure_counts: Counter) -> None:
    """Export the analysis results to a CSV report."""

    REPORT_DIRECTORY.mkdir(exist_ok=True)

    with REPORT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(
            ["IP Address", "Failed Login Attempts", "Status"]
        )

        for ip_address, count in failure_counts.most_common():
            writer.writerow(
                [
                    ip_address,
                    count,
                    determine_status(count),
                ]
            )


def display_results(failure_counts: Counter) -> None:
    """Print the results in a readable format."""

    print("\nSECURITY LOG ANALYSIS")
    print("-" * 50)

    if not failure_counts:
        print("No failed login attempts were found.")
        return

    for ip_address, count in failure_counts.most_common():
        status = determine_status(count)

        print(
            f"IP: {ip_address:<16} "
            f"Failures: {count:<3} "
            f"Status: {status}"
        )


def main() -> None:
    failed_logins = read_failed_logins(LOG_FILE)

    if not failed_logins:
        return

    failure_counts = count_failures_by_ip(failed_logins)

    display_results(failure_counts)
    create_report(failure_counts)

    print(f"\nReport created: {REPORT_FILE}")


if __name__ == "__main__":
    main()
