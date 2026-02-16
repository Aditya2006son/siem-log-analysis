import argparse
import json
from .cleaner import clean_logs


def main():
    parser = argparse.ArgumentParser(description="SIEM Log Cleaner (sort + quarantine bad logs)")
    parser.add_argument("--input", required=True, help="Path to input log file")
    parser.add_argument("--format", required=True, choices=["syslog", "jsonl"], help="Input format")
    parser.add_argument("--outdir", required=True, help="Output directory")

    args = parser.parse_args()
    summary = clean_logs(args.input, args.format, args.outdir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
