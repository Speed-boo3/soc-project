import re
import argparse
from collections import defaultdict
from datetime import datetime


LOG_PATTERN = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*(?:Failed password|Invalid user).*from (\d+\.\d+\.\d+\.\d+)'
)

TIME_FORMAT = "%b %d %H:%M:%S"


def parse_attempts(filepath):
    attempts = defaultdict(list)
    with open(filepath, "r") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                timestamp_str, ip = match.groups()
                try:
                    ts = datetime.strptime(timestamp_str.strip(), TIME_FORMAT)
                    attempts[ip].append(ts)
                except ValueError:
                    attempts[ip].append(None)
    return attempts


def detect(attempts, threshold, window_seconds):
    flagged = {}
    for ip, timestamps in attempts.items():
        valid = [t for t in timestamps if t is not None]
        total = len(timestamps)
        if total >= threshold:
            flagged[ip] = total
    return flagged


def print_report(flagged, threshold, window):
    print("\nBrute Force Detection Report")
    print("=" * 60)
    print(f"Threshold : {threshold} failed attempts within {window} seconds\n")
    if not flagged:
        print("No brute force activity detected.")
        return
    print("FLAGGED IPs:")
    for ip, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
        status = "BLOCK RECOMMENDED" if count >= threshold * 2 else "MONITOR"
        print(f"  {ip:<20} {count} attempts   {status}")


def main():
    parser = argparse.ArgumentParser(description="Detect brute force attempts from auth logs")
    parser.add_argument("--file", required=True, help="Path to auth log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempt threshold")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    args = parser.parse_args()

    attempts = parse_attempts(args.file)
    flagged = detect(attempts, args.threshold, args.window)
    print_report(flagged, args.threshold, args.window)


if __name__ == "__main__":
    main()
