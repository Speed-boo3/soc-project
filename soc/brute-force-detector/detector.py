import re
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

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
                ts_str, ip = match.groups()
                try:
                    ts = datetime.strptime(ts_str.strip(), TIME_FORMAT).replace(year=datetime.now().year)
                    attempts[ip].append(ts)
                except ValueError:
                    attempts[ip].append(datetime.now())
    return attempts


def detect(attempts, threshold, window_seconds):
    flagged = {}
    for ip, timestamps in attempts.items():
        if not timestamps:
            continue
        timestamps_sorted = sorted(timestamps)
        max_in_window = 0
        for i, start in enumerate(timestamps_sorted):
            window_end = start + timedelta(seconds=window_seconds)
            count_in_window = sum(1 for t in timestamps_sorted[i:] if t <= window_end)
            if count_in_window > max_in_window:
                max_in_window = count_in_window
        if max_in_window >= threshold:
            flagged[ip] = {"count": len(timestamps), "max_in_window": max_in_window}
    return flagged


def print_report(flagged, threshold, window):
    print("\nBrute Force Detection Report")
    print("=" * 60)
    print(f"Threshold : {threshold} attempts within {window} seconds\n")
    if not flagged:
        print("No brute force activity detected.")
        return
    print("FLAGGED IPs:")
    for ip, data in sorted(flagged.items(), key=lambda x: x[1]["max_in_window"], reverse=True):
        status = "BLOCK RECOMMENDED" if data["max_in_window"] >= threshold * 2 else "MONITOR"
        print(f"  {ip:<20} {data['max_in_window']} in window / {data['count']} total   {status}")


def main():
    parser = argparse.ArgumentParser(description="Detect brute force attempts from auth logs")
    parser.add_argument("--file", required=True, help="Path to auth log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempt threshold")
    parser.add_argument("--window", type=int, default=300, help="Time window in seconds")
    args = parser.parse_args()

    attempts = parse_attempts(args.file)
    flagged = detect(attempts, args.threshold, args.window)
    print_report(flagged, args.threshold, args.window)


if __name__ == "__main__":
    main()
