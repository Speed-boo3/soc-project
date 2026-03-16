import json
import argparse
import os
from collections import Counter


def load_logs(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


def bar(value, max_value, width=25):
    filled = int((value / max_value) * width) if max_value else 0
    return "█" * filled + "░" * (width - filled)


def print_dashboard(entries):
    os.system("clear")
    total = len(entries)
    suspicious = [e for e in entries if e.get("suspicious")]
    types = Counter(e.get("type", "unknown") for e in entries)
    ips = Counter(e.get("ip") for e in entries if e.get("ip")).most_common(5)
    codes = Counter(e.get("status") for e in entries if e.get("status")).most_common(5)

    print("=" * 55)
    print("           SOC DASHBOARD")
    print("=" * 55)
    print(f"\n  Total log entries  : {total}")
    print(f"  Suspicious events  : {len(suspicious)}")

    print("\n  Log types:")
    max_t = max(types.values(), default=1)
    for t, c in types.items():
        print(f"    {t:<12} {bar(c, max_t)} {c}")

    if ips:
        print("\n  Top source IPs:")
        max_ip = max(c for _, c in ips)
        for ip, c in ips:
            print(f"    {ip:<18} {bar(c, max_ip, 15)} {c}")

    if codes:
        print("\n  HTTP status codes:")
        max_c = max(c for _, c in codes)
        for code, c in codes:
            print(f"    {code:<6} {bar(c, max_c, 15)} {c}")

    if suspicious:
        print("\n  Recent suspicious events:")
        for e in suspicious[-5:]:
            msg = e.get("message") or e.get("request") or e.get("raw", "")
            print(f"    [{e.get('type')}] {msg[:55]}")

    print("\n" + "=" * 55)


def main():
    parser = argparse.ArgumentParser(description="Terminal dashboard for parsed log data")
    parser.add_argument("--logs", required=True, help="Path to parsed JSON log file")
    args = parser.parse_args()
    entries = load_logs(args.logs)
    print_dashboard(entries)


if __name__ == "__main__":
    main()
