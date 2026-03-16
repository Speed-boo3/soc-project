import re
import json
import argparse

PATTERNS = {
    "syslog": re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
    ),
    "apache": re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'
    ),
    "auth": re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<service>sshd|sudo|login)\[?\d*\]?:\s+(?P<message>.+)'
    ),
}

SUSPICIOUS_KEYWORDS = [
    "failed password",
    "invalid user",
    "authentication failure",
    "permission denied",
    "sudo: pam_unix",
    "segfault",
]


def detect_log_type(line):
    for name, pattern in PATTERNS.items():
        if pattern.match(line):
            return name
    return "unknown"


def parse_line(line):
    line = line.strip()
    log_type = detect_log_type(line)
    pattern = PATTERNS.get(log_type)
    if not pattern:
        return {"raw": line, "type": "unknown", "suspicious": False}
    match = pattern.match(line)
    if not match:
        return {"raw": line, "type": log_type, "suspicious": False}
    entry = match.groupdict()
    entry["type"] = log_type
    entry["suspicious"] = any(kw in line.lower() for kw in SUSPICIOUS_KEYWORDS)
    return entry


def parse_file(filepath):
    results = []
    with open(filepath, "r") as f:
        for line in f:
            if line.strip():
                results.append(parse_line(line))
    return results


def print_summary(entries):
    total = len(entries)
    suspicious = [e for e in entries if e.get("suspicious")]
    types = {}
    for e in entries:
        t = e.get("type", "unknown")
        types[t] = types.get(t, 0) + 1
    print(f"\nTotal log entries : {total}")
    print(f"Suspicious events : {len(suspicious)}")
    print(f"Log types         : {json.dumps(types, indent=2)}")
    if suspicious:
        print("\n--- Suspicious entries ---")
        for e in suspicious:
            print(f"  [{e.get('type')}] {e.get('message') or e.get('request') or e.get('raw')}")


def main():
    parser = argparse.ArgumentParser(description="Parse and analyze log files")
    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--output", help="Save parsed output as JSON")
    args = parser.parse_args()
    entries = parse_file(args.file)
    print_summary(entries)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(entries, f, indent=2)
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
