import json
import os
import argparse
import urllib.request
import urllib.error


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

CATEGORY_NAMES = {
    "1": "DNS Compromise", "2": "DNS Poisoning", "3": "Fraud Orders",
    "4": "DDoS Attack", "5": "FTP Brute-Force", "6": "Ping of Death",
    "7": "Phishing", "8": "Fraud VoIP", "9": "Open Proxy",
    "10": "Web Spam", "11": "Email Spam", "12": "Blog Spam",
    "13": "VPN IP", "14": "Port Scan", "15": "Hacking",
    "16": "SQL Injection", "17": "Spoofing", "18": "Brute Force",
    "19": "Bad Web Bot", "20": "Exploited Host", "21": "Web App Attack",
    "22": "SSH", "23": "IoT Targeted",
}


def get_unique_ips(logs):
    ips = set()
    for entry in logs:
        ip = entry.get("ip")
        if ip and ip not in ("", "-"):
            ips.add(ip)
        msg = entry.get("message", "")
        parts = msg.split("from ")
        if len(parts) > 1:
            candidate = parts[1].split()[0]
            if candidate.count(".") == 3:
                ips.add(candidate)
    return ips


def check_ip(ip, api_key):
    req = urllib.request.Request(
        ABUSEIPDB_URL + "?ipAddress=" + ip + "&maxAgeInDays=90&verbose",
        headers={"Key": api_key, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": str(e)}


def print_results(results):
    print(f"\nThreat Intel Results — {len(results)} IP(s) checked\n")
    print(f"{'IP':<20} {'Score':>6}  {'Reports':>8}  {'Categories'}")
    print("-" * 70)
    for ip, data in results.items():
        if "error" in data:
            print(f"{ip:<20}  Error: {data['error']}")
            continue
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        categories = d.get("usageType", "Unknown")
        flag = " ⚠" if score > 50 else ""
        print(f"{ip:<20} {score:>6}%  {reports:>8}  {categories}{flag}")


def main():
    parser = argparse.ArgumentParser(description="Check IPs from parsed logs against AbuseIPDB")
    parser.add_argument("--logs", required=True, help="Path to parsed JSON log file")
    args = parser.parse_args()

    api_key = os.environ.get("ABUSEIPDB_KEY")
    if not api_key:
        print("Error: ABUSEIPDB_KEY environment variable not set.")
        print("Get a free key at https://www.abuseipdb.com/register")
        return

    with open(args.logs, "r") as f:
        logs = json.load(f)

    ips = get_unique_ips(logs)
    if not ips:
        print("No IPs found in logs.")
        return

    print(f"Checking {len(ips)} IP(s)...")
    results = {}
    for ip in ips:
        results[ip] = check_ip(ip, api_key)

    print_results(results)


if __name__ == "__main__":
    main()
