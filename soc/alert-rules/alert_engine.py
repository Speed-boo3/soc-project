import json
import yaml
import argparse
from collections import defaultdict
from datetime import datetime, timedelta


def load_rules(rules_file):
    with open(rules_file, "r") as f:
        data = yaml.safe_load(f)
    return data["rules"]


def load_logs(log_file):
    with open(log_file, "r") as f:
        return json.load(f)


def match_rule(rule, entry):
    condition = rule["condition"]
    field = condition.get("field")
    value = str(entry.get(field, "")).lower()
    if "contains" in condition:
        return condition["contains"].lower() in value
    if "equals" in condition:
        return value == condition["equals"].lower()
    return False


def run_engine(logs, rules):
    triggered = []
    counts = defaultdict(int)
    ip_counts = defaultdict(int)

    for entry in logs:
        ip = entry.get("ip") or ""
        msg = entry.get("message") or ""
        if "failed password" in msg.lower() or "invalid user" in msg.lower():
            parts = msg.lower().split("from ")
            if len(parts) > 1:
                candidate = parts[1].split()[0]
                if candidate.count(".") == 3:
                    ip_counts[candidate] += 1

        for rule in rules:
            if entry.get("type") == rule.get("log_type"):
                if match_rule(rule, entry):
                    counts[rule["id"]] += 1
                    threshold = rule["condition"].get("threshold", 1)
                    if counts[rule["id"]] >= threshold:
                        triggered.append({
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "action": rule["action"],
                            "mitre": rule.get("mitre", {}),
                            "matched_entry": entry,
                            "threshold_hit": counts[rule["id"]],
                        })

    for ip, count in ip_counts.items():
        if count >= 3:
            triggered.append({
                "rule_id": "RULE-BF",
                "rule_name": "Brute Force Detected",
                "severity": "high",
                "action": "alert",
                "mitre": {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
                "matched_entry": {"type": "auth", "message": f"Source IP {ip} had {count} failed login attempts"},
                "threshold_hit": count,
            })

    return triggered


def print_alerts(alerts, output_file=None):
    if not alerts:
        print("No alerts triggered.")
        return

    lines = [f"\n{len(alerts)} alert(s) triggered:\n"]
    seen = set()
    for a in alerts:
        key = a["rule_id"] + str(a["matched_entry"].get("message", ""))
        if key in seen:
            continue
        seen.add(key)
        mitre = a.get("mitre", {})
        lines.append(f"[{a['severity'].upper()}] {a['rule_name']} ({a['rule_id']})")
        if mitre:
            lines.append(f"  MITRE ATT&CK : {mitre.get('technique_id')} - {mitre.get('technique_name')} ({mitre.get('tactic')})")
        lines.append(f"  Action       : {a['action']}")
        msg = a["matched_entry"].get("message") or a["matched_entry"].get("request") or a["matched_entry"].get("raw")
        lines.append(f"  Log entry    : {msg}")
        lines.append("")

    output = "\n".join(lines)
    print(output)

    if output_file:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(output_file, "a") as f:
            f.write(f"\n=== Run: {ts} ===\n")
            f.write(output)
        print(f"Alerts appended to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Run detection rules against parsed logs")
    parser.add_argument("--logs", required=True, help="Path to parsed JSON log file")
    parser.add_argument("--rules", required=True, help="Path to rules YAML file")
    parser.add_argument("--output", help="Append alerts to this log file")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    logs = load_logs(args.logs)
    alerts = run_engine(logs, rules)
    print_alerts(alerts, output_file=args.output)


if __name__ == "__main__":
    main()
