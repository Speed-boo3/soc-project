import json
import yaml
import argparse
from collections import defaultdict


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
    for entry in logs:
        for rule in rules:
            if entry.get("type") == rule.get("log_type"):
                if match_rule(rule, entry):
                    counts[rule["id"]] += 1
                    if counts[rule["id"]] >= rule["condition"].get("threshold", 1):
                        triggered.append({
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "action": rule["action"],
                            "mitre": rule.get("mitre", {}),
                            "matched_entry": entry,
                        })
    return triggered


def print_alerts(alerts):
    if not alerts:
        print("No alerts triggered.")
        return
    print(f"\n{len(alerts)} alert(s) triggered:\n")
    for a in alerts:
        mitre = a.get("mitre", {})
        print(f"[{a['severity'].upper()}] {a['rule_name']} ({a['rule_id']})")
        if mitre:
            print(f"  MITRE ATT&CK : {mitre.get('technique_id')} – {mitre.get('technique_name')} ({mitre.get('tactic')})")
        print(f"  Action       : {a['action']}")
        msg = a["matched_entry"].get("message") or a["matched_entry"].get("request") or a["matched_entry"].get("raw")
        print(f"  Log entry    : {msg}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Run detection rules against parsed logs")
    parser.add_argument("--logs", required=True, help="Path to parsed JSON log file")
    parser.add_argument("--rules", required=True, help="Path to rules YAML file")
    args = parser.parse_args()
    rules = load_rules(args.rules)
    logs = load_logs(args.logs)
    alerts = run_engine(logs, rules)
    print_alerts(alerts)


if __name__ == "__main__":
    main()
