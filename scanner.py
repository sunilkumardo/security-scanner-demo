import requests
import json
from datetime import datetime
import os


# ─── CONFIG ───────────────────────────────────────────
##GITHUB_TOKEN = "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"   # we will fill this next
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
OWNER        = "sunilkumardo"
REPO         = "security-scanner-demo"
# ──────────────────────────────────────────────────────

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "error", "unknown"]

def fetch_code_scanning_alerts():
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/code-scanning/alerts"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Could not fetch alerts: {e}")
        return []
    except requests.exceptions.ConnectionError:
        print("[ERROR] No internet connection.")
        return []

def fetch_secret_scanning_alerts():
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/secret-scanning/alerts"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Secret scanning not available: {e}")
        return []

def triage_alerts(alerts):
    report = {s: [] for s in SEVERITY_ORDER}
    skipped = []

    for alert in alerts:
        state     = alert.get("state", "")
        severity  = alert.get("rule", {}).get("severity", "unknown").lower()
        rule_id   = alert.get("rule", {}).get("id", "Unknown Rule")
        rule_desc = alert.get("rule", {}).get("description", "No description")
        location  = alert.get("most_recent_instance", {}).get("location", {})
        file_path = location.get("path", "N/A")
        line      = location.get("start_line", "N/A")

        if state == "dismissed":
            skipped.append({
                "rule": rule_id,
                "reason": alert.get("dismissed_reason", "No reason given")
            })
            continue

        entry = {
            "rule": rule_id,
            "description": rule_desc,
            "file": file_path,
            "line": line
        }

        if severity in report:
            report[severity].append(entry)
        else:
            report["unknown"].append(entry)

    return report, skipped

def print_report(report, skipped, secret_alerts):
    print("\n" + "="*60)
    print("   GITHUB SECURITY ALERT TRIAGE REPORT")
    print(f"   Repo  : {OWNER}/{REPO}")
    print(f"   Date  : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("="*60)

    total = sum(len(v) for v in report.values())
    print(f"\n[SUMMARY] Total Active Alerts: {total}  |  Skipped/Dismissed: {len(skipped)}\n")

    for severity in SEVERITY_ORDER:
        alerts = report[severity]
        if not alerts:
            continue
        print(f"  [{severity.upper()}] — {len(alerts)} alert(s)")
        for a in alerts:
            print(f"    > Rule    : {a['rule']}")
            print(f"      Details : {a['description']}")
            print(f"      File    : {a['file']}  (Line {a['line']})")
            print()

    if skipped:
        print(f"  [SKIPPED/DISMISSED] — {len(skipped)} alert(s)")
        for s in skipped:
            print(f"    > Rule   : {s['rule']}")
            print(f"      Reason : {s['reason']}")
        print()

    if secret_alerts:
        print(f"  [SECRET SCANNING] — {len(secret_alerts)} secret(s) found!")
        for s in secret_alerts:
            print(f"    > Type  : {s.get('secret_type_display_name', 'Unknown')}")
            print(f"      State : {s.get('state', 'N/A')}")
        print()

    print("="*60)
    print("  Scan complete.")
    print("="*60 + "\n")

def save_report(report, skipped):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    data = {"alerts": report, "skipped": skipped}
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Report saved to {filename}")

if __name__ == "__main__":
    print("[INFO] Fetching code scanning alerts...")
    alerts = fetch_code_scanning_alerts()

    print("[INFO] Fetching secret scanning alerts...")
    secret_alerts = fetch_secret_scanning_alerts()

    print("[INFO] Triaging alerts...")
    report, skipped = triage_alerts(alerts)

    print_report(report, skipped, secret_alerts)
    save_report(report, skipped)