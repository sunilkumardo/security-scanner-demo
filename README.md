# GitHub Security Alert Scanner

A Python automation tool that fetches and triages security alerts 
from GitHub Advanced Security (GHAS) using the GitHub REST API.

## What it does
- Fetches CodeQL code scanning alerts from a GitHub repository
- Fetches secret scanning alerts
- Triages alerts by severity: Critical / High / Medium / Low
- Filters dismissed/skipped alerts separately
- Saves a structured JSON report automatically

## Tech Stack
- Python 3
- GitHub REST API
- GitHub Advanced Security (GHAS) — CodeQL, Secret Scanning

## How to Run

1. Clone the repo
   git clone https://github.com/sunilkumardo/security-scanner-demo.git

2. Install dependency
   pip install requests

3. Set your GitHub token as environment variable
   Windows: set GITHUB_TOKEN=your_token_here

4. Run the scanner
   python scanner.py

## Sample Output

GITHUB SECURITY ALERT TRIAGE REPORT
Repo  : sunilkumardo/security-scanner-demo
Date  : 2026-05-18 03:27

[SUMMARY] Total Active Alerts: 2  |  Skipped/Dismissed: 0

  [HIGH] — 2 alert(s)
    > Rule    : py/clear-text-logging-sensitive-data
      Details : Clear-text logging of sensitive information
      File    : scanner.py  (Line 108)

  [SECRET SCANNING] — 1 secret(s) found!
    > Type  : GitHub Personal Access Token
      State : resolved

## Why I built this
Built as hands-on practice during my cybersecurity learning at 
IISc Bangalore (CySeck Program). This mirrors real GHAS automation 
workflows used by Application Security Engineering teams.