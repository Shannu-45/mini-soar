# Mini-SOAR

A self-contained blue-team platform built in Python/Flask that generates
synthetic Windows Event Log-style events, detects suspicious behaviour with a
7-rule MITRE ATT&CK-mapped engine, enriches alerts with real threat intelligence
(AbuseIPDB, VirusTotal), scores risk 0-100, and gives analysts a triage queue
with a feedback loop.

## Features

- 7 detection rules mapped to MITRE ATT&CK
- In-memory sliding-window correlation
- Threat-intel enrichment: AbuseIPDB, VirusTotal (IP + file hash), GeoIP, Shodan
- Weighted 0-100 risk score with Low / Medium / High / Critical verdict
- Analyst feedback loop that down-weights confirmed false positives
- Flask analyst queue, incident report page, Chart.js analytics dashboard
- MITRE ATT&CK coverage page
- JSON / CSV export
- APScheduler background event generator
- Flask-Login analyst authentication
- Docker + Gunicorn + Render / Fly.io deploy configs

## Stack

Python · Flask · SQLAlchemy · SQLite · Chart.js · Docker · APScheduler

## Run locally

```bash
pip install -r requirements.txt
cp .env.example .env
python app.py
