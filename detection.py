from correlation import SlidingWindow

FAILED_WINDOW = SlidingWindow(300)          # 5 minutes
FAILED_USERS_WINDOW = SlidingWindow(300)    # 5 minutes
SUCCESS_WINDOW = SlidingWindow(600)         # 10 minutes

RULES = {
    "Brute Force":             {"mitre": "T1110",     "base": 70},
    "Credential Stuffing":     {"mitre": "T1110.004", "base": 75},
    "Valid Account Abuse":     {"mitre": "T1078",     "base": 80},
    "Audit Log Tampering":     {"mitre": "T1070.001", "base": 90},
    "New Account Creation":    {"mitre": "T1136.001", "base": 50},
    "Service Account Anomaly": {"mitre": "T1078.002", "base": 65},
    "Off-Hours Login":         {"mitre": "T1078",     "base": 40},
}


def detect(event):
    alerts = []
    ip = event.source_ip
    user = event.username or ""

    # Feed the windows first so counts include the current event
    if event.event_id == 4625:
        FAILED_WINDOW.add("failed:" + ip)
        FAILED_USERS_WINDOW.add("failed_users:" + ip, value=user)
    if event.event_id == 4624:
        SUCCESS_WINDOW.add("success:" + ip)

    # 1. Brute Force - 5+ failed logons from one IP within 5 minutes
    if event.event_id == 4625 and FAILED_WINDOW.count("failed:" + ip) >= 5:
        alerts.append(("Brute Force", RULES["Brute Force"]))

    # 2. Credential Stuffing - 3+ distinct usernames from one IP in 5 minutes
    if event.event_id == 4625 and FAILED_USERS_WINDOW.distinct("failed_users:" + ip) >= 3:
        alerts.append(("Credential Stuffing", RULES["Credential Stuffing"]))

    # 3. Valid Account Abuse - success right after 3+ failures in 10 minutes
    if event.event_id == 4624 and FAILED_WINDOW.count("failed:" + ip) >= 3:
        alerts.append(("Valid Account Abuse", RULES["Valid Account Abuse"]))

    # 4. Audit Log Tampering
    if event.event_id == 1102:
        alerts.append(("Audit Log Tampering", RULES["Audit Log Tampering"]))

    # 5. New Account Creation
    if event.event_id == 4720:
        alerts.append(("New Account Creation", RULES["New Account Creation"]))

    # 6. Service Account Anomaly
    if event.event_id == 4624 and user:
        is_svc = user.startswith("svc_") or user.startswith("service")
        off_hours = event.timestamp.hour < 8 or event.timestamp.hour > 18
        external = not ip.startswith("10.")
        if is_svc and (off_hours or external):
            alerts.append(("Service Account Anomaly", RULES["Service Account Anomaly"]))

    # 7. Off-Hours Login
    if event.event_id == 4624 and (event.timestamp.hour < 9 or event.timestamp.hour >= 18):
        alerts.append(("Off-Hours Login", RULES["Off-Hours Login"]))

    return alerts