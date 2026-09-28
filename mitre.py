MITRE_MAP = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.004": {
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Adversaries may use credentials obtained from breach dumps to gain access.",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.002": {
        "name": "Domain Accounts",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Adversaries may use domain account credentials for access.",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows Event Logs to hide activity.",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
    },
    "T1136.001": {
        "name": "Create Local Account",
        "tactic": "Persistence",
        "description": "Adversaries may create local accounts to maintain access.",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
    },
}