import requests

from config import Config

TIMEOUT = 5


def _base(ip):
    return {
        "abuse_score": 0,
        "total_reports": 0,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "country": "Unknown",
        "country_code": "??",
        "city": "Unknown",
        "isp": "Unknown",
        "shodan_ports": [],
        "shodan_org": "",
        "source": "mock",
    }


def _geoip(ip):
    try:
        r = requests.get("http://ip-api.com/json/" + ip, timeout=TIMEOUT)
        if r.ok:
            d = r.json()
            return {
                "country": d.get("country", "Unknown"),
                "country_code": d.get("countryCode", "??"),
                "city": d.get("city", "Unknown"),
                "isp": d.get("isp", "Unknown"),
            }
    except Exception:
        pass
    return {}


def _abuseipdb(ip):
    if not Config.ABUSEIPDB_API_KEY:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": Config.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        if r.ok:
            d = r.json()["data"]
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
            }
    except Exception:
        pass
    return {}


def _virustotal_ip(ip):
    if not Config.VIRUSTOTAL_API_KEY:
        return {}
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
            headers={"x-apikey": Config.VIRUSTOTAL_API_KEY},
            timeout=TIMEOUT,
        )
        if r.ok:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
            }
    except Exception:
        pass
    return {}


def _virustotal_file(file_hash):
    if not Config.VIRUSTOTAL_API_KEY or not file_hash:
        return {}
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/files/" + file_hash,
            headers={"x-apikey": Config.VIRUSTOTAL_API_KEY},
            timeout=TIMEOUT,
        )
        if r.ok:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_file_malicious": stats.get("malicious", 0),
                "vt_file_suspicious": stats.get("suspicious", 0),
            }
    except Exception:
        pass
    return {}


def _shodan(ip):
    if not Config.SHODAN_API_KEY:
        return {}
    try:
        r = requests.get(
            "https://api.shodan.io/shodan/host/" + ip,
            params={"key": Config.SHODAN_API_KEY},
            timeout=TIMEOUT,
        )
        if r.ok:
            d = r.json()
            return {
                "shodan_ports": d.get("ports", [])[:10],
                "shodan_org": d.get("org", ""),
            }
    except Exception:
        pass
    return {}


def enrich(ip, file_hash=None):
    data = _base(ip)
    data.update(_geoip(ip))
    data.update(_abuseipdb(ip))
    data.update(_virustotal_ip(ip))
    data.update(_shodan(ip))
    if file_hash:
        data.update(_virustotal_file(file_hash))
    if Config.ABUSEIPDB_API_KEY or Config.VIRUSTOTAL_API_KEY:
        data["source"] = "live"
    return data