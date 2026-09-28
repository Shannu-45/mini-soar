from models import RuleFeedback


def calculate_risk(base_score, enrichment, rule_name, source_ip):
    abuse = enrichment.get("abuse_score", 0)
    vt_mal = enrichment.get("vt_malicious", 0)
    vt_sus = enrichment.get("vt_suspicious", 0)
    vtf_mal = enrichment.get("vt_file_malicious", 0)
    vtf_sus = enrichment.get("vt_file_suspicious", 0)

    score = (
        base_score
        + abuse * 0.3
        + vt_mal * 5
        + vt_sus * 2
        + vtf_mal * 6
        + vtf_sus * 3
    )

    # Analyst feedback loop: down-weight confirmed false-positive patterns
    fps = RuleFeedback.query.filter_by(
        rule_name=rule_name, source_ip=source_ip, is_true_positive=False
    ).count()
    tps = RuleFeedback.query.filter_by(
        rule_name=rule_name, source_ip=source_ip, is_true_positive=True
    ).count()

    adjustment = min(fps * 5, 40) - min(tps * 5, 20)
    score = max(0, min(100, score - adjustment))
    return int(score)


def get_verdict(score):
    if score <= 25:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


def get_recommended_action(verdict):
    actions = {
        "Low": "Monitor and log. No immediate action.",
        "Medium": "Investigate source IP and user activity. Consider temporary block.",
        "High": "Block source IP, reset affected credentials, escalate to SOC lead.",
        "Critical": "Immediate isolation, block IP, reset credentials, initiate incident response.",
    }
    return actions.get(verdict, "Investigate.")