import csv
import io
import json

from flask import Blueprint, Response
from flask_login import login_required

from models import Alert

export_bp = Blueprint("export", __name__)


def _alerts_as_dicts():
    rows = []
    for a in Alert.query.order_by(Alert.created_at.desc()).all():
        rows.append({
            "id": a.id,
            "created_at": a.created_at.isoformat(),
            "rule_name": a.rule_name,
            "mitre_technique": a.mitre_technique,
            "risk_score": a.risk_score,
            "verdict": a.verdict,
            "recommended_action": a.recommended_action,
            "status": a.status,
            "feedback": a.feedback,
            "source_ip": a.event.source_ip,
            "username": a.event.username,
            "hostname": a.event.hostname,
            "event_id": a.event.event_id,
            "enrichment": json.loads(a.enrichment) if a.enrichment else {},
        })
    return rows


@export_bp.route("/export/alerts.json")
@login_required
def export_json():
    payload = json.dumps(_alerts_as_dicts(), indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=alerts.json"},
    )


@export_bp.route("/export/alerts.csv")
@login_required
def export_csv():
    rows = _alerts_as_dicts()
    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for r in rows:
            r = dict(r)
            r["enrichment"] = json.dumps(r["enrichment"])
            writer.writerow(r)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )