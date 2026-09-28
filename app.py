import json

from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func

from config import Config
from extensions import db, login_manager
from models import Event, Alert, RuleFeedback, User
from detection import detect
from enrichment import enrich
from risk import calculate_risk, get_verdict, get_recommended_action
from generator import generate_event
from mitre import MITRE_MAP
from auth import auth_bp, seed_admin
from export import export_bp
from tasks import start_scheduler

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "auth.login"

app.register_blueprint(auth_bp)
app.register_blueprint(export_bp)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ------------------------------------------------------------- core pipeline

def process_event(event):
    detected = detect(event)
    for rule_name, meta in detected:
        enrichment = enrich(event.source_ip, event.file_hash)
        risk = calculate_risk(meta["base"], enrichment, rule_name, event.source_ip)
        verdict = get_verdict(risk)

        alert = Alert(
            event_id=event.id,
            rule_name=rule_name,
            mitre_technique=meta["mitre"],
            base_score=meta["base"],
            risk_score=risk,
            verdict=verdict,
            recommended_action=get_recommended_action(verdict),
            enrichment=json.dumps(enrichment),
        )
        db.session.add(alert)
    db.session.commit()


# ------------------------------------------------------------------- routes

@app.route("/")
@login_required
def index():
    return redirect(url_for("queue"))


@app.route("/queue")
@login_required
def queue():
    status = request.args.get("status", "all")
    q = Alert.query
    if status in ("open", "closed"):
        q = q.filter_by(status=status)
    alerts = q.order_by(Alert.created_at.desc()).limit(200).all()
    return render_template("queue.html", alerts=alerts, status=status)


@app.route("/alert/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    enrichment = json.loads(alert.enrichment) if alert.enrichment else {}
    mitre = MITRE_MAP.get(alert.mitre_technique, {})
    return render_template(
        "alert.html", alert=alert, enrichment=enrichment, mitre=mitre
    )


@app.route("/feedback/<int:alert_id>", methods=["POST"])
@login_required
def feedback(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    is_tp = request.form.get("feedback") == "true_positive"

    alert.status = "closed"
    alert.feedback = "true_positive" if is_tp else "false_positive"

    db.session.add(RuleFeedback(
        rule_name=alert.rule_name,
        source_ip=alert.event.source_ip,
        is_true_positive=is_tp,
    ))
    db.session.commit()
    return redirect(url_for("queue"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/mitre")
@login_required
def mitre_page():
    counts = dict(
        db.session.query(Alert.mitre_technique, func.count(Alert.id))
        .group_by(Alert.mitre_technique)
        .all()
    )
    return render_template("mitre.html", mitre=MITRE_MAP, counts=counts)


@app.route("/api/stats")
@login_required
def stats():
    verdicts = dict(
        db.session.query(Alert.verdict, func.count(Alert.id))
        .group_by(Alert.verdict).all()
    )
    rules = dict(
        db.session.query(Alert.rule_name, func.count(Alert.id))
        .group_by(Alert.rule_name).all()
    )
    ips = dict(
        db.session.query(Event.source_ip, func.count(Alert.id))
        .join(Alert)
        .group_by(Event.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10).all()
    )
    return jsonify({"verdicts": verdicts, "rules": rules, "ips": ips})


@app.route("/generate")
@login_required
def generate():
    event = generate_event()
    process_event(event)
    return redirect(url_for("queue"))


# ---------------------------------------------------------------- bootstrap

def bootstrap():
    with app.app_context():
        db.create_all()
    seed_admin(app)
    start_scheduler(app)


bootstrap()

if __name__ == "__main__":
    # use_reloader=False so the scheduler does not start twice
    app.run(debug=True, use_reloader=False)