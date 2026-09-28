from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_id = db.Column(db.Integer, index=True)
    source_ip = db.Column(db.String(45), index=True)
    username = db.Column(db.String(100), index=True)
    hostname = db.Column(db.String(100))
    event_type = db.Column(db.String(50))
    file_hash = db.Column(db.String(64))
    raw = db.Column(db.Text)

    alerts = db.relationship(
        "Alert", backref="event", lazy=True, cascade="all, delete-orphan"
    )


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), index=True)
    rule_name = db.Column(db.String(100), index=True)
    mitre_technique = db.Column(db.String(50))
    base_score = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    verdict = db.Column(db.String(20), index=True)
    recommended_action = db.Column(db.String(255))
    enrichment = db.Column(db.Text)
    status = db.Column(db.String(20), default="open", index=True)
    feedback = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class RuleFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(100), index=True)
    source_ip = db.Column(db.String(45), index=True)
    is_true_positive = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)