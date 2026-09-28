from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, current_user

from models import db, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("queue"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("queue"))
        flash("Invalid credentials", "error")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


def seed_admin(app):
    from config import Config
    with app.app_context():
        if not User.query.filter_by(username=Config.ADMIN_USERNAME).first():
            u = User(username=Config.ADMIN_USERNAME)
            u.set_password(Config.ADMIN_PASSWORD)
            db.session.add(u)
            db.session.commit()