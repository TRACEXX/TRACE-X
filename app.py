"""
TRACE X application factory.

create_app() builds the Flask app, registers the blueprints in routes/,
adds security protections, and creates + seeds the SQLite database the
first time the app runs.

Run it with:   python run.py        (or: flask --app app run)
"""

import hmac
import os
import secrets

from flask import Flask, abort, render_template, request, session

from config import Config
from database.db import close_db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    for folder in (os.path.dirname(app.config["DATABASE"]), app.config["EVIDENCE_DIR"],
                   app.config["REPORTS_DIR"], app.config["TEMP_DIR"]):
        os.makedirs(folder, exist_ok=True)

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_or_create_secret(os.path.dirname(app.config["DATABASE"]))

    app.teardown_appcontext(close_db)
    _register_blueprints(app)
    _register_template_helpers(app)
    _register_security(app)
    _register_error_handlers(app)

    # First run: create the tables and load the fictional sample data.
    if not os.path.exists(app.config["DATABASE"]):
        from database.seed import seed_database
        with app.app_context():
            seed_database()
    return app


def _load_or_create_secret(folder):
    """Keep one random secret key per installation (instance/secret_key.txt)."""
    path = os.path.join(folder, "secret_key.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(key)
    return key


def _register_blueprints(app):
    from routes import admin, ai, auth, cases, detectives, evidence, reports
    for module in (auth, admin, detectives, cases, evidence, reports, ai):
        app.register_blueprint(module.bp)


def _register_template_helpers(app):
    from database.queries import suspect_code, witness_code
    from routes.auth import current_user, is_admin

    def filesize(num):
        num = num or 0
        for unit in ("bytes", "KB", "MB", "GB"):
            if num < 1024 or unit == "GB":
                return f"{num:,.0f} {unit}" if unit == "bytes" else f"{num:,.1f} {unit}"
            num /= 1024

    def slug(text):
        return (text or "").lower().replace(" ", "-")

    def initials(name):
        return "".join(part[0] for part in (name or "?").split()[:2]).upper()

    app.jinja_env.filters.update(scode=suspect_code, wcode=witness_code, filesize=filesize,
                                 slug=slug, initials=initials)
    app.jinja_env.globals.update(csrf_token=_csrf_token)

    @app.context_processor
    def inject_user():
        user = current_user()
        return {"current_user": user, "user_is_admin": is_admin(user) if user else False}


# ------------------------------------------------------------------ security

def _csrf_token():
    """One random token per session. Every POST form and fetch() call sends it back."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _register_security(app):
    @app.before_request
    def check_csrf():
        if request.method == "POST" and app.config.get("CSRF_ENABLED", True):
            expected = session.get("csrf_token")
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            if not expected or not sent or not hmac.compare_digest(expected, sent):
                abort(400, description="Your form expired or was not sent from TRACE X. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        if response.mimetype == "text/html":
            # Scripts only from our own /static folder: no inline JavaScript.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self'; object-src 'self'; "
                "frame-ancestors 'self'; base-uri 'self'; form-action 'self'")
            response.headers["Cache-Control"] = "no-store"
        return response


def _register_error_handlers(app):
    messages = {
        400: ("Bad request", None),
        403: ("Access denied", "You do not have permission to open this record. The attempt has been logged."),
        404: ("Not found", "That record or page does not exist."),
        413: ("File too large", "The upload is larger than the configured limit (TRACEX_MAX_UPLOAD_MB)."),
        500: ("Server error", "Something went wrong. Check the terminal running Flask for details."),
    }

    def handler(error):
        code = getattr(error, "code", 500)
        title, text = messages.get(code, ("Error", None))
        description = getattr(error, "description", None) if code == 400 else None
        return render_template("error.html", code=code, title=title, text=description or text), code

    for code in messages:
        app.register_error_handler(code, handler)