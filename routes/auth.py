"""
Landing page, login / logout, and the permission helpers used by every
other blueprint.

SECURITY RULES
  * Passwords are checked on the server with Werkzeug's check_password_hash.
    Only the hash is stored in SQLite; nothing about passwords reaches HTML/JS.
  * The logged-in user's id lives in the signed Flask session cookie.
  * @login_required / @admin_required protect routes.
  * require_case_access() is called by every route that touches case data,
    so changing a URL by hand cannot open a case the user is not assigned to.
"""

from functools import wraps

from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

from database.db import log_activity, query_all, query_one
from database.queries import get_case, get_case_by_number, list_detectives

bp = Blueprint("auth", __name__)


# ------------------------------------------------------------ current user

def current_user():
    """The logged-in user row, or None. Cached for the rest of the request."""
    if "current_user" not in g:
        user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = query_one("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,))
            if user is None:
                session.clear()
        g.current_user = user
    return g.current_user


def is_admin(user=None):
    user = user or current_user()
    return user is not None and user["role"] == "admin"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not is_admin():
            log_activity(current_user()["id"], "Access denied", "route", request.path, "Administrator area")
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# --------------------------------------------------------- case permissions

def case_permission(user, case_id):
    """Return 'admin', 'lead', 'investigator', 'viewer' or None (no access)."""
    if user is None:
        return None
    if user["role"] == "admin":
        return "admin"
    row = query_one("SELECT permission_level FROM case_assignments WHERE case_id = ? AND user_id = ?",
                    (case_id, user["id"]))
    return row["permission_level"] if row else None


def can_edit(permission):
    """Viewers (shared read-only) may look but not add or change records."""
    return permission in ("admin", "lead", "investigator")


def accessible_case_ids(user):
    """Ids of every case this user may open."""
    if user is None:
        return []
    if user["role"] == "admin":
        return [row["id"] for row in query_all("SELECT id FROM cases ORDER BY id")]
    return [row["case_id"] for row in query_all(
        "SELECT case_id FROM case_assignments WHERE user_id = ? ORDER BY case_id", (user["id"],))]


def require_case_access(case_number=None, case_id=None, need_edit=False):
    """Load a case and stop the request (404/403) if the user may not use it.

    Returns (case_row, permission).
    """
    case = get_case_by_number(case_number) if case_number else get_case(case_id)
    if case is None:
        abort(404)
    user = current_user()
    permission = case_permission(user, case["id"])
    if permission is None or (need_edit and not can_edit(permission)):
        log_activity(user["id"] if user else None, "Access denied", "case", case["case_number"],
                     "edit attempt" if need_edit else "view attempt")
        abort(403)
    return case, permission


# -------------------------------------------------------------------- routes

@bp.route("/")
def index():
    return render_template("index.html", detectives=list_detectives(), public_page=True)


def _safe_next(target):
    """Only allow redirects to paths on this site (prevents open redirects)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(home_for(current_user()))

    # Which profile was clicked on the landing page (only used for display).
    detective = None
    portal = request.values.get("portal", "")
    if portal and portal != "admin":
        detective = query_one(
            "SELECT username, full_name, badge_id, specialization, profile_image FROM users "
            "WHERE username = ? AND role = 'detective'", (portal,))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = query_one("SELECT * FROM users WHERE username = ?", (username,))
        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            log_activity(user["id"], "Successful login", "user", user["username"])
            flash(f"Welcome, {user['full_name']}.", "success")
            return redirect(_safe_next(request.form.get("next")) or home_for(user))
        # Same message for unknown user and wrong password, so usernames cannot be guessed.
        log_activity(user["id"] if user else None, "Failed login attempt", "user", username or "(blank)")
        flash("Invalid username or password.", "danger")

    return render_template("login.html", detective=detective, portal=portal, public_page=True,
                           next=_safe_next(request.values.get("next")) or "")


@bp.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        log_activity(user["id"], "Logout", "user", user["username"])
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.index"))


def home_for(user):
    return url_for("admin.dashboard") if user["role"] == "admin" else url_for("detectives.portal")
