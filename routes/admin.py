from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from database.db import execute, get_db, log_activity, now_str, query_all, query_one
from database.queries import (PERMISSION_LEVELS, STATUSES, case_team, cases_for_user_with_role,
                              evidence_for_cases, get_case_by_number, get_evidence, list_cases,
                              list_detectives, next_case_number)
from forensics.custody import record_custody_event
from forensics.integrity import run_tamper_demo
from routes.auth import admin_required, current_user

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    db = get_db()

    def count(sql, params=()):
        return db.execute(sql, params).fetchone()[0]

    stats = {
        "detectives": count("SELECT COUNT(*) FROM users WHERE role = 'detective'"),
        "cases": count("SELECT COUNT(*) FROM cases"),
        "active": count("SELECT COUNT(*) FROM cases WHERE status != 'Closed'"),
        "closed": count("SELECT COUNT(*) FROM cases WHERE status = 'Closed'"),
        "evidence": count("SELECT COUNT(*) FROM evidence"),
        "alerts": count("SELECT COUNT(*) FROM evidence WHERE integrity_status IN ('MISMATCH', 'FILE MISSING')"),
        "unverified": count("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'UNVERIFIED'"),
        "unassigned": count("SELECT COUNT(*) FROM cases c WHERE NOT EXISTS "
                            "(SELECT 1 FROM case_assignments a WHERE a.case_id = c.id)"),
    }
    status_counts = {s: count("SELECT COUNT(*) FROM cases WHERE status = ?", (s,)) for s in STATUSES}
    alerts = query_all(
        "SELECT e.*, c.case_number FROM evidence e JOIN cases c ON c.id = e.case_id "
        "WHERE e.integrity_status IN ('MISMATCH', 'FILE MISSING') ORDER BY e.last_verified_at DESC")
    recent_activity = query_all(
        "SELECT l.*, u.full_name FROM activity_logs l LEFT JOIN users u ON u.id = l.user_id "
        "ORDER BY l.id DESC LIMIT 12")
    recent_uploads = query_all(
        "SELECT e.*, c.case_number, u.full_name AS uploaded_by_name FROM evidence e "
        "JOIN cases c ON c.id = e.case_id LEFT JOIN users u ON u.id = e.uploaded_by "
        "ORDER BY e.uploaded_at DESC, e.id DESC LIMIT 6")
    return render_template("admin.html", stats=stats, status_counts=status_counts, alerts=alerts,
                           recent_activity=recent_activity, recent_uploads=recent_uploads,
                           detectives=list_detectives(), cases=list_cases())


# ---------------------------------------------------------------- detectives

@bp.route("/detectives")
@admin_required
def detectives():
    return render_template("admin_detectives.html", detectives=list_detectives())


@bp.route("/detectives/<int:user_id>")
@admin_required
def detective_cases(user_id):
    detective = query_one("SELECT * FROM users WHERE id = ? AND role = 'detective'", (user_id,))
    if detective is None:
        abort(404)
    recent = query_all("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 10", (user_id,))
    return render_template("admin_detective.html", detective=detective,
                           cases=cases_for_user_with_role(user_id), recent=recent)


# --------------------------------------------------------------------- cases

@bp.route("/cases")
@admin_required
def cases():
    all_cases = list_cases()
    teams = {c["id"]: case_team(c["id"]) for c in all_cases}
    return render_template("admin_cases.html", cases=all_cases, teams=teams,
                           detectives=list_detectives(), levels=PERMISSION_LEVELS)


def _case_form_values():
    form = request.form
    return {
        "title": form.get("title", "").strip(),
        "category": form.get("category", "").strip(),
        "description": form.get("description", "").strip(),
        "summary": form.get("summary", "").strip(),
        "status": form.get("status", "Open"),
        "incident_date": form.get("incident_date", "").strip() or None,
        "location": form.get("location", "").strip(),
    }


def _validate_case(values):
    errors = []
    if not values["title"]:
        errors.append("Title is required.")
    if not values["category"]:
        errors.append("Category is required.")
    if values["status"] not in STATUSES:
        errors.append("Unknown status.")
    return errors


@bp.route("/cases/new", methods=["GET", "POST"])
@admin_required
def new_case():
    values = {"status": "Open"}
    if request.method == "POST":
        values = _case_form_values()
        errors = _validate_case(values)
        for error in errors:
            flash(error, "danger")
        if not errors:
            user = current_user()
            case_number = next_case_number()
            case_id = execute(
                "INSERT INTO cases (case_number, title, category, description, summary, status, "
                "incident_date, location, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_number, values["title"], values["category"], values["description"], values["summary"],
                 values["status"], values["incident_date"], values["location"], now_str(), user["id"]),
            )
            log_activity(user["id"], "Case created", "case", case_number, values["title"])
            lead_id = request.form.get("lead_id", type=int)
            if lead_id:
                _assign(case_id, case_number, lead_id, "lead")
            flash(f"{case_number} created.", "success")
            return redirect(url_for("cases.view_case", case_number=case_number))
    return render_template("case_form.html", values=values, statuses=STATUSES,
                           detectives=list_detectives(), is_new=True)


@bp.route("/cases/<case_number>/edit", methods=["GET", "POST"])
@admin_required
def edit_case(case_number):
    case = get_case_by_number(case_number)
    if case is None:
        abort(404)
    values = dict(case)
    if request.method == "POST":
        values = _case_form_values()
        errors = _validate_case(values)
        for error in errors:
            flash(error, "danger")
        if not errors:
            execute(
                "UPDATE cases SET title = ?, category = ?, description = ?, summary = ?, status = ?, "
                "incident_date = ?, location = ? WHERE id = ?",
                (values["title"], values["category"], values["description"], values["summary"],
                 values["status"], values["incident_date"], values["location"], case["id"]),
            )
            log_activity(current_user()["id"], "Case updated", "case", case_number, "Full edit by administrator")
            flash("Case details saved.", "success")
            return redirect(url_for("cases.view_case", case_number=case_number))
    values["case_number"] = case["case_number"]
    return render_template("case_form.html", values=values, statuses=STATUSES,
                           detectives=list_detectives(), is_new=False)


def _assign(case_id, case_number, user_id, level):
    """Insert or update one assignment. Only one detective can be lead."""
    detective = query_one("SELECT * FROM users WHERE id = ? AND role = 'detective'", (user_id,))
    if detective is None or level not in PERMISSION_LEVELS:
        flash("Choose a detective and a valid permission level.", "danger")
        return False
    db = get_db()
    if level == "lead":
        db.execute("UPDATE case_assignments SET permission_level = 'investigator' "
                   "WHERE case_id = ? AND permission_level = 'lead' AND user_id != ?", (case_id, user_id))
    existing = db.execute("SELECT id FROM case_assignments WHERE case_id = ? AND user_id = ?",
                          (case_id, user_id)).fetchone()
    if existing:
        db.execute("UPDATE case_assignments SET permission_level = ?, assigned_at = ?, assigned_by = ? "
                   "WHERE id = ?", (level, now_str(), current_user()["id"], existing["id"]))
    else:
        db.execute("INSERT INTO case_assignments (case_id, user_id, permission_level, assigned_at, assigned_by) "
                   "VALUES (?, ?, ?, ?, ?)", (case_id, user_id, level, now_str(), current_user()["id"]))
    db.commit()
    action = "Case shared" if level == "viewer" else "Case assigned"
    log_activity(current_user()["id"], action, "case", case_number, f"{detective['full_name']} as {level}")
    flash(f"{detective['full_name']} now has {level} access to {case_number}.", "success")
    return True


@bp.route("/cases/<case_number>/assign", methods=["POST"])
@admin_required
def assign(case_number):
    case = get_case_by_number(case_number)
    if case is None:
        abort(404)
    _assign(case["id"], case_number, request.form.get("user_id", type=int), request.form.get("permission_level"))
    return redirect(request.form.get("back") or url_for("admin.cases"))


@bp.route("/cases/<case_number>/reassign", methods=["POST"])
@admin_required
def reassign(case_number):
    """Move the lead role from one detective to another and transfer custody of
    the evidence that the previous lead was holding."""
    case = get_case_by_number(case_number)
    if case is None:
        abort(404)
    new_lead = query_one("SELECT * FROM users WHERE id = ? AND role = 'detective'",
                         (request.form.get("user_id", type=int),))
    old_lead = query_one("SELECT u.* FROM case_assignments a JOIN users u ON u.id = a.user_id "
                         "WHERE a.case_id = ? AND a.permission_level = 'lead'", (case["id"],))
    if new_lead is None:
        flash("Choose the detective who will take over the case.", "danger")
        return redirect(url_for("admin.cases"))
    if old_lead and old_lead["id"] == new_lead["id"]:
        flash(f"{new_lead['full_name']} is already the lead.", "info")
        return redirect(url_for("admin.cases"))

    db = get_db()
    if old_lead:
        db.execute("DELETE FROM case_assignments WHERE case_id = ? AND user_id = ?", (case["id"], old_lead["id"]))
        db.commit()
    _assign(case["id"], case_number, new_lead["id"], "lead")
    if old_lead:
        held = db.execute("SELECT id FROM evidence WHERE case_id = ? AND custodian_id = ?",
                          (case["id"], old_lead["id"])).fetchall()
        for item in held:
            db.execute("UPDATE evidence SET custodian_id = ? WHERE id = ?", (new_lead["id"], item["id"]))
            record_custody_event(item["id"], current_user()["id"], "Evidence transferred",
                                 f"Case reassigned: custody moved from {old_lead['full_name']} "
                                 f"to {new_lead['full_name']}", commit=False)
        db.commit()
    log_activity(current_user()["id"], "Case reassigned", "case", case_number,
                 f"{old_lead['full_name'] if old_lead else 'nobody'} -> {new_lead['full_name']}")
    return redirect(url_for("admin.cases"))


@bp.route("/cases/<case_number>/unassign/<int:user_id>", methods=["POST"])
@admin_required
def unassign(case_number, user_id):
    case = get_case_by_number(case_number)
    if case is None:
        abort(404)
    execute("DELETE FROM case_assignments WHERE case_id = ? AND user_id = ?", (case["id"], user_id))
    user = query_one("SELECT full_name FROM users WHERE id = ?", (user_id,))
    log_activity(current_user()["id"], "Case access removed", "case", case_number,
                 user["full_name"] if user else str(user_id))
    flash("Access removed.", "info")
    return redirect(request.form.get("back") or url_for("admin.cases"))


# ---------------------------------------------------------------------- logs

@bp.route("/logs")
@admin_required
def logs():
    user_filter = request.args.get("user_id", type=int)
    text_filter = request.args.get("q", "").strip()
    sql = ("SELECT l.*, u.full_name, u.username FROM activity_logs l "
           "LEFT JOIN users u ON u.id = l.user_id WHERE 1 = 1")
    params = []
    if user_filter:
        sql += " AND l.user_id = ?"
        params.append(user_filter)
    if text_filter:
        sql += " AND (l.action LIKE ? OR l.target_id LIKE ? OR l.details LIKE ?)"
        params += [f"%{text_filter}%"] * 3
    sql += " ORDER BY l.id DESC LIMIT 300"
    users = query_all("SELECT id, full_name FROM users ORDER BY role, full_name")
    return render_template("admin_logs.html", logs=query_all(sql, params), users=users,
                           user_filter=user_filter, text_filter=text_filter)


# --------------------------------------------------------------------- users

@bp.route("/users")
@admin_required
def users():
    return render_template("admin_users.html",
                           users=query_all("SELECT * FROM users ORDER BY role, badge_id"))


@bp.route("/users/<int:user_id>", methods=["POST"])
@admin_required
def update_user(user_id):
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if user is None:
        abort(404)
    full_name = request.form.get("full_name", "").strip() or user["full_name"]
    specialization = request.form.get("specialization", "").strip()
    profile_image = request.form.get("profile_image", "").strip() or None
    if profile_image and (".." in profile_image or profile_image.startswith(("/", "\\")) or ":" in profile_image):
        flash("Profile image must be a path inside static/, e.g. assets/detectives/amna.jpg", "danger")
        return redirect(url_for("admin.users"))
    is_active = 1 if request.form.get("is_active") or user["id"] == current_user()["id"] else 0
    execute("UPDATE users SET full_name = ?, specialization = ?, profile_image = ?, is_active = ? WHERE id = ?",
            (full_name, specialization, profile_image, is_active, user_id))

    new_password = request.form.get("new_password", "")
    if new_password:
        if len(new_password) < 8:
            flash("New password must be at least 8 characters. Other changes were saved.", "warning")
        else:
            execute("UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), user_id))
            log_activity(current_user()["id"], "Password reset", "user", user["username"])
    log_activity(current_user()["id"], "User account updated", "user", user["username"])
    flash(f"Account {user['username']} updated.", "success")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------- integrity demo

@bp.route("/integrity-demo", methods=["GET", "POST"])
@admin_required
def integrity_demo():
    result = None
    selected = None
    if request.method == "POST":
        selected = get_evidence(request.form.get("evidence_id", type=int))
        if selected is None:
            flash("Choose an evidence item.", "danger")
        else:
            result = run_tamper_demo(selected, current_user()["id"])
    return render_template("integrity_demo.html", evidence=evidence_for_cases(None),
                           result=result, selected=selected)
