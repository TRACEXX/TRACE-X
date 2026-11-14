import os

from flask import Blueprint, abort, current_app, redirect, render_template, request, send_file, url_for

from ai.context_builder import deterministic_summary
from ai.providers import provider_status
from database.db import log_activity, query_one
from database.queries import case_bundle, case_reports
from reports.generator import create_case_report
from routes.auth import current_user, login_required, require_case_access

bp = Blueprint("reports", __name__)


@bp.route("/cases/<case_number>/report")
@login_required
def preview(case_number):
    case, permission = require_case_access(case_number)
    bundle = case_bundle(case["id"])
    return render_template("report.html", case=case, permission=permission, bundle=bundle,
                           summary=deterministic_summary(bundle), reports=case_reports(case["id"]),
                           ai=provider_status())


@bp.route("/cases/<case_number>/report/generate", methods=["POST"])
@login_required
def generate(case_number):
    case, _ = require_case_access(case_number)
    report_id, _ = create_case_report(case["id"], current_user(), use_ai=bool(request.form.get("use_ai")))
    return redirect(url_for("reports.download", report_id=report_id))


@bp.route("/reports/<int:report_id>/download")
@login_required
def download(report_id):
    report = query_one("SELECT r.*, c.case_number FROM ai_reports r JOIN cases c ON c.id = r.case_id "
                       "WHERE r.id = ?", (report_id,))
    if report is None:
        abort(404)
    require_case_access(case_id=report["case_id"])
    folder = os.path.realpath(current_app.config["REPORTS_DIR"])
    path = os.path.realpath(os.path.join(folder, os.path.basename(report["report_path"])))
    if not os.path.exists(path):
        abort(404)
    log_activity(current_user()["id"], "Report downloaded", "case", report["case_number"], report["report_path"])
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=os.path.basename(path))
