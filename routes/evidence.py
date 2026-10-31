"""
Digital evidence vault.

UPLOAD WORKFLOW (upload route below)
  1. Flask receives the file.
  2. The user's permission on the case is checked.
  3. File type (extension + file signature) and size are validated.
  4. A random storage filename is generated (the user never chooses the path).
  5. The file is written once into evidence_storage/<case>/ (outside /static)
     and then marked read-only.
  6. Python calculates its SHA-256 hash.
  7-8. The hash and metadata are saved in SQLite.
  9. A custody event 'Evidence registered' is recorded.
  10. The evidence appears in the case's Evidence Vault.

Files are only ever sent through file() below, which checks access first.
There is deliberately no route that replaces or deletes a registered file.
"""

import csv
import io
import mimetypes
import os
import stat
import uuid

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   send_file, url_for)

from config import EVIDENCE_TYPES
from database.db import execute, get_db, log_activity, now_str, query_all, query_one
from database.queries import case_relationships, get_evidence
from forensics.custody import load_custody_chain, record_custody_event, verify_custody_chain
from forensics.hashing import sha256_file
from forensics.integrity import evidence_abspath, integrity_history, run_tamper_demo, verify_evidence
from forensics.timeline import normalize_timestamp
from routes.auth import can_edit, current_user, login_required, require_case_access

bp = Blueprint("evidence", __name__)

PREVIEW_LIMIT = 200 * 1024     # show at most 200 KB of a text file in the browser

# First bytes ("magic numbers") that real files of each type start with.
SIGNATURES = {
    "png": [b"\x89PNG\r\n\x1a\n"], "jpg": [b"\xff\xd8\xff"], "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"], "bmp": [b"BM"], "pdf": [b"%PDF"],
    "webm": [b"\x1a\x45\xdf\xa3"], "ogv": [b"OggS"], "ogg": [b"OggS"],
    "zip": [b"PK\x03\x04"], "docx": [b"PK\x03\x04"], "xlsx": [b"PK\x03\x04"],
    "mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
}


def evidence_type_for(extension):
    for evidence_type, extensions in EVIDENCE_TYPES.items():
        if extension in extensions:
            return evidence_type
    return None


def signature_ok(extension, head):
    """Check that the file content looks like its extension claims."""
    if extension in ("mp4", "mov", "m4v", "m4a"):
        return head[4:8] == b"ftyp"
    if extension == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if extension == "wav":
        return head[:4] == b"RIFF" and head[8:12] == b"WAVE"
    if extension in ("txt", "md", "log", "json", "csv"):
        return b"\x00" not in head            # text files should not contain NUL bytes
    if extension in SIGNATURES:
        return any(head.startswith(sig) for sig in SIGNATURES[extension])
    return True                                # e.g. aac: no simple signature


def clean_original_name(filename):
    """Keep the uploader's file name for display only, without any folder part."""
    name = os.path.basename((filename or "").replace("\\", "/")).strip().lstrip(". ")
    return name[:200] or "unnamed"


def store_evidence_file(case, file_bytes_stream, original_name, user, description="", notes="",
                        camera_id=None, recorded_at=None, uploaded_at=None):
    """Save a validated stream into private storage and register it.

    Shared by the upload route and database/seed.py. Returns the new evidence id.
    """
    extension = original_name.rsplit(".", 1)[-1].lower()
    evidence_type = evidence_type_for(extension)
    relative_path = f"{case['case_number']}/{uuid.uuid4().hex}.{extension}"
    full_path = evidence_abspath(relative_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    # 'xb' = create a NEW file and fail if one already exists: nothing is overwritten.
    with open(full_path, "xb") as out:
        while True:
            chunk = file_bytes_stream.read(64 * 1024)
            if not chunk:
                break
            out.write(chunk)
    os.chmod(full_path, stat.S_IREAD)                 # registered originals are read-only

    sha256 = sha256_file(full_path)
    size = os.path.getsize(full_path)
    stamp = uploaded_at or now_str()
    db = get_db()
    cursor = db.execute(
        "INSERT INTO evidence (case_id, filename, storage_path, file_type, mime_type, file_size, original_sha256, "
        "uploaded_by, uploaded_at, description, notes, camera_id, recorded_at, custodian_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (case["id"], original_name, relative_path, evidence_type, mimetypes.guess_type(original_name)[0],
         size, sha256, user["id"], stamp, description, notes, camera_id, recorded_at, user["id"]),
    )
    evidence_id = cursor.lastrowid
    code = f"EV-{evidence_id:04d}"
    db.execute("UPDATE evidence SET evidence_code = ? WHERE id = ?", (code, evidence_id))
    db.commit()
    record_custody_event(evidence_id, user["id"], "Evidence registered",
                         f"{original_name} registered with SHA-256 {sha256}", timestamp=stamp)
    return evidence_id


@bp.route("/cases/<case_number>/evidence", methods=["POST"])
@login_required
def upload(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    back = redirect(url_for("cases.view_case", case_number=case_number, tab="evidence"))
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        flash("Choose a file to upload.", "danger")
        return back

    original_name = clean_original_name(upload_file.filename)
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    if evidence_type_for(extension) is None:
        allowed = ", ".join(sorted(ext for group in EVIDENCE_TYPES.values() for ext in group))
        flash(f"File type '.{extension}' is not accepted. Allowed: {allowed}", "danger")
        return back

    head = upload_file.stream.read(4096)
    upload_file.stream.seek(0)
    if not head:
        flash("The file is empty.", "danger")
        return back
    if not signature_ok(extension, head):
        flash(f"The file content does not look like a real .{extension} file. Upload refused.", "danger")
        return back

    recorded_at = normalize_timestamp(request.form.get("recorded_at")) if request.form.get("recorded_at") else None
    evidence_id = store_evidence_file(
        case, upload_file.stream, original_name, current_user(),
        description=request.form.get("description", "").strip(),
        notes=request.form.get("notes", "").strip(),
        camera_id=request.form.get("camera_id", "").strip() or None,
        recorded_at=recorded_at,
    )
    evidence = get_evidence(evidence_id)
    log_activity(current_user()["id"], "Evidence uploaded", "evidence", evidence["evidence_code"], case_number)
    flash(f"{evidence['evidence_code']} registered. Original SHA-256: {evidence['original_sha256']}", "success")
    return redirect(url_for("evidence.view", evidence_id=evidence_id))


def _load(evidence_id, need_edit=False):
    evidence = get_evidence(evidence_id)
    if evidence is None:
        abort(404)
    case, permission = require_case_access(case_id=evidence["case_id"], need_edit=need_edit)
    return evidence, case, permission


def _demo_allowed(permission):
    return permission == "admin" or current_app.config["INTEGRITY_DEMO_FOR_DETECTIVES"]


def _render_viewer(evidence, case, permission, demo=None):
    path = evidence_abspath(evidence["storage_path"])
    exists = os.path.exists(path)
    text_preview = csv_rows = None
    truncated = False
    if exists and evidence["file_type"] in ("text", "csv"):
        with open(path, "rb") as handle:
            raw = handle.read(PREVIEW_LIMIT + 1)
        truncated = len(raw) > PREVIEW_LIMIT
        text_preview = raw[:PREVIEW_LIMIT].decode("utf-8", errors="replace")
        if evidence["file_type"] == "csv":
            csv_rows = list(csv.reader(io.StringIO(text_preview)))[:500]

    key = f"evidence:{evidence['id']}"
    links = [r for r in case_relationships(case["id"]) if key in (r["source_node"], r["target_node"])]
    team = query_all("SELECT u.id, u.full_name FROM case_assignments a JOIN users u ON u.id = a.user_id "
                     "WHERE a.case_id = ? AND a.permission_level != 'viewer'", (case["id"],))
    template = "cctv.html" if evidence["file_type"] == "video" else "evidence.html"
    return render_template(
        template, evidence=evidence, case=case, permission=permission, editable=can_edit(permission),
        exists=exists, text_preview=text_preview, csv_rows=csv_rows, truncated=truncated,
        checks=integrity_history(evidence["id"]), custody=load_custody_chain(evidence["id"]).to_list()[-6:],
        links=links, team=team, demo=demo, demo_allowed=_demo_allowed(permission),
        can_transfer=permission in ("admin", "lead"),
    )


@bp.route("/evidence/<int:evidence_id>")
@login_required
def view(evidence_id):
    evidence, case, permission = _load(evidence_id)
    record_custody_event(evidence_id, current_user()["id"], "Evidence viewed", "Opened in the evidence viewer")
    log_activity(current_user()["id"], "Evidence accessed", "evidence", evidence["evidence_code"])
    return _render_viewer(evidence, case, permission)


@bp.route("/evidence/<int:evidence_id>/file")
@login_required
def file(evidence_id):
    """Stream the stored file. ?download=1 sends it as an attachment and is logged."""
    evidence, _, _ = _load(evidence_id)
    path = evidence_abspath(evidence["storage_path"])
    if not os.path.exists(path):
        abort(404)
    download = request.args.get("download") == "1" or evidence["file_type"] == "other"
    if download:
        record_custody_event(evidence_id, current_user()["id"], "Evidence downloaded",
                             f"Downloaded as {evidence['filename']}")
        log_activity(current_user()["id"], "Evidence downloaded", "evidence", evidence["evidence_code"])
    mimetype = evidence["mime_type"] or "application/octet-stream"
    if evidence["file_type"] in ("text", "csv"):
        mimetype = "text/plain; charset=utf-8"   # never let a stored file render as HTML
    return send_file(path, mimetype=mimetype, as_attachment=download,
                     download_name=evidence["filename"], conditional=True, max_age=0)


@bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@login_required
def verify(evidence_id):
    evidence, _, _ = _load(evidence_id)
    outcome = verify_evidence(evidence, current_user()["id"])
    category = {"MATCH": "success", "MISMATCH": "danger", "FILE MISSING": "danger"}[outcome["result"]]
    flash(f"Integrity check for {evidence['evidence_code']}: {outcome['result']}", category)
    return redirect(request.form.get("back") or url_for("evidence.view", evidence_id=evidence_id))


@bp.route("/evidence/<int:evidence_id>/custody")
@login_required
def custody(evidence_id):
    evidence, case, permission = _load(evidence_id)
    chain = load_custody_chain(evidence_id)
    action_filter = request.args.get("action", "").strip()
    found = None
    if action_filter:
        # Linear search through the linked list.
        found = chain.search_all(lambda event: action_filter.lower() in event["action"].lower())
    actions = sorted({event["action"] for event in chain})
    log_activity(current_user()["id"], "Custody history viewed", "evidence", evidence["evidence_code"])
    return render_template("custody.html", evidence=evidence, case=case, permission=permission,
                           events=chain.to_list(), chain_text=chain.display(lambda e: e["action"]),
                           verification=verify_custody_chain(evidence_id), action_filter=action_filter,
                           found=found, actions=actions)


@bp.route("/evidence/<int:evidence_id>/notes", methods=["POST"])
@login_required
def update_notes(evidence_id):
    """Investigator notes ABOUT the evidence. The file itself never changes."""
    evidence, _, _ = _load(evidence_id, need_edit=True)
    notes = request.form.get("notes", "").strip()
    execute("UPDATE evidence SET notes = ? WHERE id = ?", (notes, evidence_id))
    record_custody_event(evidence_id, current_user()["id"], "Evidence notes updated",
                         "Investigator notes changed")
    log_activity(current_user()["id"], "Evidence notes updated", "evidence", evidence["evidence_code"])
    flash("Notes saved.", "success")
    return redirect(url_for("evidence.view", evidence_id=evidence_id))


@bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@login_required
def transfer(evidence_id):
    evidence, case, permission = _load(evidence_id, need_edit=True)
    if permission not in ("admin", "lead"):
        abort(403)
    new_id = request.form.get("custodian_id", type=int)
    allowed = query_one("SELECT u.full_name FROM case_assignments a JOIN users u ON u.id = a.user_id "
                        "WHERE a.case_id = ? AND a.user_id = ? AND a.permission_level != 'viewer'",
                        (case["id"], new_id))
    if allowed is None:
        flash("Custody can only be given to a lead or investigator on this case.", "danger")
    elif new_id == evidence["custodian_id"]:
        flash("That detective already holds this evidence.", "info")
    else:
        execute("UPDATE evidence SET custodian_id = ? WHERE id = ?", (new_id, evidence_id))
        reason = request.form.get("reason", "").strip()
        record_custody_event(evidence_id, current_user()["id"], "Evidence transferred",
                             f"Custody: {evidence['custodian_name'] or 'none'} -> {allowed['full_name']}"
                             + (f". Reason: {reason}" if reason else ""))
        log_activity(current_user()["id"], "Evidence transferred", "evidence", evidence["evidence_code"],
                     allowed["full_name"])
        flash(f"Custody transferred to {allowed['full_name']}.", "success")
    return redirect(url_for("evidence.view", evidence_id=evidence_id))


@bp.route("/evidence/<int:evidence_id>/demo", methods=["POST"])
@login_required
def tamper_demo(evidence_id):
    evidence, case, permission = _load(evidence_id)
    if not _demo_allowed(permission):
        abort(403)
    demo = run_tamper_demo(evidence, current_user()["id"])
    return _render_viewer(get_evidence(evidence_id), case, permission, demo=demo)
