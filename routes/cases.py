import mimetypes
import os
import uuid

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect, render_template,
                   request, url_for)

from database.db import execute, get_db, log_activity, now_str, query_all, query_one
from database.queries import (NODE_TYPES, STATUSES, build_case_graph, case_evidence, case_findings,
                              case_node_labels, case_notes, case_relationships, case_reports, case_suspects,
                              case_tasks, case_team, case_witnesses, get_evidence, get_suspect,
                              suspect_code, suspect_linked_evidence, witness_code, witness_history)
from dsa.queue import Queue
from dsa.stack import Stack
from dsa.tree import build_evidence_tree
from forensics.custody import record_custody_event, verify_custody_chain
from forensics.integrity import evidence_abspath, verify_evidence
from forensics.timeline import build_case_timeline, import_csv_activity_log, normalize_timestamp
from routes.auth import can_edit, current_user, login_required, require_case_access

bp = Blueprint("cases", __name__)

TABS = [
    ("overview", "Overview"), ("suspects", "Suspects"), ("witnesses", "Witnesses"),
    ("evidence", "Evidence Vault"), ("timeline", "Timeline"), ("notes", "Notes"),
    ("forensics", "Forensic Tools"), ("reports", "Reports & Findings"),
]
TASK_TYPES = {
    "verify_integrity": "Verify SHA-256 integrity",
    "import_csv_timeline": "Import CSV log into timeline",
    "extract_metadata": "Extract file metadata",
}
IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}


def back_to(case_number, tab):
    return redirect(url_for("cases.view_case", case_number=case_number, tab=tab))


# ======================================================================= case

@bp.route("/cases/<case_number>")
@login_required
def view_case(case_number):
    case, permission = require_case_access(case_number)
    tab = request.args.get("tab", "overview")
    if tab not in dict(TABS):
        tab = "overview"
    user = current_user()
    if tab == "overview":
        log_activity(user["id"], "Case opened", "case", case["case_number"])

    data = {"team": case_team(case["id"])}
    db = get_db()
    if tab == "overview":
        data["counts"] = {
            "suspects": db.execute("SELECT COUNT(*) FROM suspects WHERE case_id = ?", (case["id"],)).fetchone()[0],
            "witnesses": db.execute("SELECT COUNT(*) FROM witnesses WHERE case_id = ?", (case["id"],)).fetchone()[0],
            "evidence": db.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case["id"],)).fetchone()[0],
            "alerts": db.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ? AND integrity_status IN "
                                 "('MISMATCH', 'FILE MISSING')", (case["id"],)).fetchone()[0],
        }
        data["recent_events"] = build_case_timeline(case["id"], include_system=False)[-5:]
    elif tab == "suspects":
        data["suspects"] = case_suspects(case["id"])
    elif tab == "witnesses":
        data["witnesses"] = case_witnesses(case["id"])
        data["history"] = {w["id"]: witness_history(w["id"]) for w in data["witnesses"]}
        data["suspects"] = case_suspects(case["id"])
        data["evidence"] = case_evidence(case["id"])
    elif tab == "evidence":
        data["evidence"] = case_evidence(case["id"])
        tree = build_evidence_tree([case], data["evidence"])
        data["tree"] = tree.children[0].to_dict() if tree.children else None
        data["tree_size"] = tree.count() - 1
    elif tab == "timeline":
        include_system = request.args.get("system", "1") == "1"
        data["include_system"] = include_system
        data["events"] = build_case_timeline(case["id"], include_system=include_system)
        data["evidence"] = case_evidence(case["id"])
    elif tab == "notes":
        data["notes"] = case_notes(case["id"])
    elif tab == "forensics":
        data["evidence"] = case_evidence(case["id"])
        data["chains"] = {e["id"]: verify_custody_chain(e["id"]) for e in data["evidence"]}
        data["tasks"] = case_tasks(case["id"])
        data["pending"] = sum(1 for t in data["tasks"] if t["status"] == "pending")
        data["relationships"] = case_relationships(case["id"])
        data["nodes"] = sorted(case_node_labels(case["id"]).items(), key=lambda kv: (kv[1][0], kv[1][1]))
        data["task_types"] = TASK_TYPES
        data["node_types"] = NODE_TYPES
    elif tab == "reports":
        data["findings"] = case_findings(case["id"])
        data["suspects"] = case_suspects(case["id"])
        data["evidence"] = case_evidence(case["id"])
        data["reports"] = case_reports(case["id"])

    return render_template("case.html", case=case, permission=permission, editable=can_edit(permission),
                           tab=tab, tabs=TABS, statuses=STATUSES, **data)


@bp.route("/cases/<case_number>/update", methods=["POST"])
@login_required
def update_case(case_number):
    """Detectives with edit rights may update the summary and status.
    Only the administrator may close a case (full edit is in admin.edit_case)."""
    case, permission = require_case_access(case_number, need_edit=True)
    status = request.form.get("status", case["status"])
    summary = request.form.get("summary", case["summary"]).strip()
    if status not in STATUSES:
        abort(400)
    if status == "Closed" and permission != "admin" and case["status"] != "Closed":
        flash("Only the administrator can close a case. Set it to Pending Review instead.", "warning")
        status = case["status"]
    if case["status"] == "Closed" and status != "Closed" and permission != "admin":
        flash("Only the administrator can re-open a closed case.", "warning")
        status = "Closed"
    execute("UPDATE cases SET summary = ?, status = ? WHERE id = ?", (summary, status, case["id"]))
    log_activity(current_user()["id"], "Case updated", "case", case_number,
                 f"Status: {case['status']} -> {status}" if status != case["status"] else "Summary updated")
    flash("Case updated.", "success")
    return back_to(case_number, "overview")


# =================================================================== suspects

def _save_suspect_photo():
    """Store an uploaded suspect photo in static/assets/suspects. Returns the
    static-relative path or None. These are fictional dossier photos, not evidence."""
    photo = request.files.get("photo")
    if not photo or not photo.filename:
        return None
    extension = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if extension not in IMAGE_EXTENSIONS:
        flash("Suspect photo must be a JPG, PNG, GIF or WEBP image.", "warning")
        return None
    folder = current_app.config["SUSPECT_PHOTO_DIR"]
    os.makedirs(folder, exist_ok=True)
    name = f"{uuid.uuid4().hex}.{extension}"
    photo.save(os.path.join(folder, name))
    return f"assets/suspects/{name}"


SUSPECT_FIELDS = ["name", "background", "relationship", "motive", "alibi", "statements", "notes"]


@bp.route("/cases/<case_number>/suspects", methods=["POST"])
@login_required
def add_suspect(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    values = {f: request.form.get(f, "").strip() for f in SUSPECT_FIELDS}
    if not values["name"]:
        flash("Suspect name is required.", "danger")
        return back_to(case_number, "suspects")
    stamp = now_str()
    suspect_id = execute(
        "INSERT INTO suspects (case_id, name, photo_path, background, relationship, motive, alibi, statements, "
        "notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (case["id"], values["name"], _save_suspect_photo(), values["background"], values["relationship"],
         values["motive"], values["alibi"], values["statements"], values["notes"], stamp, stamp),
    )
    log_activity(current_user()["id"], "Suspect added", "suspect", suspect_code(suspect_id), case_number)
    flash(f"Suspect {suspect_code(suspect_id)} added.", "success")
    return redirect(url_for("cases.suspect_dossier", suspect_id=suspect_id))


@bp.route("/suspects/<int:suspect_id>")
@login_required
def suspect_dossier(suspect_id):
    suspect = get_suspect(suspect_id)
    if suspect is None:
        abort(404)
    case, permission = require_case_access(case_id=suspect["case_id"])
    key = f"suspect:{suspect_id}"
    other_links = [r for r in case_relationships(case["id"])
                   if key in (r["source_node"], r["target_node"])
                   and not (r["source_node"].startswith("evidence:") or r["target_node"].startswith("evidence:"))]
    witnesses = query_all("SELECT * FROM witnesses WHERE related_suspect_id = ?", (suspect_id,))
    log_activity(current_user()["id"], "Suspect dossier opened", "suspect", suspect_code(suspect_id))
    return render_template("suspect.html", suspect=suspect, case=case, permission=permission,
                           editable=can_edit(permission), linked=suspect_linked_evidence(suspect_id),
                           other_links=other_links, witnesses=witnesses, code=suspect_code(suspect_id))


@bp.route("/suspects/<int:suspect_id>/edit", methods=["POST"])
@login_required
def edit_suspect(suspect_id):
    suspect = get_suspect(suspect_id)
    if suspect is None:
        abort(404)
    require_case_access(case_id=suspect["case_id"], need_edit=True)
    values = {f: request.form.get(f, "").strip() for f in SUSPECT_FIELDS}
    values["name"] = values["name"] or suspect["name"]
    photo = _save_suspect_photo() or suspect["photo_path"]
    execute(
        "UPDATE suspects SET name = ?, photo_path = ?, background = ?, relationship = ?, motive = ?, alibi = ?, "
        "statements = ?, notes = ?, updated_at = ? WHERE id = ?",
        (values["name"], photo, values["background"], values["relationship"], values["motive"],
         values["alibi"], values["statements"], values["notes"], now_str(), suspect_id),
    )
    log_activity(current_user()["id"], "Suspect record updated", "suspect", suspect_code(suspect_id))
    flash("Dossier saved.", "success")
    return redirect(url_for("cases.suspect_dossier", suspect_id=suspect_id))


# ================================================================== witnesses

def _related_ids(case_id):
    """Read optional suspect/evidence links from the form, accepting only ids in this case."""
    suspect_id = request.form.get("related_suspect_id", type=int)
    evidence_id = request.form.get("related_evidence_id", type=int)
    if suspect_id and not query_one("SELECT 1 FROM suspects WHERE id = ? AND case_id = ?", (suspect_id, case_id)):
        suspect_id = None
    if evidence_id and not query_one("SELECT 1 FROM evidence WHERE id = ? AND case_id = ?", (evidence_id, case_id)):
        evidence_id = None
    return suspect_id, evidence_id


@bp.route("/cases/<case_number>/witnesses", methods=["POST"])
@login_required
def add_witness(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    name = request.form.get("name", "").strip()
    statement = request.form.get("statement", "").strip()
    if not name or not statement:
        flash("Witness name and statement are required.", "danger")
        return back_to(case_number, "witnesses")
    recorded_at = normalize_timestamp(request.form.get("recorded_at")) or now_str()
    suspect_id, evidence_id = _related_ids(case["id"])
    witness_id = execute(
        "INSERT INTO witnesses (case_id, name, contact, statement, recorded_at, recorded_by, related_suspect_id, "
        "related_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (case["id"], name, request.form.get("contact", "").strip(), statement, recorded_at,
         current_user()["id"], suspect_id, evidence_id),
    )
    log_activity(current_user()["id"], "Witness statement recorded", "witness", witness_code(witness_id), case_number)
    flash(f"Witness {witness_code(witness_id)} recorded.", "success")
    return back_to(case_number, "witnesses")


@bp.route("/witnesses/<int:witness_id>/edit", methods=["POST"])
@login_required
def edit_witness(witness_id):
    """Update a statement. The previous version is copied to witness_history first."""
    witness = query_one("SELECT * FROM witnesses WHERE id = ?", (witness_id,))
    if witness is None:
        abort(404)
    case, _ = require_case_access(case_id=witness["case_id"], need_edit=True)
    statement = request.form.get("statement", "").strip()
    reason = request.form.get("reason", "").strip()
    if not statement:
        flash("Statement cannot be empty.", "danger")
        return back_to(case["case_number"], "witnesses")
    suspect_id, evidence_id = _related_ids(case["id"])
    db = get_db()
    if statement != witness["statement"]:
        db.execute("INSERT INTO witness_history (witness_id, previous_statement, edited_by, edited_at, reason) "
                   "VALUES (?, ?, ?, ?, ?)", (witness_id, witness["statement"], current_user()["id"], now_str(), reason))
    db.execute("UPDATE witnesses SET statement = ?, related_suspect_id = ?, related_evidence_id = ?, updated_at = ? "
               "WHERE id = ?", (statement, suspect_id, evidence_id, now_str(), witness_id))
    db.commit()
    log_activity(current_user()["id"], "Witness statement updated", "witness", witness_code(witness_id),
                 reason or None)
    flash("Statement updated. The previous version was kept in the audit history.", "success")
    return back_to(case["case_number"], "witnesses")


# ====================================================================== notes

@bp.route("/cases/<case_number>/notes", methods=["POST"])
@login_required
def add_note(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    content = request.form.get("content", "").strip()
    if not content:
        flash("Note is empty.", "danger")
        return back_to(case_number, "notes")
    stamp = now_str()
    execute("INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (case["id"], current_user()["id"], request.form.get("title", "").strip() or "Note", content, stamp, stamp))
    log_activity(current_user()["id"], "Investigation note added", "case", case_number)
    flash("Note saved.", "success")
    return back_to(case_number, "notes")


def _note_for_edit(note_id):
    note = query_one("SELECT * FROM investigation_notes WHERE id = ?", (note_id,))
    if note is None:
        abort(404)
    case, permission = require_case_access(case_id=note["case_id"], need_edit=True)
    if note["user_id"] != current_user()["id"] and permission not in ("admin", "lead"):
        abort(403)
    return note, case


@bp.route("/notes/<int:note_id>/edit", methods=["POST"])
@login_required
def edit_note(note_id):
    note, case = _note_for_edit(note_id)
    title = request.form.get("title", "").strip() or note["title"]
    content = request.form.get("content", "").strip()
    if not content:
        flash("Note is empty.", "danger")
        return back_to(case["case_number"], "notes")
    if content == note["content"] and title == note["title"]:
        flash("No changes to save.", "info")
        return back_to(case["case_number"], "notes")
    db = get_db()
    # Save the current version first; this is what Undo will pop back off the stack.
    db.execute("INSERT INTO note_history (note_id, title, content, saved_by, saved_at) VALUES (?, ?, ?, ?, ?)",
               (note_id, note["title"], note["content"], current_user()["id"], now_str()))
    db.execute("UPDATE investigation_notes SET title = ?, content = ?, updated_at = ? WHERE id = ?",
               (title, content, now_str(), note_id))
    db.commit()
    log_activity(current_user()["id"], "Investigation note updated", "note", note_id, case["case_number"])
    flash("Note updated. Use Undo to restore the previous version.", "success")
    return back_to(case["case_number"], "notes")


@bp.route("/notes/<int:note_id>/undo", methods=["POST"])
@login_required
def undo_note(note_id):
    """Restore the most recent previous version using the Stack (LIFO)."""
    note, case = _note_for_edit(note_id)
    stack = Stack()
    for version in query_all("SELECT * FROM note_history WHERE note_id = ? ORDER BY id", (note_id,)):
        stack.push(version)                      # oldest pushed first, newest ends on top
    if stack.is_empty():
        flash("Nothing to undo for this note.", "info")
        return back_to(case["case_number"], "notes")
    previous = stack.pop()                       # newest saved version
    db = get_db()
    db.execute("UPDATE investigation_notes SET title = ?, content = ?, updated_at = ? WHERE id = ?",
               (previous["title"], previous["content"], now_str(), note_id))
    db.execute("DELETE FROM note_history WHERE id = ?", (previous["id"],))
    db.commit()
    log_activity(current_user()["id"], "Investigation note undo", "note", note_id,
                 f"Restored version saved {previous['saved_at']}; {len(stack)} older version(s) remain")
    flash(f"Restored the version saved at {previous['saved_at']}. {len(stack)} older version(s) remain.", "success")
    return back_to(case["case_number"], "notes")


# =================================================================== timeline

@bp.route("/cases/<case_number>/timeline", methods=["POST"])
@login_required
def add_timeline_event(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    event_time = normalize_timestamp(request.form.get("event_time"))
    description = request.form.get("description", "").strip()
    if not event_time or not description:
        flash("A valid date/time and a description are required.", "danger")
        return back_to(case_number, "timeline")
    evidence_id = request.form.get("source_evidence_id", type=int)
    if evidence_id and not query_one("SELECT 1 FROM evidence WHERE id = ? AND case_id = ?", (evidence_id, case["id"])):
        evidence_id = None
    execute("INSERT INTO timeline_events (case_id, event_time, event_type, description, source, source_evidence_id, "
            "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (case["id"], event_time, request.form.get("event_type", "").strip() or "Incident event", description,
             request.form.get("source", "").strip() or f"Entered by {current_user()['full_name']}",
             evidence_id, current_user()["id"], now_str()))
    log_activity(current_user()["id"], "Timeline event added", "case", case_number, event_time)
    flash("Timeline event added.", "success")
    return back_to(case_number, "timeline")


# ============================================================ relationships

def _valid_node(node_key, known):
    node_type, _, ref = node_key.partition(":")
    if node_key in known:
        return True
    return node_type in ("location", "device") and bool(ref.strip())


@bp.route("/cases/<case_number>/relationships", methods=["POST"])
@login_required
def add_relationship(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    known = case_node_labels(case["id"])
    source = request.form.get("source_node", "")
    target = request.form.get("target_node", "")
    if target == "__new__":
        new_type = request.form.get("new_type", "")
        new_label = " ".join(request.form.get("new_label", "").split())
        target = f"{new_type}:{new_label}" if new_type in ("location", "device") and new_label else ""
    relationship_type = request.form.get("relationship_type", "").strip()
    description = request.form.get("description", "").strip()
    if not (_valid_node(source, known) and _valid_node(target, known)) or source == target:
        flash("Choose two different nodes that belong to this case.", "danger")
    elif not relationship_type or not description:
        flash("Every link needs a type and the recorded basis for it (description).", "danger")
    else:
        execute("INSERT INTO evidence_relationships (case_id, source_node, target_node, relationship_type, "
                "description, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case["id"], source, target, relationship_type, description, current_user()["id"], now_str()))
        for node in (source, target):
            if node.startswith("evidence:"):
                record_custody_event(int(node.split(":")[1]), current_user()["id"], "Evidence notes updated",
                                     f"Relationship recorded: {relationship_type}")
        log_activity(current_user()["id"], "Relationship recorded", "case", case_number,
                     f"{source} -[{relationship_type}]- {target}")
        flash("Relationship recorded.", "success")
    return redirect(request.form.get("back") or url_for("cases.view_case", case_number=case_number, tab="forensics"))


@bp.route("/relationships/<int:rel_id>/delete", methods=["POST"])
@login_required
def delete_relationship(rel_id):
    rel = query_one("SELECT * FROM evidence_relationships WHERE id = ?", (rel_id,))
    if rel is None:
        abort(404)
    case, _ = require_case_access(case_id=rel["case_id"], need_edit=True)
    execute("DELETE FROM evidence_relationships WHERE id = ?", (rel_id,))
    log_activity(current_user()["id"], "Relationship removed", "case", case["case_number"],
                 f"{rel['source_node']} -[{rel['relationship_type']}]- {rel['target_node']}")
    flash("Relationship removed.", "info")
    return back_to(case["case_number"], "forensics")


@bp.route("/cases/<case_number>/graph")
@login_required
def graph_page(case_number):
    case, permission = require_case_access(case_number)
    graph = build_case_graph(case["id"])
    return render_template("graph.html", case=case, permission=permission, graph=graph.to_json(),
                           node_count=graph.node_count(), edge_count=graph.edge_count(),
                           start=request.args.get("start", ""))


@bp.route("/cases/<case_number>/graph/traverse", methods=["POST"])
@login_required
def graph_traverse(case_number):
    """Run BFS or DFS in Python and return the visit order as JSON."""
    case, _ = require_case_access(case_number)
    payload = request.get_json(silent=True) or {}
    start = payload.get("start", "")
    algorithm = payload.get("algorithm", "bfs")
    target = payload.get("target") or None
    graph = build_case_graph(case["id"])
    if start not in graph.adjacency:
        return jsonify({"error": "Choose a start node from this case."}), 400

    steps = []
    if algorithm == "dfs":
        order = graph.dfs(start, steps=steps)
        distances = {}
    else:
        algorithm = "bfs"
        order, distances = graph.bfs(start, steps=steps)

    direct = [{"id": n, "label": graph.label(n), "type": info.get("type"), "description": info.get("description")}
              for n, info in graph.neighbors(start)]
    path = None
    if target and target in graph.adjacency:
        hops = graph.find_path(start, target)
        path = None if hops is None else [{
            "from": graph.label(a), "to": graph.label(b), "type": info.get("type"),
            "description": info.get("description"),
            "recorded": f"{graph.label(info['recorded_from'])} -> {graph.label(info['recorded_to'])}",
        } for a, b, info in hops]

    log_activity(current_user()["id"], f"Graph traversal ({algorithm.upper()})", "case", case_number, start)
    return jsonify({
        "algorithm": algorithm,
        "start": start,
        "order": [{"id": n, "label": graph.label(n), "level": distances.get(n)} for n in order],
        "unreached": [n for n in graph.adjacency if n not in set(order)],
        "direct": direct,
        "steps": steps,
        "path": path,
        "target": target,
    })


# ============================================================ analysis queue

@bp.route("/cases/<case_number>/tasks", methods=["POST"])
@login_required
def enqueue_task(case_number):
    case, _ = require_case_access(case_number, need_edit=True)
    evidence_id = request.form.get("evidence_id", type=int)
    task_type = request.form.get("task_type")
    evidence = query_one("SELECT * FROM evidence WHERE id = ? AND case_id = ?", (evidence_id, case["id"]))
    if evidence is None or task_type not in TASK_TYPES:
        flash("Choose an evidence item and a task.", "danger")
    elif task_type == "import_csv_timeline" and evidence["file_type"] != "csv":
        flash("Only CSV activity logs can be imported into the timeline.", "warning")
    else:
        execute("INSERT INTO analysis_tasks (case_id, evidence_id, task_type, requested_by, created_at) "
                "VALUES (?, ?, ?, ?, ?)", (case["id"], evidence_id, task_type, current_user()["id"], now_str()))
        log_activity(current_user()["id"], "Analysis task queued", "evidence", evidence["evidence_code"], task_type)
        flash(f"Queued: {TASK_TYPES[task_type]} for {evidence['evidence_code']}.", "success")
    return back_to(case_number, "forensics")


@bp.route("/cases/<case_number>/tasks/process", methods=["POST"])
@login_required
def process_tasks(case_number):
    """Load pending tasks into a FIFO Queue and process the oldest one (or all)."""
    case, _ = require_case_access(case_number, need_edit=True)
    queue = Queue()
    for task in query_all("SELECT * FROM analysis_tasks WHERE case_id = ? AND status = 'pending' ORDER BY id",
                          (case["id"],)):
        queue.enqueue(task)
    if queue.is_empty():
        flash("No pending tasks.", "info")
        return back_to(case_number, "forensics")
    limit = len(queue) if request.form.get("all") else 1
    processed = 0
    while not queue.is_empty() and processed < limit:
        task = queue.dequeue()
        status, result = _run_task(task)
        execute("UPDATE analysis_tasks SET status = ?, result = ?, processed_by = ?, processed_at = ? WHERE id = ?",
                (status, result, current_user()["id"], now_str(), task["id"]))
        processed += 1
        flash(f"Task #{task['id']} ({TASK_TYPES[task['task_type']]}): {result}",
              "success" if status == "done" else "danger")
    log_activity(current_user()["id"], "Analysis tasks processed", "case", case_number,
                 f"{processed} processed, {len(queue)} still pending")
    return back_to(case_number, "forensics")


def _run_task(task):
    evidence = get_evidence(task["evidence_id"])
    user_id = current_user()["id"]
    try:
        path = evidence_abspath(evidence["storage_path"])
        if task["task_type"] == "verify_integrity":
            outcome = verify_evidence(evidence, user_id)
            return "done", f"{outcome['result']} (current hash {(outcome['current'] or 'n/a')[:16]}...)"
        if not os.path.exists(path):
            return "failed", "Registered file is missing from evidence storage."
        if task["task_type"] == "import_csv_timeline":
            imported, _, message = import_csv_activity_log(evidence, path, user_id)
            record_custody_event(evidence["id"], user_id, "Evidence analysed", message)
            return ("done" if imported or "already" in message else "failed"), message
        if task["task_type"] == "extract_metadata":
            return "done", _extract_metadata(evidence, path)
    except (OSError, ValueError) as error:
        return "failed", f"Could not process file: {error}"
    return "failed", "Unknown task type."


def _extract_metadata(evidence, path):
    """Read basic facts from the file itself (read-only)."""
    size = os.path.getsize(path)
    parts = [f"{size:,} bytes on disk", f"type {mimetypes.guess_type(evidence['filename'])[0] or 'unknown'}"]
    if size != evidence["file_size"]:
        parts.append(f"WARNING: registered size was {evidence['file_size']:,} bytes")
    if evidence["file_type"] in ("text", "csv"):
        with open(path, encoding="utf-8", errors="replace") as handle:
            parts.append(f"{sum(1 for _ in handle)} lines")
    elif evidence["file_type"] == "pdf":
        with open(path, "rb") as handle:
            data = handle.read()
        parts.append(f"about {max(data.count(b'/Type /Page') - data.count(b'/Type /Pages'), 1)} page(s)")
    elif evidence["file_type"] == "image":
        with open(path, "rb") as handle:
            head = handle.read(32)
        if head.startswith(b"\x89PNG") and len(head) >= 24:
            parts.append(f"{int.from_bytes(head[16:20], 'big')} x {int.from_bytes(head[20:24], 'big')} pixels")
    record_custody_event(evidence["id"], current_user()["id"], "Evidence analysed", "Metadata extracted (read-only)")
    return "; ".join(parts)


# ================================================================== findings

@bp.route("/cases/<case_number>/findings", methods=["POST"])
@login_required
def submit_findings(case_number):
    """Save the investigator's own findings. Nothing is compared to any 'answer'."""
    case, permission = require_case_access(case_number, need_edit=True)
    text = request.form.get("findings_text", "").strip()
    if not text:
        flash("Write your findings before submitting.", "danger")
        return back_to(case_number, "reports")
    suspect_id = request.form.get("selected_suspect_id", type=int)
    if suspect_id and not query_one("SELECT 1 FROM suspects WHERE id = ? AND case_id = ?", (suspect_id, case["id"])):
        suspect_id = None
    db = get_db()
    cursor = db.execute("INSERT INTO investigation_findings (case_id, submitted_by, selected_suspect_id, "
                        "findings_text, submitted_at) VALUES (?, ?, ?, ?, ?)",
                        (case["id"], current_user()["id"], suspect_id, text, now_str()))
    finding_id = cursor.lastrowid
    for evidence_id in request.form.getlist("evidence_ids", type=int):
        if db.execute("SELECT 1 FROM evidence WHERE id = ? AND case_id = ?", (evidence_id, case["id"])).fetchone():
            db.execute("INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id) VALUES (?, ?)",
                       (finding_id, evidence_id))
    if request.form.get("mark_pending_review") and case["status"] != "Closed":
        db.execute("UPDATE cases SET status = 'Pending Review' WHERE id = ?", (case["id"],))
    db.commit()
    log_activity(current_user()["id"], "Investigation findings submitted", "case", case_number)
    flash("Findings saved to the case record.", "success")
    return back_to(case_number, "reports")
