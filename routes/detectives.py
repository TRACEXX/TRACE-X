import re

from flask import Blueprint, redirect, render_template, request, url_for

from database.db import placeholders, query_all
from database.queries import (build_evidence_index, cases_for_user_with_role, evidence_for_cases,
                              list_cases, suspect_code, witness_code)
from dsa.searching import binary_search, keyword_search
from dsa.sorting import merge_sort
from routes.auth import accessible_case_ids, current_user, is_admin, login_required

bp = Blueprint("detectives", __name__)


@bp.route("/portal")
@login_required
def portal():
    user = current_user()
    if is_admin(user):
        return redirect(url_for("admin.dashboard"))
    my_cases = cases_for_user_with_role(user["id"])
    case_ids = [c["id"] for c in my_cases]
    awaiting = []
    activity = []
    if case_ids:
        marks = placeholders(case_ids)
        awaiting = query_all(
            "SELECT e.*, c.case_number FROM evidence e JOIN cases c ON c.id = e.case_id "
            f"WHERE e.case_id IN ({marks}) AND e.integrity_status != 'MATCH' ORDER BY e.uploaded_at DESC",
            tuple(case_ids))
        activity = query_all(
            "SELECT ce.*, e.evidence_code, c.case_number, u.full_name FROM custody_events ce "
            "JOIN evidence e ON e.id = ce.evidence_id JOIN cases c ON c.id = e.case_id "
            f"LEFT JOIN users u ON u.id = ce.user_id WHERE e.case_id IN ({marks}) "
            "ORDER BY ce.timestamp DESC, ce.id DESC LIMIT 10", tuple(case_ids))
    return render_template("detective_portal.html", user=user,
                           assigned=[c for c in my_cases if c["my_role"] != "viewer"],
                           shared=[c for c in my_cases if c["my_role"] == "viewer"],
                           awaiting=awaiting, activity=activity)


@bp.route("/cases")
@login_required
def case_list():
    user = current_user()
    if is_admin(user):
        cases = [dict(c) | {"my_role": "admin"} for c in list_cases()]
    else:
        cases = cases_for_user_with_role(user["id"])
    status = request.args.get("status", "")
    if status:
        cases = [c for c in cases if c["status"] == status]
    return render_template("case_list.html", cases=cases, status=status)


@bp.route("/search")
@login_required
def search():
    """Search only the cases this user may open."""
    query = request.args.get("q", "").strip()
    results = None
    algorithm_notes = []
    if query:
        results, algorithm_notes = run_search(current_user(), query)
    return render_template("search.html", query=query, results=results, algorithm_notes=algorithm_notes)


def run_search(user, query):
    case_ids = accessible_case_ids(user)
    notes = []
    results = {"exact": [], "cases": [], "suspects": [], "witnesses": [], "evidence": [], "notes": []}
    if not case_ids:
        return results, ["You have no accessible cases to search."]
    marks = placeholders(case_ids)
    params = tuple(case_ids)

    # 1) Exact case number -> BINARY SEARCH over case numbers sorted with merge sort.
    case_match = re.search(r"case[\s\-#]*0*(\d{1,4})", query, re.I)
    if case_match:
        wanted = f"CASE-{int(case_match.group(1)):03d}"
        cases = merge_sort([dict(c) for c in list_cases(case_ids)], key=lambda c: c["case_number"])
        steps = []
        index = binary_search(cases, wanted, key=lambda c: c["case_number"], steps=steps)
        notes.append(f"Binary search for {wanted} in {len(cases)} sorted case numbers: "
                     f"{len(steps)} comparison(s), {'found' if index >= 0 else 'not found'}.")
        if index >= 0:
            c = cases[index]
            results["exact"].append({"label": f"{c['case_number']} {c['title']}",
                                     "url": url_for("cases.view_case", case_number=c["case_number"]),
                                     "kind": "Case"})

    # 2) Exact evidence ID -> HASH TABLE lookup.
    ev_match = re.search(r"\bev[\s\-]*0*(\d{1,5})\b", query, re.I)
    if ev_match:
        code = f"EV-{int(ev_match.group(1)):04d}"
        index = build_evidence_index(evidence_for_cases(case_ids))
        item, bucket, comparisons = index.get_with_trace(code)
        notes.append(f"Hash table lookup for {code}: bucket {bucket} of {index.capacity}, "
                     f"{comparisons} comparison(s), {'found' if item else 'not found'}.")
        if item:
            results["exact"].append({"label": f"{item['evidence_code']} {item['filename']}",
                                     "url": url_for("evidence.view", evidence_id=item["id"]),
                                     "kind": "Evidence"})

    # 3) Keyword search (linear scan with scoring), ranked with merge sort.
    def ranked(rows, fields, weights):
        scored = keyword_search([dict(r) for r in rows], query, fields, weights)
        return [record for _, record in merge_sort(scored, key=lambda pair: pair[0], reverse=True)]

    cases = query_all(f"SELECT * FROM cases WHERE id IN ({marks})", params)
    results["cases"] = ranked(cases, ["case_number", "title", "category", "location", "description", "summary"],
                              {"title": 3, "case_number": 3})
    suspects = query_all("SELECT s.*, c.case_number FROM suspects s JOIN cases c ON c.id = s.case_id "
                         f"WHERE s.case_id IN ({marks})", params)
    results["suspects"] = [s | {"code": suspect_code(s["id"])} for s in
                           ranked(suspects, ["name", "background", "relationship", "motive", "alibi", "statements"],
                                  {"name": 3})]
    witnesses = query_all("SELECT w.*, c.case_number FROM witnesses w JOIN cases c ON c.id = w.case_id "
                          f"WHERE w.case_id IN ({marks})", params)
    results["witnesses"] = [w | {"code": witness_code(w["id"])} for w in
                            ranked(witnesses, ["name", "statement"], {"name": 3})]
    evidence = query_all("SELECT e.*, c.case_number FROM evidence e JOIN cases c ON c.id = e.case_id "
                         f"WHERE e.case_id IN ({marks})", params)
    results["evidence"] = ranked(evidence, ["evidence_code", "filename", "description", "notes", "camera_id"],
                                 {"evidence_code": 3, "filename": 2})
    notes_rows = query_all("SELECT n.*, c.case_number FROM investigation_notes n JOIN cases c ON c.id = n.case_id "
                           f"WHERE n.case_id IN ({marks})", params)
    results["notes"] = ranked(notes_rows, ["title", "content"], {"title": 2})
    total = sum(len(v) for k, v in results.items() if k != "exact")
    notes.append(f"Keyword search scanned {len(cases) + len(suspects) + len(witnesses) + len(evidence) + len(notes_rows)} "
                 f"records linearly and merge-sorted {total} match(es) by relevance.")
    return results, notes
