"""TRACE AI page and the JSON endpoint the chat panel calls."""

from flask import Blueprint, jsonify, render_template, request

from ai.assistant import answer_question
from ai.providers import provider_status
from database.queries import get_case_by_number
from routes.auth import accessible_case_ids, current_user, login_required

bp = Blueprint("ai", __name__, url_prefix="/ai")

EXAMPLES = [
    "Show me Case 001",
    "Show all cases assigned to Detective Amna",
    "Summarize Case 003",
    "What evidence is available in Case 002?",
    "Which evidence items failed integrity verification?",
    "What evidence is connected to Kamran Sheikh?",
    "Explain the timeline of Case 001",
    "Generate an investigation report for Case 001",
]


@bp.route("/")
@login_required
def page():
    page_case = request.args.get("case", "")
    case = get_case_by_number(page_case) if page_case else None
    if case is not None and case["id"] not in accessible_case_ids(current_user()):
        case = None
    return render_template("ai.html", examples=EXAMPLES, provider=provider_status(), case=case)


@bp.route("/ask", methods=["POST"])
@login_required
def ask():
    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    if not question:
        return jsonify({"error": "Type a question first."}), 400
    page_case = payload.get("case") or None
    return jsonify(answer_question(current_user(), question, page_case=page_case))
