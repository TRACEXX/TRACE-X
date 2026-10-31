"""
Turns a detective's question into (1) an intent and (2) a structured context
containing ONLY records the user is authorised to see.

The LLM never touches the database. Python decides what to look up using
fixed functions (no SQL is ever generated from the user's message), then
hands the LLM a JSON snapshot of those records.
"""

import json
import re

from database.db import placeholders, query_all

SYSTEM_PROMPT = """You are TRACE AI, the investigation assistant inside TRACE X, a case-management
system used with FICTIONAL training cases.

Rules you must follow:
- Use ONLY the records in the AUTHORISED RECORDS block. Do not invent people, evidence,
  times, places or statements.
- If the question asks for something that is not in the records, say clearly that it is
  "not recorded in TRACE X".
- Never state or imply that any person is guilty, and never name a culprit. You may point
  out inconsistencies, gaps and what could be checked next.
- Keep stored facts and your own interpretation clearly separate.
- Refer to records by their IDs (CASE-001, EV-0003, S-002, W-001).
- Be concise and use plain language."""

ANSWER_FORMAT = """Answer in exactly these three parts:
RECORDED FACTS: short bullet points taken directly from the records.
INTERPRETATION (AI-generated): brief observations, clearly your own reading of the records.
MISSING INFORMATION: anything relevant that is not recorded."""

CASE_PATTERN = re.compile(r"\bcase[\s\-#:]*0*(\d{1,4})\b", re.I)
SUSPECT_CODE_PATTERN = re.compile(r"\bS-0*(\d{1,4})\b", re.I)
TEXT_LIMIT = 700


def parse_case_numbers(text):
    return [f"CASE-{int(n):03d}" for n in CASE_PATTERN.findall(text or "")]


def find_detective(text):
    """Return the detective row whose first name or full name appears in the text."""
    lowered = (text or "").lower()
    for detective in query_all("SELECT * FROM users WHERE role = 'detective'"):
        full = detective["full_name"].lower()
        first = full.split()[0]
        if re.search(rf"\b{re.escape(full)}\b", lowered) or re.search(rf"\b{re.escape(first)}\b", lowered) \
                or re.search(rf"\b{re.escape(detective['username'])}\b", lowered):
            return detective
    return None


def find_suspects(text, case_ids):
    """Suspects (in accessible cases) mentioned by full name, a name part, or S-### code."""
    if not case_ids:
        return []
    lowered = (text or "").lower()
    codes = {int(n) for n in SUSPECT_CODE_PATTERN.findall(text or "")}
    rows = query_all(
        "SELECT s.*, c.case_number FROM suspects s JOIN cases c ON c.id = s.case_id "
        f"WHERE s.case_id IN ({placeholders(case_ids)})", tuple(case_ids))
    matches = []
    for row in rows:
        name = row["name"].lower()
        parts = [p for p in re.findall(r"[a-z]+", name) if len(p) >= 4]
        if row["id"] in codes or name in lowered or any(re.search(rf"\b{p}\b", lowered) for p in parts):
            matches.append(row)
    return matches


def detect_intent(text):
    q = (text or "").lower()
    has_case = bool(CASE_PATTERN.search(q))
    if "report" in q and any(w in q for w in ("generate", "create", "make", "produce", "download")):
        return "report"
    if any(w in q for w in ("fail", "mismatch", "missing", "tamper", "alert")) and \
            any(w in q for w in ("integrity", "verif", "hash", "evidence")):
        return "integrity_failures"
    if "summar" in q or "overview" in q or "brief me" in q:
        return "summary"
    if any(w in q for w in ("timeline", "sequence", "chronolog", "order of events", "what happened when")):
        return "timeline"
    if "evidence" in q and any(w in q for w in ("connect", "link", "related", "against", "tied", "associated")) \
            and not has_case:
        return "suspect_evidence"
    if "evidence" in q and ("suspect" in q or SUSPECT_CODE_PATTERN.search(q)):
        return "suspect_evidence"
    if "evidence" in q:
        return "evidence"
    if "assigned" in q or "my cases" in q or ("cases" in q and "detective" in q):
        return "detective_cases"
    if "witness" in q or "statement" in q:
        return "witnesses"
    if "suspect" in q:
        return "suspects"
    if has_case:
        return "show_case"
    if q.strip() in ("cases", "list cases", "show cases", "all cases"):
        return "detective_cases"
    return "search"


def _clip(value):
    text = "" if value is None else str(value)
    return text if len(text) <= TEXT_LIMIT else text[:TEXT_LIMIT] + " ...[truncated]"


def llm_case_context(bundle, parts=("case", "suspects", "witnesses", "evidence", "timeline", "notes",
                                    "relationships", "findings")):
    """Reduce a case bundle to the fields the LLM needs, with long text clipped."""
    case = bundle["case"]
    context = {}
    if "case" in parts:
        context["case"] = {
            "case_id": case["case_number"], "title": case["title"], "category": case["category"],
            "status": case["status"], "incident_date": case["incident_date"], "location": case["location"],
            "description": _clip(case["description"]), "summary": _clip(case["summary"]),
            "investigators": [f"{t['full_name']} ({t['permission_level']})" for t in bundle["team"]],
        }
    if "suspects" in parts:
        context["suspects"] = [{
            "id": s["code"], "name": s["name"], "relationship_to_incident": _clip(s["relationship"]),
            "background": _clip(s["background"]), "possible_motive": _clip(s["motive"]),
            "alibi": _clip(s["alibi"]), "statements": _clip(s["statements"]),
        } for s in bundle["suspects"]]
    if "witnesses" in parts:
        context["witness_statements"] = [{
            "id": w["code"], "name": w["name"], "recorded_at": w["recorded_at"],
            "statement": _clip(w["statement"]), "mentions_suspect": w["related_suspect_name"],
            "related_evidence": w["related_evidence_code"],
        } for w in bundle["witnesses"]]
    if "evidence" in parts:
        context["evidence"] = [{
            "id": e["evidence_code"], "file": e["filename"], "type": e["file_type"],
            "description": _clip(e["description"]), "investigator_notes": _clip(e["notes"]),
            "uploaded_to_system_at": e["uploaded_at"], "recording_time_if_known": e["recorded_at"],
            "camera": e["camera_id"], "integrity_status": e["integrity_status"],
        } for e in bundle["evidence"]]
    if "timeline" in parts:
        context["timeline_sorted"] = [{
            "time": t["time"], "type": t["type"], "description": _clip(t["description"]), "source": t["source"],
        } for t in bundle["timeline"]]
    if "notes" in parts:
        context["investigator_notes"] = [{"title": n["title"], "author": n["author_name"],
                                          "content": _clip(n["content"])} for n in bundle["notes"]]
    if "relationships" in parts:
        context["recorded_relationships"] = [{
            "from": r["source_label"], "to": r["target_label"], "type": r["relationship_type"],
            "basis": _clip(r["description"]),
        } for r in bundle["relationships"]]
    if "findings" in parts:
        context["submitted_findings"] = [{"by": f["submitted_by_name"], "at": f["submitted_at"],
                                          "text": _clip(f["findings_text"])} for f in bundle["findings"]]
    return context


def build_llm_prompt(question, context):
    return (f"QUESTION FROM THE INVESTIGATOR:\n{question}\n\n"
            f"AUTHORISED RECORDS (JSON):\n{json.dumps(context, indent=1, default=str)}\n\n{ANSWER_FORMAT}")


def deterministic_summary(bundle):
    """A plain, rule-based summary built only from stored records (no LLM)."""
    case = bundle["case"]
    evidence = bundle["evidence"]
    verified = sum(1 for e in evidence if e["integrity_status"] == "MATCH")
    alerts = [e["evidence_code"] for e in evidence if e["integrity_status"] in ("MISMATCH", "FILE MISSING")]
    unverified = sum(1 for e in evidence if e["integrity_status"] == "UNVERIFIED")
    lead = next((t["full_name"] for t in bundle["team"] if t["permission_level"] == "lead"), "no lead assigned")
    lines = [
        f"{case['case_number']} \"{case['title']}\" is a {case['category'].lower()} case with status "
        f"{case['status']}. Incident date: {case['incident_date'] or 'not recorded'}; "
        f"location: {case['location'] or 'not recorded'}. Lead investigator: {lead}.",
    ]
    if bundle["suspects"]:
        lines.append(f"{len(bundle['suspects'])} suspect(s) on record: "
                     + ", ".join(f"{s['name']} ({s['code']})" for s in bundle["suspects"]) + ".")
    else:
        lines.append("No suspects are recorded.")
    lines.append(f"{len(bundle['witnesses'])} witness statement(s) recorded.")
    lines.append(f"{len(evidence)} evidence item(s): {verified} verified MATCH, {unverified} not yet verified"
                 + (f", integrity alerts on {', '.join(alerts)}" if alerts else ", no integrity alerts") + ".")
    if bundle["timeline"]:
        first, last = bundle["timeline"][0], bundle["timeline"][-1]
        lines.append(f"The timeline holds {len(bundle['timeline'])} recorded event(s) from {first['time']} "
                     f"({first['type']}) to {last['time']} ({last['type']}).")
    else:
        lines.append("No timeline events are recorded.")
    lines.append(f"{len(bundle['relationships'])} recorded relationship(s) and "
                 f"{len(bundle['findings'])} submitted finding(s).")
    if case["summary"]:
        lines.append(f"Investigator summary on file: {case['summary']}")
    return "\n".join(lines)
