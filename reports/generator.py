import os
from datetime import datetime
from xml.sax.saxutils import escape

from flask import current_app
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from ai.context_builder import SYSTEM_PROMPT, build_llm_prompt, deterministic_summary, llm_case_context
from ai.providers import AIProviderError, generate, provider_status
from database.db import execute, log_activity, now_str, query_all
from database.queries import case_bundle
from forensics.custody import load_custody_chain, verify_custody_chain

INK = colors.HexColor("#14202b")
MUTED = colors.HexColor("#5b6773")
ACCENT = colors.HexColor("#b7791f")
RULE = colors.HexColor("#d5dbe1")
TINT = colors.HexColor("#f3f5f7")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20,
                                textColor=INK, alignment=TA_LEFT, spaceAfter=2),
        "kicker": ParagraphStyle("kicker", fontName="Helvetica-Bold", fontSize=8, textColor=ACCENT,
                                 leading=10, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, textColor=INK, leading=16,
                             spaceBefore=12, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10.5, textColor=INK, leading=13,
                             spaceBefore=6, spaceAfter=3),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13, textColor=INK),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=10.5, textColor=MUTED),
        "hash": ParagraphStyle("hash", fontName="Courier", fontSize=7.4, leading=9.5, textColor=INK),
        "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5, leading=11, textColor=INK),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=MUTED),
    }


def _p(text, style):
    """Paragraph with escaped text (ReportLab treats < and & as markup)."""
    return Paragraph(escape(str(text if text not in (None, "") else "-")).replace("\n", "<br/>"), style)


def _kv_table(rows, styles, widths=(42 * mm, 128 * mm)):
    data = [[_p(k, styles["label"]), v if not isinstance(v, str) else _p(v, styles["cell"])] for k, v in rows]
    table = Table(data, colWidths=widths)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _grid(header, rows, styles, widths):
    data = [[_p(h, styles["label"]) for h in header]] + [[_p(c, styles["cell"]) for c in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TINT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "TRACE X - Digital Evidence Integrity & Investigation System - "
                                        "fictional training data")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_report_pdf(path, bundle, summary_text, summary_source, generated_by):
    s = _styles()
    case = bundle["case"]
    story = []

    story.append(_p("TRACE X  |  INVESTIGATION REPORT", s["kicker"]))
    story.append(_p(f"{case['case_number']}: {case['title']}", s["title"]))
    story.append(_p(f"Generated {datetime.now().strftime('%d %B %Y, %H:%M')} by {generated_by}", s["small"]))
    story.append(Spacer(1, 8))
    story.append(_kv_table([
        ("Case ID", case["case_number"]), ("Status", case["status"]), ("Category", case["category"]),
        ("Incident date", case["incident_date"] or "Not recorded"), ("Location", case["location"] or "Not recorded"),
        ("Date opened", case["created_at"]),
        ("Assigned detectives", ", ".join(f"{t['full_name']} ({t['badge_id']}, {t['permission_level']})"
                                          for t in bundle["team"]) or "None assigned"),
    ], s))

    story.append(_p("Case description (recorded)", s["h2"]))
    story.append(_p(case["description"] or "No description recorded.", s["body"]))
    if case["summary"]:
        story.append(_p("Investigator summary (recorded)", s["h3"]))
        story.append(_p(case["summary"], s["body"]))

    label = ("AUTOMATED SUMMARY - AI-GENERATED INTERPRETATION" if summary_source.startswith("ai")
             else "AUTOMATED SUMMARY - RULE-BASED, FROM STORED RECORDS (NO AI)")
    box = Table([[_p(label, s["kicker"])], [_p(summary_text, s["body"])],
                 [_p("This summary is produced automatically. It is not evidence and does not determine guilt. "
                     "Check every statement against the recorded sections below.", s["small"])]],
                colWidths=[170 * mm])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), TINT), ("BOX", (0, 0), (-1, -1), 0.6, ACCENT),
                             ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(Spacer(1, 8))
    story.append(box)

    story.append(_p(f"Suspects ({len(bundle['suspects'])})", s["h2"]))
    for suspect in bundle["suspects"]:
        story.append(KeepTogether([_p(f"{suspect['code']}  {suspect['name']}", s["h3"]), _kv_table([
            ("Relationship", suspect["relationship"]), ("Background", suspect["background"]),
            ("Possible motive", suspect["motive"]), ("Alibi", suspect["alibi"]),
            ("Recorded statements", suspect["statements"]), ("Notes", suspect["notes"]),
        ], s)]))
    if not bundle["suspects"]:
        story.append(_p("No suspects recorded.", s["body"]))

    story.append(_p(f"Witness statements ({len(bundle['witnesses'])})", s["h2"]))
    for witness in bundle["witnesses"]:
        story.append(KeepTogether([_p(f"{witness['code']}  {witness['name']}", s["h3"]), _kv_table([
            ("Recorded", f"{witness['recorded_at']} by {witness['recorded_by_name'] or 'unknown'}"),
            ("Statement", witness["statement"]),
            ("Mentions suspect", witness["related_suspect_name"] or "-"),
            ("Related evidence", witness["related_evidence_code"] or "-"),
            ("Revisions kept", str(witness["revision_count"])),
        ], s)]))
    if not bundle["witnesses"]:
        story.append(_p("No witness statements recorded.", s["body"]))

    story.append(PageBreak())
    story.append(_p(f"Evidence inventory and SHA-256 verification ({len(bundle['evidence'])})", s["h2"]))
    for item in bundle["evidence"]:
        checks = query_all("SELECT i.*, u.full_name FROM integrity_checks i LEFT JOIN users u ON u.id = i.checked_by "
                           "WHERE evidence_id = ? ORDER BY i.id DESC LIMIT 3", (item["id"],))
        check_text = "\n".join(f"{c['checked_at']}  {c['result']}  ({c['full_name'] or 'unknown'})" for c in checks) \
            or "Never verified"
        story.append(KeepTogether([_p(f"{item['evidence_code']}  {item['filename']}", s["h3"]), _kv_table([
            ("Type / size", f"{item['file_type']} / {item['file_size']:,} bytes"),
            ("Registered", f"{item['uploaded_at']} by {item['uploaded_by_name'] or 'unknown'} (system upload time)"),
            ("Recording time", item["recorded_at"] or "Not recorded"),
            ("Description", item["description"]),
            ("Original SHA-256", _p(item["original_sha256"], s["hash"])),
            ("Current status", item["integrity_status"]),
            ("Recent checks", check_text),
            ("Custodian", item["custodian_name"] or "-"),
        ], s)]))

    story.append(_p("Chain-of-custody summary", s["h2"]))
    rows = []
    for item in bundle["evidence"]:
        chain = load_custody_chain(item["id"]).to_list()
        verdict = verify_custody_chain(item["id"])
        rows.append([item["evidence_code"], str(len(chain)),
                     chain[0]["timestamp"] if chain else "-", chain[-1]["timestamp"] if chain else "-",
                     "Intact" if verdict["valid"] else f"BROKEN at record {verdict['broken_at']}"])
    story.append(_grid(["Evidence", "Events", "First event", "Last event", "Audit hash chain"], rows, s,
                       [26 * mm, 18 * mm, 38 * mm, 38 * mm, 50 * mm]) if rows else _p("No evidence.", s["body"]))

    story.append(_p(f"Investigation timeline ({len(bundle['timeline'])} recorded events, merge-sorted)", s["h2"]))
    if bundle["timeline"]:
        story.append(_grid(["Time", "Event", "Description", "Source"],
                           [[t["time"], t["type"], t["description"], t["source"]] for t in bundle["timeline"]],
                           s, [30 * mm, 32 * mm, 70 * mm, 38 * mm]))
    else:
        story.append(_p("No timeline events recorded.", s["body"]))

    story.append(_p("Recorded relationships", s["h2"]))
    if bundle["relationships"]:
        story.append(_grid(["From", "Link", "To", "Recorded basis"],
                           [[r["source_label"], r["relationship_type"], r["target_label"], r["description"]]
                            for r in bundle["relationships"]], s, [38 * mm, 28 * mm, 38 * mm, 66 * mm]))
    else:
        story.append(_p("No relationships recorded.", s["body"]))

    story.append(_p(f"Investigator notes ({len(bundle['notes'])})", s["h2"]))
    for note in bundle["notes"]:
        story.append(KeepTogether([_p(f"{note['title']} - {note['author_name']}, {note['updated_at']}", s["h3"]),
                                   _p(note["content"], s["body"])]))
    if not bundle["notes"]:
        story.append(_p("No notes recorded.", s["body"]))

    story.append(_p("Submitted findings", s["h2"]))
    for finding in bundle["findings"]:
        refs = ", ".join(e["evidence_code"] for e in finding["evidence"]) or "none"
        story.append(KeepTogether([
            _p(f"{finding['submitted_by_name']} - {finding['submitted_at']}", s["h3"]),
            _p(finding["findings_text"], s["body"]),
            _p(f"Suspect referenced: {finding['suspect_name'] or 'none'}. Supporting evidence: {refs}. "
               "Recorded as the investigator's own finding; TRACE X does not evaluate it.", s["small"]),
        ]))
    if not bundle["findings"]:
        story.append(_p("No findings recorded yet.", s["body"]))

    story.append(Spacer(1, 14))
    story.append(_p("Notice: this report compiles recorded information. It does not declare guilt or identify "
                    "a culprit. An integrity MISMATCH shows that a stored file differs from its registered "
                    "fingerprint; it does not show who changed it.", s["small"]))

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=f"{case['case_number']} Investigation Report",
                            author="TRACE X")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


def create_case_report(case_id, user, use_ai=True):
    """Build and store a PDF report. Returns (report id, summary source)."""
    bundle = case_bundle(case_id)
    summary_text = deterministic_summary(bundle)
    summary_source = "deterministic"
    status = provider_status()
    if use_ai and status["configured"]:
        try:
            question = ("Write a neutral investigation summary of this case for the report: what is recorded, "
                        "what the evidence and timeline show, open questions. Do not assess guilt.")
            summary_text = generate(SYSTEM_PROMPT, build_llm_prompt(question, llm_case_context(bundle)))
            summary_source = f"ai:{status['name']}"
        except AIProviderError as error:
            summary_text += f"\n\n(AI summary unavailable: {error})"

    folder = current_app.config["REPORTS_DIR"]
    os.makedirs(folder, exist_ok=True)
    filename = f"{bundle['case']['case_number']}_report_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.pdf"
    build_report_pdf(os.path.join(folder, filename), bundle, summary_text, summary_source,
                     f"{user['full_name']} ({user['badge_id'] or user['role']})")
    report_id = execute("INSERT INTO ai_reports (case_id, generated_by, report_path, summary_source, created_at) "
                        "VALUES (?, ?, ?, ?, ?)", (case_id, user["id"], filename, summary_source, now_str()))
    log_activity(user["id"], "Report generated", "case", bundle["case"]["case_number"], summary_source)
    return report_id, summary_source
