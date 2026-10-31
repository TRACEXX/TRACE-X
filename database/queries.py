"""
Reusable read queries.

The case page, TRACE AI and the PDF report all need the same information, so
the SQL lives here once instead of being copied into every route.
"""

from database.db import get_db, placeholders, query_all, query_one
from dsa.graph import Graph
from dsa.hash_table import HashTable

STATUSES = ["Open", "Under Investigation", "Pending Review", "Closed"]
PERMISSION_LEVELS = ["lead", "investigator", "viewer"]


def suspect_code(suspect_id):
    return f"S-{suspect_id:03d}"


def witness_code(witness_id):
    return f"W-{witness_id:03d}"


# ------------------------------------------------------------------ cases

def get_case_by_number(case_number):
    return query_one("SELECT * FROM cases WHERE case_number = ?", ((case_number or "").upper(),))


def get_case(case_id):
    return query_one("SELECT * FROM cases WHERE id = ?", (case_id,))


CASE_COLUMNS = """
    c.*,
    (SELECT u.full_name FROM case_assignments a JOIN users u ON u.id = a.user_id
      WHERE a.case_id = c.id AND a.permission_level = 'lead' LIMIT 1) AS lead_name,
    (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id) AS evidence_count,
    (SELECT COUNT(*) FROM suspects s WHERE s.case_id = c.id) AS suspect_count,
    (SELECT COUNT(*) FROM case_assignments a WHERE a.case_id = c.id) AS team_size
"""
CASE_LIST_SQL = "SELECT " + CASE_COLUMNS + " FROM cases c"


def list_cases(case_ids=None):
    """All cases (case_ids=None) or only the given ids."""
    if case_ids is None:
        return query_all(CASE_LIST_SQL + " ORDER BY c.case_number")
    if not case_ids:
        return []
    return query_all(CASE_LIST_SQL + f" WHERE c.id IN ({placeholders(case_ids)}) ORDER BY c.case_number",
                     tuple(case_ids))


def cases_for_user_with_role(user_id):
    """Cases a detective is on, with their permission level for each."""
    return query_all(
        "SELECT " + CASE_COLUMNS + ", me.permission_level AS my_role "
        "FROM cases c JOIN case_assignments me ON me.case_id = c.id "
        "WHERE me.user_id = ? ORDER BY c.case_number",
        (user_id,),
    )


def next_case_number():
    rows = query_all("SELECT case_number FROM cases")
    highest = 0
    for row in rows:
        try:
            highest = max(highest, int(row["case_number"].split("-")[1]))
        except (IndexError, ValueError):
            continue
    return f"CASE-{highest + 1:03d}"


def case_team(case_id):
    return query_all(
        "SELECT u.id, u.full_name, u.badge_id, u.username, u.profile_image, a.permission_level, a.assigned_at "
        "FROM case_assignments a JOIN users u ON u.id = a.user_id WHERE a.case_id = ? "
        "ORDER BY CASE a.permission_level WHEN 'lead' THEN 0 WHEN 'investigator' THEN 1 ELSE 2 END, u.full_name",
        (case_id,),
    )


def list_detectives():
    return query_all(
        "SELECT u.*, "
        "(SELECT COUNT(*) FROM case_assignments a WHERE a.user_id = u.id AND a.permission_level != 'viewer') AS assigned_count, "
        "(SELECT COUNT(*) FROM case_assignments a WHERE a.user_id = u.id AND a.permission_level = 'viewer') AS shared_count "
        "FROM users u WHERE u.role = 'detective' ORDER BY u.badge_id"
    )


# -------------------------------------------------------------- records

def case_suspects(case_id):
    return query_all("SELECT * FROM suspects WHERE case_id = ? ORDER BY id", (case_id,))


def get_suspect(suspect_id):
    return query_one(
        "SELECT s.*, c.case_number, c.title AS case_title FROM suspects s JOIN cases c ON c.id = s.case_id "
        "WHERE s.id = ?", (suspect_id,))


def case_witnesses(case_id):
    return query_all(
        "SELECT w.*, u.full_name AS recorded_by_name, s.name AS related_suspect_name, "
        "e.evidence_code AS related_evidence_code, "
        "(SELECT COUNT(*) FROM witness_history h WHERE h.witness_id = w.id) AS revision_count "
        "FROM witnesses w LEFT JOIN users u ON u.id = w.recorded_by "
        "LEFT JOIN suspects s ON s.id = w.related_suspect_id "
        "LEFT JOIN evidence e ON e.id = w.related_evidence_id "
        "WHERE w.case_id = ? ORDER BY w.recorded_at",
        (case_id,),
    )


def witness_history(witness_id):
    return query_all(
        "SELECT h.*, u.full_name AS edited_by_name FROM witness_history h "
        "LEFT JOIN users u ON u.id = h.edited_by WHERE h.witness_id = ? ORDER BY h.id DESC",
        (witness_id,),
    )


EVIDENCE_SQL = """
    SELECT e.*, c.case_number, c.title AS case_title,
           up.full_name AS uploaded_by_name, cu.full_name AS custodian_name
    FROM evidence e
    JOIN cases c ON c.id = e.case_id
    LEFT JOIN users up ON up.id = e.uploaded_by
    LEFT JOIN users cu ON cu.id = e.custodian_id
"""


def case_evidence(case_id):
    return query_all(EVIDENCE_SQL + " WHERE e.case_id = ? ORDER BY e.id", (case_id,))


def get_evidence(evidence_id):
    return query_one(EVIDENCE_SQL + " WHERE e.id = ?", (evidence_id,))


def evidence_for_cases(case_ids):
    if case_ids is None:
        return query_all(EVIDENCE_SQL + " ORDER BY e.id")
    if not case_ids:
        return []
    return query_all(EVIDENCE_SQL + f" WHERE e.case_id IN ({placeholders(case_ids)}) ORDER BY e.id",
                     tuple(case_ids))


def build_evidence_index(evidence_rows):
    """Load evidence rows into the custom HashTable, keyed by evidence code."""
    table = HashTable()
    for row in evidence_rows:
        table.put(row["evidence_code"], dict(row))
    return table


def case_notes(case_id):
    return query_all(
        "SELECT n.*, u.full_name AS author_name, "
        "(SELECT COUNT(*) FROM note_history h WHERE h.note_id = n.id) AS version_count "
        "FROM investigation_notes n LEFT JOIN users u ON u.id = n.user_id "
        "WHERE n.case_id = ? ORDER BY n.updated_at DESC",
        (case_id,),
    )


def case_findings(case_id):
    findings = query_all(
        "SELECT f.*, u.full_name AS submitted_by_name, s.name AS suspect_name FROM investigation_findings f "
        "LEFT JOIN users u ON u.id = f.submitted_by LEFT JOIN suspects s ON s.id = f.selected_suspect_id "
        "WHERE f.case_id = ? ORDER BY f.submitted_at DESC",
        (case_id,),
    )
    result = []
    for finding in findings:
        item = dict(finding)
        item["evidence"] = query_all(
            "SELECT e.id, e.evidence_code, e.filename FROM finding_evidence fe "
            "JOIN evidence e ON e.id = fe.evidence_id WHERE fe.finding_id = ?",
            (finding["id"],),
        )
        result.append(item)
    return result


def case_reports(case_id):
    return query_all(
        "SELECT r.*, u.full_name AS generated_by_name FROM ai_reports r "
        "LEFT JOIN users u ON u.id = r.generated_by WHERE r.case_id = ? ORDER BY r.id DESC",
        (case_id,),
    )


def case_tasks(case_id):
    return query_all(
        "SELECT t.*, e.evidence_code, e.filename, u.full_name AS requested_by_name "
        "FROM analysis_tasks t JOIN evidence e ON e.id = t.evidence_id "
        "LEFT JOIN users u ON u.id = t.requested_by WHERE t.case_id = ? ORDER BY t.id DESC LIMIT 30",
        (case_id,),
    )


# ------------------------------------------------------------------ graph

NODE_TYPES = ["suspect", "evidence", "witness", "event", "location", "device"]


def case_node_labels(case_id):
    """Every node that can appear in a case's graph, with a readable label."""
    labels = {}
    for s in case_suspects(case_id):
        labels[f"suspect:{s['id']}"] = ("suspect", f"{suspect_code(s['id'])} {s['name']}")
    for e in query_all("SELECT id, evidence_code, filename FROM evidence WHERE case_id = ?", (case_id,)):
        labels[f"evidence:{e['id']}"] = ("evidence", f"{e['evidence_code']} {e['filename']}")
    for w in query_all("SELECT id, name FROM witnesses WHERE case_id = ?", (case_id,)):
        labels[f"witness:{w['id']}"] = ("witness", f"{witness_code(w['id'])} {w['name']}")
    for t in query_all("SELECT id, event_time, event_type FROM timeline_events WHERE case_id = ? "
                       "AND source NOT LIKE 'CSV log%'", (case_id,)):
        labels[f"event:{t['id']}"] = ("event", f"{t['event_time'][:16]} {t['event_type']}")
    return labels


def label_for_node(node_key, known):
    if node_key in known:
        return known[node_key]
    node_type, _, ref = node_key.partition(":")
    return node_type, ref or node_key


def case_relationships(case_id):
    known = case_node_labels(case_id)
    rows = query_all(
        "SELECT r.*, u.full_name AS created_by_name FROM evidence_relationships r "
        "LEFT JOIN users u ON u.id = r.created_by WHERE r.case_id = ? ORDER BY r.id",
        (case_id,),
    )
    result = []
    for row in rows:
        item = dict(row)
        item["source_type"], item["source_label"] = label_for_node(row["source_node"], known)
        item["target_type"], item["target_label"] = label_for_node(row["target_node"], known)
        result.append(item)
    return result


def build_case_graph(case_id):
    """Create the adjacency-list Graph for one case from SQLite."""
    graph = Graph()
    known = case_node_labels(case_id)
    # Suspects, evidence and witnesses always appear, even without links.
    for key, (node_type, label) in known.items():
        if node_type != "event":
            graph.add_node(key, label, node_type)
    for rel in case_relationships(case_id):
        graph.add_node(rel["source_node"], rel["source_label"], rel["source_type"])
        graph.add_node(rel["target_node"], rel["target_label"], rel["target_type"])
        graph.add_edge(rel["source_node"], rel["target_node"], {
            "id": rel["id"], "type": rel["relationship_type"], "description": rel["description"],
        })
    return graph


def suspect_linked_evidence(suspect_id):
    """Evidence explicitly linked to a suspect in the relationships table."""
    key = f"suspect:{suspect_id}"
    rows = query_all(
        "SELECT * FROM evidence_relationships WHERE source_node = ? AND target_node LIKE 'evidence:%' "
        "UNION ALL SELECT * FROM evidence_relationships WHERE target_node = ? AND source_node LIKE 'evidence:%'",
        (key, key),
    )
    linked = []
    for rel in rows:
        other = rel["target_node"] if rel["source_node"] == key else rel["source_node"]
        evidence = get_evidence(int(other.split(":")[1]))
        if evidence:
            linked.append({"evidence": evidence, "relationship_type": rel["relationship_type"],
                           "description": rel["description"]})
    return linked


# ------------------------------------------------------------ full bundle

def case_bundle(case_id):
    """Everything about a case as plain dictionaries (used by TRACE AI and reports)."""
    from forensics.timeline import build_case_timeline   # imported here to avoid a circular import

    case = get_case(case_id)
    if case is None:
        return None
    evidence = [dict(e) for e in case_evidence(case_id)]
    db = get_db()
    for item in evidence:
        last = db.execute(
            "SELECT result, checked_at FROM integrity_checks WHERE evidence_id = ? ORDER BY id DESC LIMIT 1",
            (item["id"],),
        ).fetchone()
        item["last_check"] = dict(last) if last else None
        item["custody_count"] = db.execute(
            "SELECT COUNT(*) FROM custody_events WHERE evidence_id = ?", (item["id"],)).fetchone()[0]
    return {
        "case": dict(case),
        "team": [dict(t) for t in case_team(case_id)],
        "suspects": [dict(s) | {"code": suspect_code(s["id"])} for s in case_suspects(case_id)],
        "witnesses": [dict(w) | {"code": witness_code(w["id"])} for w in case_witnesses(case_id)],
        "evidence": evidence,
        "notes": [dict(n) for n in case_notes(case_id)],
        "findings": case_findings(case_id),
        "relationships": case_relationships(case_id),
        "timeline": build_case_timeline(case_id, include_system=False),
    }
