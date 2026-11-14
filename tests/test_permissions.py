"""Role-based access: detectives only reach assigned or shared cases, even by editing URLs."""

import io

from database.db import query_one

def _first_evidence_id(app, case_number):
    with app.app_context():
        return query_one("SELECT e.id FROM evidence e JOIN cases c ON c.id = e.case_id "
                         "WHERE c.case_number = ? ORDER BY e.id LIMIT 1", (case_number,))["id"]


def test_detective_cannot_open_unassigned_case_by_url(app, client, login):
    login("warisha")
    evidence_id = _first_evidence_id(app, "CASE-001")
    assert client.get("/cases/CASE-001").status_code == 403
    assert client.get("/cases/CASE-001?tab=evidence").status_code == 403
    assert client.get(f"/evidence/{evidence_id}").status_code == 403
    assert client.get(f"/evidence/{evidence_id}/file").status_code == 403
    assert client.get(f"/evidence/{evidence_id}/file?download=1").status_code == 403
    assert client.get(f"/evidence/{evidence_id}/custody").status_code == 403
    assert client.post(f"/evidence/{evidence_id}/verify").status_code == 403
    assert client.get("/suspects/1").status_code == 403
    assert client.post("/cases/CASE-001/graph/traverse", json={"start": "suspect:1"}).status_code == 403
    assert client.get("/cases/CASE-001/report").status_code == 403
    with app.app_context():
        assert query_one("SELECT * FROM activity_logs WHERE action = 'Access denied'") is not None


def test_detective_can_open_own_case(client, login):
    login("warisha")
    assert client.get("/cases/CASE-002").status_code == 200
    for tab in ("suspects", "witnesses", "evidence", "timeline", "notes", "forensics", "reports"):
        assert client.get(f"/cases/CASE-002?tab={tab}").status_code == 200


def test_shared_viewer_can_read_but_not_change(app, client, login):
    login("maryam")
    assert client.get("/cases/CASE-003").status_code == 200
    upload = client.post("/cases/CASE-003/evidence",
                         data={"file": (io.BytesIO(b"note"), "x.txt")}, content_type="multipart/form-data")
    assert upload.status_code == 403
    assert client.post("/cases/CASE-003/notes", data={"content": "hi"}).status_code == 403
    assert client.post("/cases/CASE-003/suspects", data={"name": "X"}).status_code == 403
    
    evidence_id = _first_evidence_id(app, "CASE-003")
    assert client.post(f"/evidence/{evidence_id}/verify").status_code == 302


def test_detective_cannot_use_admin_area(client, login):
    login("amna")
    for url in ("/admin/", "/admin/cases", "/admin/logs", "/admin/users", "/admin/integrity-demo"):
        assert client.get(url).status_code == 403, url
    assert client.post("/admin/cases/CASE-004/assign", data={"user_id": 2, "permission_level": "lead"}).status_code == 403


def test_detective_cannot_close_case(app, client, login):
    login("amna")
    client.post("/cases/CASE-001/update", data={"status": "Closed", "summary": "x"})
    with app.app_context():
        assert query_one("SELECT status FROM cases WHERE case_number = 'CASE-001'")["status"] != "Closed"


def test_admin_assignment_grants_access(app, client, login):
    login("admin")
    with app.app_context():
        maryam = query_one("SELECT id FROM users WHERE username = 'maryam'")["id"]
    client.post("/admin/cases/CASE-004/assign", data={"user_id": maryam, "permission_level": "lead"})
    client.post("/logout")
    login("maryam")
    assert client.get("/cases/CASE-004").status_code == 200
    assert "Noor Gallery" in client.get("/portal").get_data(as_text=True)


def test_reassign_moves_lead_and_custody(app, client, login):
    login("admin")
    with app.app_context():
        warisha = query_one("SELECT id FROM users WHERE username = 'warisha'")["id"]
    client.post("/admin/cases/CASE-001/reassign", data={"user_id": warisha})
    with app.app_context():
        lead = query_one("SELECT u.username FROM case_assignments a JOIN users u ON u.id = a.user_id "
                         "JOIN cases c ON c.id = a.case_id WHERE c.case_number = 'CASE-001' "
                         "AND a.permission_level = 'lead'")
        assert lead["username"] == "warisha"
        assert query_one("SELECT * FROM case_assignments a JOIN users u ON u.id = a.user_id "
                         "WHERE u.username = 'amna' AND a.case_id = 1") is None
        assert query_one("SELECT * FROM custody_events WHERE action = 'Evidence transferred'") is not None


def test_search_and_ai_only_see_accessible_cases(client, login):
    login("warisha")
    page = client.get("/search?q=library").get_data(as_text=True)
    assert "Riverside Library Death" not in page
    answer = client.post("/ai/ask", json={"question": "Summarize Case 001"}).get_json()
    text = str(answer["sections"])
    assert "not shared with you" in text
    assert "Kamran" not in text


def test_admin_sees_everything(client, login):
    login("admin")
    for case in ("CASE-001", "CASE-002", "CASE-003", "CASE-004"):
        assert client.get(f"/cases/{case}").status_code == 200
