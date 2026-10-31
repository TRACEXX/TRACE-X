"""End-to-end checks that every page renders and the main workflows run for real."""

import io

from database.db import query_all, query_one

CASES = ("CASE-001", "CASE-002", "CASE-003", "CASE-004")
TABS = ("overview", "suspects", "witnesses", "evidence", "timeline", "notes", "forensics", "reports")


def test_every_admin_page_renders(app, client, login):
    login("admin")
    for url in ("/", "/admin/", "/admin/detectives", "/admin/detectives/2", "/admin/cases", "/admin/cases/new",
                "/admin/cases/CASE-001/edit", "/admin/logs", "/admin/logs?q=login", "/admin/users",
                "/admin/integrity-demo", "/cases", "/search?q=card", "/search?q=case 2", "/search?q=EV-0003",
                "/ai/", "/ai/?case=CASE-001", "/dsa/"):
        response = client.get(url)
        assert response.status_code == 200, url
        assert "Content-Security-Policy" in response.headers
    for case in CASES:
        for tab in TABS:
            assert client.get(f"/cases/{case}?tab={tab}").status_code == 200, (case, tab)
        assert client.get(f"/cases/{case}/graph").status_code == 200
        assert client.get(f"/cases/{case}/report").status_code == 200
    with app.app_context():
        ids = [r["id"] for r in query_all("SELECT id FROM evidence")]
        suspects = [r["id"] for r in query_all("SELECT id FROM suspects")]
    for evidence_id in ids:
        assert client.get(f"/evidence/{evidence_id}").status_code == 200
        assert client.get(f"/evidence/{evidence_id}/custody").status_code == 200
        assert client.get(f"/evidence/{evidence_id}/custody?action=viewed").status_code == 200
    for suspect_id in suspects:
        assert client.get(f"/suspects/{suspect_id}").status_code == 200


def test_dsa_inspector_runs_every_algorithm(client, login):
    login("amna")
    for algo in ("linked_list", "stack", "queue", "hash_table", "tree", "bfs", "dfs", "merge_sort",
                 "binary_search", "linear_search"):
        page = client.get(f"/dsa/?algo={algo}&case=CASE-001&note_id=1&key=EV-0002&target=CASE-001&word=log")
        assert page.status_code == 200, algo
        assert "Processing order" in page.get_data(as_text=True)


def test_graph_traversal_runs_in_python(client, login):
    login("amna")
    bfs = client.post("/cases/CASE-001/graph/traverse",
                      json={"start": "suspect:1", "algorithm": "bfs", "target": "witness:3"}).get_json()
    assert bfs["order"][0]["id"] == "suspect:1"
    assert bfs["path"] and bfs["path"][-1]["to"].endswith("Aslam Javed")
    dfs = client.post("/cases/CASE-001/graph/traverse", json={"start": "suspect:1", "algorithm": "dfs"}).get_json()
    assert dfs["algorithm"] == "dfs" and len(dfs["order"]) == len(bfs["order"])
    assert client.post("/cases/CASE-001/graph/traverse", json={"start": "suspect:999"}).status_code == 400


def test_notes_edit_and_stack_undo(app, client, login):
    login("amna")
    client.post("/cases/CASE-001/notes", data={"title": "T", "content": "first"})
    with app.app_context():
        note_id = query_one("SELECT id FROM investigation_notes ORDER BY id DESC LIMIT 1")["id"]
    client.post(f"/notes/{note_id}/edit", data={"title": "T", "content": "second"})
    client.post(f"/notes/{note_id}/edit", data={"title": "T", "content": "third"})
    client.post(f"/notes/{note_id}/undo")
    with app.app_context():
        assert query_one("SELECT content FROM investigation_notes WHERE id = ?", (note_id,))["content"] == "second"
    client.post(f"/notes/{note_id}/undo")
    with app.app_context():
        assert query_one("SELECT content FROM investigation_notes WHERE id = ?", (note_id,))["content"] == "first"


def test_queue_imports_csv_into_timeline(app, client, login):
    login("amna")
    client.post("/cases/CASE-001/tasks/process")          # seeded pending CSV import task
    with app.app_context():
        task = query_one("SELECT * FROM analysis_tasks ORDER BY id LIMIT 1")
        assert task["status"] == "done"
        rows = query_all("SELECT * FROM timeline_events WHERE source LIKE 'CSV log%'")
        assert len(rows) == 9
        assert rows[0]["event_time"] == "2026-03-13 18:02:11"


def test_witness_edit_keeps_history(app, client, login):
    login("amna")
    client.post("/witnesses/1/edit", data={"statement": "Updated statement.", "reason": "clarified"})
    with app.app_context():
        history = query_all("SELECT * FROM witness_history WHERE witness_id = 1")
        assert history and "raised male voices" in history[-1]["previous_statement"]


def test_findings_are_saved_without_judgement(app, client, login):
    login("amna")
    page = client.post("/cases/CASE-001/findings", data={
        "findings_text": "The access log and the alibi conflict.", "selected_suspect_id": 1,
        "evidence_ids": [2]}, follow_redirects=True).get_data(as_text=True)
    for word in ("Correct", "Wrong", "You Win"):
        assert word not in page
    with app.app_context():
        assert query_one("SELECT * FROM finding_evidence") is not None


def test_report_pdf_generation(client, login):
    login("hiba")
    response = client.post("/cases/CASE-003/report/generate", follow_redirects=True)
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")
    assert "attachment" in response.headers["Content-Disposition"]


def test_trace_ai_answers_from_records_without_llm(client, login):
    login("amna")
    questions = {
        "Show me Case 001": "Riverside Library",
        "Show all cases assigned to Detective Amna": "CASE-001",
        "Summarize Case 001": "Automated summary",
        "What evidence is available in Case 001?": "EV-0002",
        "Which evidence items failed integrity verification?": "Not yet verified",
        "What evidence is connected to Daniyal Raza?": "dealer_email_printout.txt",
        "Explain the timeline of Case 001": "merge-sorted",
        "access card": "Cases",
    }
    for question, expected in questions.items():
        data = client.post("/ai/ask", json={"question": question}).get_json()
        assert expected in str(data), question
        assert data["ai"]["status"] == "disabled"
    report = client.post("/ai/ask", json={"question": "Generate an investigation report for Case 001"}).get_json()
    url = report["references"][0]["url"]
    assert client.get(url).data.startswith(b"%PDF")


def test_trace_ai_falls_back_when_provider_is_down(tmp_path):
    from conftest import DETECTIVE_PASSWORD, make_app
    app = make_app(tmp_path, AI_PROVIDER="ollama", OLLAMA_URL="http://127.0.0.1:9", AI_TIMEOUT=3)
    client = app.test_client()
    client.post("/login", data={"username": "amna", "password": DETECTIVE_PASSWORD})
    data = client.post("/ai/ask", json={"question": "Summarize Case 001"}).get_json()
    assert data["ai"]["status"] == "unavailable"
    assert "AI provider unavailable" in data["ai"]["message"]
    assert "Automated summary" in str(data["sections"])          # stored records still returned


def test_upload_image_and_view(client, login, app):
    from database.seed import make_placeholder_png
    login("amna")
    client.post("/cases/CASE-001/evidence", data={"file": (io.BytesIO(make_placeholder_png(40, 30, (90, 90, 90))),
                                                           "photo.png")}, content_type="multipart/form-data")
    with app.app_context():
        evidence = query_one("SELECT * FROM evidence ORDER BY id DESC LIMIT 1")
    assert evidence["file_type"] == "image"
    assert client.get(f"/evidence/{evidence['id']}").status_code == 200
