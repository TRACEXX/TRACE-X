"""SHA-256 registration, verification (MATCH / MISMATCH / FILE MISSING), the safe
tamper demo, upload validation and the hash-linked custody chain."""

import hashlib
import io
import os
import stat

from database.db import execute, query_all, query_one
from forensics.custody import verify_custody_chain

CONTENT = b"Fictional evidence file for the TRACE X tests.\n"


def _upload(client, name="test_note.txt", data=CONTENT):
    return client.post("/cases/CASE-001/evidence", data={"file": (io.BytesIO(data), name), "description": "test"},
                       content_type="multipart/form-data")


def _latest_evidence(app):
    with app.app_context():
        return dict(query_one("SELECT * FROM evidence ORDER BY id DESC LIMIT 1"))


def _path(app, evidence):
    return os.path.join(app.config["EVIDENCE_DIR"], evidence["storage_path"])


def test_upload_records_real_sha256_in_private_storage(app, client, login):
    login("amna")
    response = _upload(client)
    assert response.status_code == 302
    evidence = _latest_evidence(app)
    assert evidence["original_sha256"] == hashlib.sha256(CONTENT).hexdigest()
    assert evidence["evidence_code"].startswith("EV-")
    path = _path(app, evidence)
    assert os.path.exists(path)
    assert "static" not in os.path.relpath(path, app.root_path).split(os.sep)
    assert os.path.basename(path) != "test_note.txt"           # generated storage name
    assert not os.stat(path).st_mode & stat.S_IWRITE            # stored read-only
    with app.app_context():
        assert query_one("SELECT * FROM custody_events WHERE evidence_id = ? AND action = 'Evidence registered'",
                         (evidence["id"],))
    # The file is served back only through the authorised route.
    assert client.get(f"/evidence/{evidence['id']}/file").data == CONTENT


def test_verify_match_then_mismatch_then_missing(app, client, login):
    login("amna")
    _upload(client)
    evidence = _latest_evidence(app)
    client.post(f"/evidence/{evidence['id']}/verify")
    assert _latest_evidence(app)["integrity_status"] == "MATCH"

    # Simulate the stored file changing on disk.
    path = _path(app, evidence)
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    with open(path, "ab") as handle:
        handle.write(b"changed")
    client.post(f"/evidence/{evidence['id']}/verify")
    after = _latest_evidence(app)
    assert after["integrity_status"] == "MISMATCH"
    assert after["original_sha256"] == evidence["original_sha256"]      # reference never replaced

    os.remove(path)
    client.post(f"/evidence/{evidence['id']}/verify")
    assert _latest_evidence(app)["integrity_status"] == "FILE MISSING"

    with app.app_context():
        results = [r["result"] for r in query_all(
            "SELECT result FROM integrity_checks WHERE evidence_id = ? ORDER BY id", (evidence["id"],))]
    assert results == ["MATCH", "MISMATCH", "FILE MISSING"]


def test_tamper_demo_never_changes_original(app, client, login):
    login("amna")
    _upload(client)
    evidence = _latest_evidence(app)
    page = client.post(f"/evidence/{evidence['id']}/demo").get_data(as_text=True)
    assert "MISMATCH" in page
    with open(_path(app, evidence), "rb") as handle:
        assert handle.read() == CONTENT
    assert os.listdir(app.config["TEMP_DIR"]) == []                   # temporary copy deleted
    client.post(f"/evidence/{evidence['id']}/verify")
    assert _latest_evidence(app)["integrity_status"] == "MATCH"


def test_upload_rejects_bad_types_and_spoofed_content(app, client, login):
    login("amna")
    before = len(os.listdir(app.config["EVIDENCE_DIR"] + "/CASE-001"))
    _upload(client, "malware.exe", b"MZ\x90\x00")
    _upload(client, "fake.png", b"this is not a png")
    _upload(client, "empty.txt", b"")
    assert len(os.listdir(app.config["EVIDENCE_DIR"] + "/CASE-001")) == before


def test_uploaded_name_cannot_choose_storage_path(app, client, login):
    login("amna")
    _upload(client, "..\\..\\..\\escape.txt")
    evidence = _latest_evidence(app)
    assert evidence["filename"] == "escape.txt"
    assert evidence["storage_path"].startswith("CASE-001/")


def test_custody_chain_detects_edited_history(app, client, login):
    login("amna")
    _upload(client)
    evidence = _latest_evidence(app)
    client.get(f"/evidence/{evidence['id']}")                          # adds "Evidence viewed"
    with app.app_context():
        assert verify_custody_chain(evidence["id"])["valid"]
        first = query_one("SELECT id FROM custody_events WHERE evidence_id = ? ORDER BY id LIMIT 1", (evidence["id"],))
        execute("UPDATE custody_events SET description = 'rewritten' WHERE id = ?", (first["id"],))
        result = verify_custody_chain(evidence["id"])
        assert not result["valid"]
        assert result["broken_at"] == first["id"]


def test_download_is_recorded_in_custody(app, client, login):
    login("hiba")
    _upload(client)
    evidence = _latest_evidence(app)
    response = client.get(f"/evidence/{evidence['id']}/file?download=1")
    assert "attachment" in response.headers["Content-Disposition"]
    with app.app_context():
        assert query_one("SELECT * FROM custody_events WHERE evidence_id = ? AND action = 'Evidence downloaded'",
                         (evidence["id"],))
