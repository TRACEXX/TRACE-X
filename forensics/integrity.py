"""
Evidence integrity verification with SHA-256.

verify_evidence()  - recompute a stored file's hash and compare it with the
                     reference hash saved at upload time.
run_tamper_demo()  - safe classroom demonstration of a mismatch using a
                     TEMPORARY COPY. The registered original is never touched.

Important: a MISMATCH only tells us that the stored file no longer matches
its registered fingerprint. It does not prove hacking and does not identify
who changed the file.
"""

import hmac
import os
import shutil
import uuid

from flask import current_app

from database.db import get_db, log_activity, now_str
from forensics.custody import record_custody_event
from forensics.hashing import sha256_file


def evidence_abspath(storage_path):
    """Turn the stored relative path into an absolute path inside EVIDENCE_DIR.

    Refuses any path that would point outside the evidence folder.
    """
    base = os.path.realpath(current_app.config["EVIDENCE_DIR"])
    full = os.path.realpath(os.path.join(base, storage_path))
    if os.path.commonpath([base, full]) != base:
        raise ValueError("Evidence path escapes the evidence storage folder")
    return full


def verify_evidence(evidence, user_id):
    """Check one evidence record. `evidence` is a row from the evidence table."""
    path = evidence_abspath(evidence["storage_path"])
    original = evidence["original_sha256"]
    checked_at = now_str()

    if not os.path.exists(path):
        result, current = "FILE MISSING", None
    else:
        current = sha256_file(path)
        # compare_digest compares in constant time (good security habit)
        result = "MATCH" if hmac.compare_digest(current, original) else "MISMATCH"

    db = get_db()
    db.execute(
        "INSERT INTO integrity_checks (evidence_id, checked_by, checked_at, current_sha256, result) "
        "VALUES (?, ?, ?, ?, ?)",
        (evidence["id"], user_id, checked_at, current, result),
    )
    # Only the STATUS is updated. original_sha256 is never replaced.
    db.execute(
        "UPDATE evidence SET integrity_status = ?, last_verified_at = ? WHERE id = ?",
        (result, checked_at, evidence["id"]),
    )
    db.commit()
    record_custody_event(evidence["id"], user_id, "Evidence verified", f"SHA-256 check result: {result}")
    log_activity(user_id, "Integrity verification performed", "evidence", evidence["evidence_code"], result)

    return {"result": result, "original": original, "current": current, "checked_at": checked_at}


def run_tamper_demo(evidence, user_id):
    """Demonstrate a mismatch on a throw-away copy of an evidence file."""
    source = evidence_abspath(evidence["storage_path"])
    if not os.path.exists(source):
        return {"ok": False, "error": "The registered file is missing, so no copy can be made."}

    temp_dir = current_app.config["TEMP_DIR"]
    os.makedirs(temp_dir, exist_ok=True)
    extension = os.path.splitext(source)[1]
    temp_path = os.path.join(temp_dir, f"demo-{uuid.uuid4().hex}{extension}")

    steps = []
    try:
        shutil.copyfile(source, temp_path)
        steps.append(f"Copied {evidence['evidence_code']} to a temporary file: {os.path.basename(temp_path)}")
        reference = sha256_file(temp_path)
        steps.append("Calculated the reference hash of the temporary copy.")
        with open(temp_path, "ab") as temp_file:
            temp_file.write(b"\n[TRACE X DEMO: one line appended to the temporary copy]\n")
        steps.append("Appended one line of text to the temporary copy only.")
        modified = sha256_file(temp_path)
        steps.append("Re-calculated the hash of the changed copy.")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    steps.append("Deleted the temporary copy.")

    original_now = sha256_file(source)
    original_untouched = hmac.compare_digest(original_now, evidence["original_sha256"])
    steps.append("Re-hashed the registered original to confirm it was not altered.")

    log_activity(user_id, "Integrity demonstration run", "evidence", evidence["evidence_code"],
                 "Temporary copy modified and deleted; original not touched")
    return {
        "ok": True,
        "reference": reference,
        "modified": modified,
        "result": "MATCH" if reference == modified else "MISMATCH",
        "original_now": original_now,
        "original_registered": evidence["original_sha256"],
        "original_untouched": original_untouched,
        "steps": steps,
    }


def integrity_history(evidence_id):
    return get_db().execute(
        "SELECT i.*, u.full_name AS checked_by_name FROM integrity_checks i "
        "LEFT JOIN users u ON u.id = i.checked_by WHERE i.evidence_id = ? ORDER BY i.id DESC",
        (evidence_id,),
    ).fetchall()
