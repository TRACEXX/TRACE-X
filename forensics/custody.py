"""
Chain of custody.

Custody events are saved in SQLite (so they survive restarts) and loaded into
the custom LinkedList from dsa/linked_list.py for traversal and display.

HASH-LINKED AUDIT RECORDS
Each custody row stores:
    prev_hash   = record_hash of the previous event for the same evidence
    record_hash = SHA-256 of (this event's fields + prev_hash)
If anyone edits or deletes an old row directly in the database, recomputing
the hashes no longer lines up and verify_custody_chain() reports where the
chain breaks.

This protects the HISTORY records. It is separate from the file SHA-256
check in forensics/integrity.py, which protects the evidence FILE itself.
"""

from database.db import get_db, now_str
from dsa.linked_list import LinkedList
from forensics.hashing import sha256_text

GENESIS_HASH = "0" * 64


def compute_record_hash(evidence_id, user_id, action, timestamp, description, prev_hash):
    payload = "|".join([str(evidence_id), str(user_id or ""), action, timestamp,
                        description or "", prev_hash])
    return sha256_text(payload)


def record_custody_event(evidence_id, user_id, action, description="", timestamp=None, commit=True):
    """Append one event to an evidence item's custody chain."""
    db = get_db()
    timestamp = timestamp or now_str()
    last = db.execute(
        "SELECT record_hash FROM custody_events WHERE evidence_id = ? ORDER BY id DESC LIMIT 1",
        (evidence_id,),
    ).fetchone()
    prev_hash = last["record_hash"] if last else GENESIS_HASH
    record_hash = compute_record_hash(evidence_id, user_id, action, timestamp, description, prev_hash)
    db.execute(
        "INSERT INTO custody_events (evidence_id, user_id, action, timestamp, description, prev_hash, record_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, user_id, action, timestamp, description or "", prev_hash, record_hash),
    )
    if commit:
        db.commit()


def load_custody_chain(evidence_id):
    """Read the events from SQLite (oldest first) into a LinkedList."""
    rows = get_db().execute(
        "SELECT c.*, u.full_name AS user_name, u.badge_id FROM custody_events c "
        "LEFT JOIN users u ON u.id = c.user_id WHERE c.evidence_id = ? ORDER BY c.id",
        (evidence_id,),
    ).fetchall()
    chain = LinkedList()
    for row in rows:
        chain.append(dict(row))
    return chain


def verify_custody_chain(evidence_id):
    """Walk the linked list and recompute every hash.

    Returns {'valid': bool, 'checked': n, 'broken_at': event id or None, 'reason': text}.
    """
    chain = load_custody_chain(evidence_id)
    expected_prev = GENESIS_HASH
    checked = 0
    for event in chain.traverse():
        checked += 1
        if event["prev_hash"] != expected_prev:
            return {"valid": False, "checked": checked, "broken_at": event["id"],
                    "reason": "Previous-hash link does not match the earlier record (a record was removed or edited)."}
        recomputed = compute_record_hash(event["evidence_id"], event["user_id"], event["action"],
                                         event["timestamp"], event["description"], event["prev_hash"])
        if recomputed != event["record_hash"]:
            return {"valid": False, "checked": checked, "broken_at": event["id"],
                    "reason": "Stored fields no longer match this record's hash (the record was edited)."}
        expected_prev = event["record_hash"]
    return {"valid": True, "checked": checked, "broken_at": None,
            "reason": "All custody records are intact." if checked else "No custody records yet."}
