"""
Investigation timeline.

build_case_timeline() collects events from several places and sorts them with
our own merge sort (dsa/sorting.py):

  * timeline_events rows    - incident events entered by investigators or
                              imported from CSV activity logs
  * witness statements      - the time each statement was recorded
  * CCTV recordings         - only when the recording time is known
  * evidence registrations  - the time a file was UPLOADED to TRACE X.
                              These are clearly labelled "system time"
                              because an upload time is not the time the
                              crime happened.

Every event keeps its original timestamp and a `source` describing where it
came from. Nothing is invented: if a time is not recorded, the event is not
placed on the timeline.
"""

import csv
import io
from datetime import datetime

from database.db import get_db, now_str
from dsa.sorting import merge_sort

ACCEPTED_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
]

TIMESTAMP_COLUMNS = ("timestamp", "time", "datetime", "date_time", "event_time", "date")


def normalize_timestamp(text):
    """Convert many common date formats to 'YYYY-MM-DD HH:MM:SS'. Returns None if unreadable."""
    text = (text or "").strip()
    for fmt in ACCEPTED_FORMATS:
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return None


def build_case_timeline(case_id, include_system=True, steps=None, sort=True):
    """Collect a case's events. With sort=False the events are returned in the
    order they were collected (used by the DSA Inspector to show merge sort's input)."""
    db = get_db()
    events = []

    for row in db.execute(
        "SELECT t.*, e.evidence_code FROM timeline_events t "
        "LEFT JOIN evidence e ON e.id = t.source_evidence_id WHERE t.case_id = ?", (case_id,)
    ):
        events.append({
            "time": row["event_time"], "type": row["event_type"], "description": row["description"],
            "source": row["source"], "evidence_id": row["source_evidence_id"],
            "evidence_code": row["evidence_code"], "category": "incident", "id": row["id"],
        })

    for row in db.execute("SELECT * FROM witnesses WHERE case_id = ?", (case_id,)):
        events.append({
            "time": row["recorded_at"], "type": "Witness statement recorded",
            "description": f"Statement taken from {row['name']}.",
            "source": f"Witness record W-{row['id']:03d}", "evidence_id": row["related_evidence_id"],
            "evidence_code": None, "category": "statement", "id": None,
        })

    for row in db.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)):
        if row["file_type"] == "video" and row["recorded_at"]:
            camera = f" on camera {row['camera_id']}" if row["camera_id"] else ""
            events.append({
                "time": row["recorded_at"], "type": "CCTV recording (stated time)",
                "description": f"Recording {row['filename']}{camera} begins.",
                "source": f"Recording time entered for {row['evidence_code']}",
                "evidence_id": row["id"], "evidence_code": row["evidence_code"],
                "category": "cctv", "id": None,
            })
        if include_system:
            events.append({
                "time": row["uploaded_at"], "type": "Evidence registered (system upload time)",
                "description": f"{row['filename']} was uploaded to TRACE X. This is not an incident time.",
                "source": "TRACE X evidence vault", "evidence_id": row["id"],
                "evidence_code": row["evidence_code"], "category": "system", "id": None,
            })

    if not sort:
        return events
    return merge_sort(events, key=lambda event: event["time"], steps=steps)


def import_csv_activity_log(evidence, file_path, user_id):
    """Read a CSV activity log and add each row as a timeline event.

    The CSV needs a timestamp column (timestamp / time / datetime / ...).
    All other columns are joined into the event description.
    Returns (imported, skipped) counts. Rows already imported are not added again.
    """
    db = get_db()
    already = db.execute(
        "SELECT COUNT(*) FROM timeline_events WHERE source_evidence_id = ? AND source LIKE 'CSV log%'",
        (evidence["id"],),
    ).fetchone()[0]
    if already:
        return 0, 0, "This CSV log was already imported into the timeline."

    with open(file_path, encoding="utf-8-sig", errors="replace") as handle:
        text = handle.read()
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return 0, 0, "The CSV file has no header row."

    lower_names = {name.lower().strip(): name for name in reader.fieldnames}
    time_column = next((lower_names[c] for c in TIMESTAMP_COLUMNS if c in lower_names), None)
    if time_column is None:
        return 0, 0, "No timestamp column found (expected one of: " + ", ".join(TIMESTAMP_COLUMNS) + ")."

    imported = skipped = 0
    for row_number, row in enumerate(reader, start=2):     # row 1 is the header
        stamp = normalize_timestamp(row.get(time_column))
        if stamp is None:
            skipped += 1
            continue
        details = "; ".join(f"{k}: {v}" for k, v in row.items() if k != time_column and v)
        db.execute(
            "INSERT INTO timeline_events (case_id, event_time, event_type, description, source, "
            "source_evidence_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence["case_id"], stamp, "Activity log entry", details or "(no details)",
             f"CSV log {evidence['evidence_code']} row {row_number}", evidence["id"], user_id, now_str()),
        )
        imported += 1
    db.commit()
    return imported, skipped, f"Imported {imported} rows, skipped {skipped} rows without a readable time."
