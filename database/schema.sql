-- TRACE X database schema (SQLite)
-- Foreign keys are switched on for every connection in database/db.py.

PRAGMA foreign_keys = ON;

-- People who can log in: exactly one administrator and four detectives.
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'detective')),
    badge_id        TEXT UNIQUE,
    specialization  TEXT,
    profile_image   TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

CREATE TABLE cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number     TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open', 'Under Investigation', 'Pending Review', 'Closed')),
    incident_date   TEXT,
    location        TEXT,
    created_at      TEXT NOT NULL,
    created_by      INTEGER REFERENCES users(id)
);

-- Who may work on which case.
--   lead / investigator : can read and add records
--   viewer              : case shared read-only
CREATE TABLE case_assignments (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_level  TEXT NOT NULL CHECK (permission_level IN ('lead', 'investigator', 'viewer')),
    assigned_at       TEXT NOT NULL,
    assigned_by       INTEGER REFERENCES users(id),
    UNIQUE (case_id, user_id)
);

CREATE TABLE suspects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    photo_path    TEXT,
    background    TEXT NOT NULL DEFAULT '',
    relationship  TEXT NOT NULL DEFAULT '',
    motive        TEXT NOT NULL DEFAULT '',
    alibi         TEXT NOT NULL DEFAULT '',
    statements    TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_code     TEXT UNIQUE,
    case_id           INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename          TEXT NOT NULL,          -- original filename from the uploader
    storage_path      TEXT NOT NULL UNIQUE,   -- generated name, relative to evidence_storage/
    file_type         TEXT NOT NULL,          -- image / video / audio / pdf / text / csv / other
    mime_type         TEXT,
    file_size         INTEGER NOT NULL,
    original_sha256   TEXT NOT NULL,          -- reference fingerprint, never changed
    uploaded_by       INTEGER REFERENCES users(id),
    uploaded_at       TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    notes             TEXT NOT NULL DEFAULT '',
    integrity_status  TEXT NOT NULL DEFAULT 'UNVERIFIED'
                      CHECK (integrity_status IN ('UNVERIFIED', 'MATCH', 'MISMATCH', 'FILE MISSING')),
    last_verified_at  TEXT,
    camera_id         TEXT,                   -- CCTV only
    recorded_at       TEXT,                   -- when the recording was made, if known
    custodian_id      INTEGER REFERENCES users(id)
);

CREATE TABLE witnesses (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id              INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    contact              TEXT NOT NULL DEFAULT '',
    statement            TEXT NOT NULL,
    recorded_at          TEXT NOT NULL,
    recorded_by          INTEGER REFERENCES users(id),
    related_suspect_id   INTEGER REFERENCES suspects(id) ON DELETE SET NULL,
    related_evidence_id  INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    updated_at           TEXT
);

-- Every edit to a statement keeps the previous version here.
CREATE TABLE witness_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    witness_id          INTEGER NOT NULL REFERENCES witnesses(id) ON DELETE CASCADE,
    previous_statement  TEXT NOT NULL,
    edited_by           INTEGER REFERENCES users(id),
    edited_at           TEXT NOT NULL,
    reason              TEXT NOT NULL DEFAULT ''
);

CREATE TABLE integrity_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    checked_by      INTEGER REFERENCES users(id),
    checked_at      TEXT NOT NULL,
    current_sha256  TEXT,                     -- NULL when the file is missing
    result          TEXT NOT NULL CHECK (result IN ('MATCH', 'MISMATCH', 'FILE MISSING'))
);

-- Chain of custody. Each row stores the hash of the previous row, so any
-- later edit to a stored row breaks the chain and can be detected.
CREATE TABLE custody_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    user_id      INTEGER REFERENCES users(id),
    action       TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    prev_hash    TEXT NOT NULL,
    record_hash  TEXT NOT NULL
);

CREATE TABLE timeline_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_time          TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    description         TEXT NOT NULL,
    source              TEXT NOT NULL DEFAULT 'Investigator entry',
    source_evidence_id  INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    created_by          INTEGER REFERENCES users(id),
    created_at          TEXT NOT NULL
);

-- Graph edges. Nodes are written as 'type:reference', for example
-- 'suspect:3', 'evidence:5', 'witness:2', 'event:7',
-- 'location:Old Riverside Library' or 'device:Black Android phone'.
CREATE TABLE evidence_relationships (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id            INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_node        TEXT NOT NULL,
    target_node        TEXT NOT NULL,
    relationship_type  TEXT NOT NULL,
    description        TEXT NOT NULL,         -- the recorded basis for the link
    created_by         INTEGER REFERENCES users(id),
    created_at         TEXT NOT NULL
);

CREATE TABLE investigation_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users(id),
    title       TEXT NOT NULL DEFAULT 'Note',
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Previous versions of a note. Loaded into a Stack for the undo feature.
CREATE TABLE note_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id   INTEGER NOT NULL REFERENCES investigation_notes(id) ON DELETE CASCADE,
    title     TEXT NOT NULL,
    content   TEXT NOT NULL,
    saved_by  INTEGER REFERENCES users(id),
    saved_at  TEXT NOT NULL
);

CREATE TABLE investigation_findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id              INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    submitted_by         INTEGER REFERENCES users(id),
    selected_suspect_id  INTEGER REFERENCES suspects(id) ON DELETE SET NULL,
    findings_text        TEXT NOT NULL,
    submitted_at         TEXT NOT NULL
);

CREATE TABLE finding_evidence (
    finding_id   INTEGER NOT NULL REFERENCES investigation_findings(id) ON DELETE CASCADE,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, evidence_id)
);

-- Evidence-analysis jobs, processed first-in first-out with dsa/queue.py.
CREATE TABLE analysis_tasks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id   INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    task_type     TEXT NOT NULL CHECK (task_type IN ('verify_integrity', 'import_csv_timeline', 'extract_metadata')),
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed')),
    requested_by  INTEGER REFERENCES users(id),
    created_at    TEXT NOT NULL,
    processed_by  INTEGER REFERENCES users(id),
    processed_at  TEXT,
    result        TEXT
);

CREATE TABLE activity_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action       TEXT NOT NULL,
    target_type  TEXT,
    target_id    TEXT,
    details      TEXT,
    ip_address   TEXT,
    timestamp    TEXT NOT NULL
);

CREATE TABLE ai_reports (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id              INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    generated_by         INTEGER REFERENCES users(id),
    report_path          TEXT NOT NULL,
    summary_source       TEXT NOT NULL DEFAULT 'deterministic',
    created_at           TEXT NOT NULL
);

CREATE INDEX idx_assign_user ON case_assignments(user_id);
CREATE INDEX idx_evidence_case ON evidence(case_id);
CREATE INDEX idx_custody_evidence ON custody_events(evidence_id);
CREATE INDEX idx_timeline_case ON timeline_events(case_id);
CREATE INDEX idx_rel_case ON evidence_relationships(case_id);
CREATE INDEX idx_logs_time ON activity_logs(timestamp);
