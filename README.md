# TRACE X: Digital Evidence Integrity & Investigation System

A Flask + SQLite investigation workspace for four detectives and one administrator. You can manage
fictional cases, suspects, witness statements and digital evidence. Every evidence file gets a SHA-256
fingerprint and a hash-linked chain of custody. Relationships are explored with hand-written BFS/DFS,
and TRACE AI answers questions from the stored records.

TRACE X is **not a game**. There are no scores, no hidden "correct culprit", and the system never decides who is responsible.

---

## 1. Run it (VS Code, Windows / macOS / Linux)

```bash
# 1. open the TRACE-X folder in VS Code, then in the terminal:
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# 2. optional: copy the settings file and change the passwords
copy .env.example .env          # macOS/Linux: cp .env.example .env

# 3. start the app
python run.py
```

Open **http://127.0.0.1:5000**.

On the first run TRACE X creates `instance/tracex.db`, the private `evidence_storage/` folder, and all
the fictional sample data automatically. You can also start it with `flask --app app run`.

### Demo accounts

The passwords come from `.env` (or these defaults if there is no `.env`). They exist only as Werkzeug
hashes in the database and never appear in any HTML or JavaScript.

| Role | Username | Default password |
|---|---|---|
| Administrator | `admin` | `TraceX-Admin-2026` |
| Detective Amna Fareed (DET-101) | `amna` | `TraceX-Detective-2026` |
| Detective Warisha Ahmed (DET-102) | `warisha` | `TraceX-Detective-2026` |
| Detective Hiba Khan (DET-103) | `hiba` | `TraceX-Detective-2026` |
| Detective Maryam Farhan (DET-104) | `maryam` | `TraceX-Detective-2026` |

To change the passwords, edit `.env` and then reset. The administrator can also reset a password from
**User accounts**.

### Reset everything

```bash
python -m database.seed --reset
```

This **deletes** the database, all uploaded evidence and all reports, then reloads the sample data.

### Run the tests

```bash
python -m pytest
```

There are 50 tests across authentication, permissions, SHA-256 integrity, every DSA module, every
page, the PDF report and TRACE AI (with and without an AI provider).

---

## 2. Sample data (all fictional)

| Case | Title | Team | Notes |
|---|---|---|---|
| CASE-001 | The Riverside Library Death (homicide) | Amna (lead), Hiba | 3 suspects, 3 witnesses, 5 evidence files including a door access-card CSV log, a pathology PDF, a scene photo and an email printout |
| CASE-002 | Disappearance of Zoya Malik (missing person) | Warisha (lead) | Call-records CSV, missing-person report, lobby still |
| CASE-003 | Crescent Bank Phishing Breach (cybercrime) | Hiba (lead), Maryam (read-only share) | Server auth-log CSV, phishing email, screenshot |
| CASE-004 | Noor Gallery Painting Theft | **unassigned** | Left unassigned so the admin can assign it live in the demo |

Every evidence item is a real file that is really hashed and stored read-only. The "photos" are
generated placeholder images. **No CCTV footage is generated.** Put your staged videos in
`static/assets/demo-videos/` and reset, or upload them from a case's Evidence Vault.

---

## 3. The 20-step demonstration

| Step | Where / what to click |
|---|---|
| 1 | Open http://127.0.0.1:5000 |
| 2-3 | **Administrator login** and log in as `admin` |
| 4 | Administrator dashboard opens (totals, alerts, recent activity) |
| 5 | Sidebar: **Detectives**, which shows all four accounts |
| 6 | Sidebar: **Cases & assignments** |
| 7 | CASE-004: choose *Maryam Farhan* and *Assign as lead*, then **Save** |
| 8 | **Log out** |
| 9 | Landing page: Maryam's **Access Portal**, then log in as `maryam` |
| 10 | Her portal now shows CASE-004 under *Assigned cases* |
| 11 | Click CASE-004 to open the case file |
| 12 | Tabs: **Suspects**, **Witnesses**, **Evidence Vault** |
| 13 | Evidence Vault: choose a file, then **Upload & register** |
| 14 | The evidence page opens with its **original SHA-256** (also in the green message) |
| 15 | **Verify integrity now** returns **MATCH** |
| 16 | **Run demo on a temporary copy** returns **MISMATCH** on the copy, while the original still matches |
| 17 | **Full history** shows the chain of custody (linked list + hash-chain check) |
| 18 | Open CASE-001 as `amna` or `admin`: **Relationship graph**, then *Run traversal in Python* (BFS or DFS) |
| 19 | **Ask TRACE AI** and type "Summarize Case 001" |
| 20 | **Reports & Findings**, then **Generate & download PDF** |

Tip: `amna` has the richest case (CASE-001). Try the **Forensic Tools** tab and press *Process next task*:
the queued job imports the CSV access log into the timeline.

---

## 4. Project structure (and a four-way split)

```text
TRACE-X/
├── app.py              application factory: blueprints, CSRF, security headers, first-run seeding
├── run.py              python run.py
├── config.py           settings from environment / .env (no secrets in code)
├── database/
│   ├── schema.sql      all tables, foreign keys, indexes
│   ├── db.py           connection per request, query helpers, activity logging
│   ├── queries.py      shared read queries (cases, evidence, graph building, case bundle)
│   └── seed.py         fictional sample data + --reset
├── dsa/                hand-written data structures and algorithms (section 5)
├── forensics/
│   ├── hashing.py      SHA-256 with hashlib (chunked, works for big videos)
│   ├── integrity.py    verify MATCH / MISMATCH / FILE MISSING, safe tamper demo
│   ├── custody.py      hash-linked custody records loaded into a LinkedList
│   └── timeline.py     timeline from several sources, merge-sorted; CSV log import
├── ai/
│   ├── context_builder.py  intent detection, authorised context, deterministic summary
│   ├── providers.py        Groq / OpenRouter / OpenAI / Gemini / Ollama adapters (urllib only)
│   └── assistant.py        TRACE AI workflow
├── reports/generator.py    PDF report (ReportLab)
├── routes/             one Flask blueprint per area
│   ├── auth.py         landing, login/logout, permission checks used everywhere
│   ├── admin.py        dashboard, assignments, users, logs, integrity demo
│   ├── detectives.py   portal, case list, search
│   ├── cases.py        case file tabs, suspects, witnesses, notes, timeline, graph, queue, findings
│   ├── evidence.py     upload, viewers, file streaming, verify, custody, transfer
│   ├── reports.py      preview, generate, download
│   ├── ai.py           TRACE AI page + JSON endpoint
│   └── inspector.py    DSA Inspector
├── templates/          Jinja2 templates (case_tabs/ holds one file per case tab)
├── static/             css, js, assets (photos you can replace)
├── evidence_storage/   PRIVATE uploaded evidence (outside /static, created automatically)
├── instance/           tracex.db, generated reports, secret key (created automatically)
└── tests/              pytest suite
```

A suggested way for four students to divide the work and the viva:

| Student | Owns |
|---|---|
| 1 | Authentication, roles, admin dashboard: `routes/auth.py`, `routes/admin.py`, `database/` |
| 2 | Evidence and cybersecurity: `routes/evidence.py`, `forensics/`, custody, integrity |
| 3 | DSA: `dsa/`, `routes/inspector.py`, graph page, timeline, search |
| 4 | TRACE AI and reports: `ai/`, `reports/`, `routes/ai.py`, `routes/reports.py` |

---

## 5. The DSA modules (all run in Python)

The **DSA Inspector** (sidebar) runs each one on live records and prints input, operation, result and steps.

| Structure / algorithm | File | Used for | Complexity |
|---|---|---|---|
| **Linked list** (head/tail pointers) | `dsa/linked_list.py` | Chain of custody: each custody event is a node; the custody page traverses it and does a linear search by action | append O(1), traverse/search O(n) |
| **Stack** (linked nodes) | `dsa/stack.py` | Undo for investigation notes: each edit saves the old version; *Undo* pushes the saved versions and pops the newest | push/pop O(1) |
| **Queue** (linked nodes) | `dsa/queue.py` | Evidence-analysis tasks (verify hash, import CSV log, extract metadata) processed oldest first; BFS also uses it | enqueue/dequeue O(1) |
| **Hash table** (separate chaining, resizes at load 0.75) | `dsa/hash_table.py` | Index of evidence by ID (`EV-0007`) for search and the inspector; reports bucket, comparisons and collisions | average O(1) |
| **Tree** (recursive) | `dsa/tree.py` | Archive → case → type folder → evidence hierarchy in the Evidence Vault; recursive count, height, find, pre-order | O(n) |
| **Graph** (adjacency list) | `dsa/graph.py` | Suspects, evidence, witnesses, devices, locations and events linked by recorded relationships | O(V + E) |
| **BFS** | `dsa/graph.py` | Nodes by distance from a suspect/evidence item; shortest chain that explains why two nodes are connected | O(V + E) |
| **DFS** (recursive, with backtracking) | `dsa/graph.py` | Follow one chain of links as deep as possible | O(V + E) |
| **Merge sort** (recursive, stable) | `dsa/sorting.py` | Chronological timeline; ranking search results by relevance | O(n log n) |
| **Binary search** | `dsa/searching.py` | Exact case-number lookup in sorted case numbers (search page) | O(log n) |
| **Linear / keyword search** | `dsa/searching.py` | Scored keyword search across cases, suspects, statements, evidence, notes | O(n) |

Why each choice fits (useful for the viva):

- **Linked list for custody:** events are only ever appended in order and read from first to last, with no random access.
- **Stack for undo:** the most recent change must be reversed first (LIFO).
- **Queue for tasks:** fairness. The first request is processed first (FIFO).
- **Hash table for IDs:** a lookup by exact ID should not scan every record.
- **Merge sort for the timeline:** it is stable, so two events with the same time keep their recorded order, and its O(n log n) worst case is guaranteed.
- **BFS for "why connected":** BFS finds the path with the fewest links.

---

## 6. Security features

- Passwords are stored as Werkzeug hashes and checked only on the server. Failed logins show one generic message and are logged.
- Flask sessions use HttpOnly, SameSite=Lax signed cookies with an 8-hour lifetime.
- **CSRF protection** on every POST (a session token in forms and in the `X-CSRFToken` header).
- **Role-based access:** `require_case_access()` runs on every case, suspect, evidence, file, graph, report and AI route. A changed URL gets 403 Forbidden, and the attempt is logged.
- Permission levels: `lead` / `investigator` can add records. A `viewer` share is read-only, though a viewer can still verify integrity. Only the admin closes cases.
- Evidence is stored outside `/static`, under random names, written once (`open(..., "xb")`) and set read-only. There is no replace or delete route. Uploads are checked by extension **and** file signature. Path traversal is blocked.
- **SHA-256 verification** never overwrites the reference hash. Every check is stored in `integrity_checks`.
- **Hash-linked custody records:** editing or deleting a stored custody row is detected. This protects the *history*, which is separate from the file check.
- A Content-Security-Policy that blocks inline scripts, plus `nosniff` and frame protection. Stored text and CSV files are served as plain text, never as HTML.
- All SQL uses `?` parameters. The AI never generates or runs SQL.

---

## 7. TRACE AI

Workflow: question → Flask checks the session → Python detects the intent and the case → **fixed
functions** read only the user's authorised records (merge-sorted timeline, hash-table lookup) →
deterministic answer → optional LLM explanation from that JSON context → the answer shows *stored
facts* and the *AI interpretation* separately.

It works with **no AI service at all** (`AI_PROVIDER=none`): case lookup, assignments, evidence,
integrity failures, suspect links, timelines, summaries and PDF reports all come straight from the
database. To add AI explanations, set these in `.env`:

| Provider | Settings | Notes |
|---|---|---|
| Groq (free tier) | `AI_PROVIDER=groq`, `AI_API_KEY=...` | key from console.groq.com |
| Google Gemini (free tier) | `AI_PROVIDER=gemini`, `AI_API_KEY=...` | key from aistudio.google.com |
| OpenRouter (free models) | `AI_PROVIDER=openrouter`, `AI_API_KEY=...` | |
| Ollama (local) | `AI_PROVIDER=ollama` (+ `ollama pull llama3.2`) | nothing leaves the computer |

Use `AI_MODEL` to choose a different model. With a cloud provider, the records relevant to each
question are sent to that provider, so use fictional data only. The TRACE AI page shows which
provider is active. If the provider fails, TRACE AI says so and still shows the stored records.

---

## 8. Design notes

- **Integrity demo access:** the brief calls the tamper demo admin-only, but demo step 16 happens while
  a detective is logged in. The demo only ever touches a temporary copy, so detectives may run it on
  their own cases by default. Set `TRACEX_DEMO_FOR_DETECTIVES=0` to restrict it to the admin.
  The admin version is always under **Integrity demo** in the sidebar.
- **Extra tables** beyond the brief: `witness_history` (statement audit trail), `note_history` (undo
  stack), `finding_evidence` (findings ↔ supporting evidence), `analysis_tasks` (queue).
- **Timestamps:** the timeline never uses an upload time as an incident time. Upload times are shown
  greyed out and labelled "system upload time", and can be hidden. CCTV appears on the timeline only
  if its recording time was entered.
- **Relationships need a basis:** every graph edge requires a written description of the record that
  supports it.
