# TRACE X: Digital Evidence Integrity & Investigation System

A Flask + SQLite investigation workspace for four detectives and one administrator. You can manage
fictional cases, suspects, witness statements, and digital evidence. Every evidence file gets a SHA-256
fingerprint and a hash-linked chain of custody. Relationships are explored with hand-written BFS/DFS,
and TRACE AI answers questions from the stored records.

TRACE X is **not a game**. There are no scores, no hidden "correct culprit", and the system never decides who is responsible.

---

## 1. Run it (VS Code, Windows / macOS / Linux)

```bash
# 1. open the TRACE-X folder in VS Code, then in the terminal:
python -m venv .venv
.venv\Scripts\activate      # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# 2. optional: copy the settings file and change the passwords
copy .env.example .env      # macOS/Linux: cp .env.example .env

# 3. start the app
python run.py

```

Open **http://127.0.0.1:5000**.

On the first run, TRACE X creates `instance/tracex.db`, the private `evidence_storage/` folder, and all
the fictional sample data automatically. You can also start it with `flask --app app run`.

### Demo accounts

The passwords come from `.env` (or these defaults if there is no `.env`). They exist only as Werkzeug
hashes in the database and never appear in any HTML or JavaScript.

| Role | Username | Default password |
| --- | --- | --- |
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

This **deletes** the database, all uploaded evidence, and all reports, then reloads the sample data.

### Run the tests

```bash
python -m pytest

```

There are 50 tests across authentication, permissions, SHA-256 integrity, every DSA module, every
page, the PDF report, and TRACE AI (with and without an AI provider).

---

## 2. Sample data ( 8 Active Cases)


| Case | Title | Category | Lead Investigator | Team / Notes |
|---|---|---|---|---|
| **CASE-001** | The Riverside Library Death | Homicide | **Warisha Ahmed** | Warisha (lead), Hiba |
| **CASE-002** | Disappearance of Aira Shakir | Missing Person | **Maryam Farhan** | Maryam (lead), Amna, Warisha |
| **CASE-003** | Crescent Bank Phishing Breach | Cybercrime | **Amna Fareed** | Amna (lead), Maryam |
| **CASE-004** | The Indigo Veil | Narcotics Offence | **Hiba Khan** | Hiba (lead), Warisha |
| **CASE-005** | Binance Wallet Theft | Cybercrime | **Maryam Farhan** | Maryam (lead), Warisha |
| **CASE-006** | The Mentalist | Homicide | **Warisha Ahmed** | Warisha (lead), Amna, Hiba, Maryam |
| **CASE-007** | The DUET Campus Theft | Theft | **Amna Fareed** | Amna (lead), Hiba |
| **CASE-008** | The Black Ledger | Criminal Conspiracy | **Hiba Khan** | Hiba (lead), Maryam |

Every evidence item is a real file that is really hashed and stored read-only. The "photos" are
generated placeholder images. **No CCTV footage is generated.** Put your staged videos in
`static/assets/demo-videos/` and reset, or upload them from a case's Evidence Vault.

---

## 3. Complete Project Structure & Custom Branding Assets

```text
TRACE-X/
├── .env                    local environment variables & secret overrides
├── .env.example            sample environment configuration template
├── .gitignore              git exclusion rules
├── app.py                  application factory: blueprints, CSRF, security headers, first-run seeding
├── config.py               settings from environment / .env (no secrets in code)
├── pytest.ini              pytest testing framework configuration
├── requirements.txt        Python package dependencies
├── run.py                  application runner entry point
├── ai/
│   ├── __init__.py
│   ├── assistant.py        TRACE AI workflow handler
│   ├── context_builder.py  intent detection and authorised context compilation
│   └── providers.py        Groq / OpenRouter / OpenAI / Gemini / Ollama adapters
├── database/
│   ├── __init__.py
│   ├── db.py               connection per request, query helpers, activity logging
│   ├── queries.py          shared read queries (cases, evidence, graph building, case bundle)
│   ├── schema.sql          all tables, foreign keys, and indexes
│   └── seed.py             fictional sample data + --reset CLI
├── dsa/                    hand-written data structures and algorithms (section 4)
│   ├── __init__.py
│   ├── graph.py            adjacency list, BFS, DFS traversals
│   ├── hash_table.py       separate chaining hash index
│   ├── linked_list.py      chain of custody nodes
│   ├── queue.py            task processing queue
│   ├── searching.py        binary search and keyword scoring
│   ├── sorting.py          merge sort timeline generator
│   ├── stack.py            undo stack for investigation notes
│   └── tree.py             evidence folder hierarchy tree
├── forensics/
│   ├── __init__.py
│   ├── custody.py          hash-linked custody records
│   ├── hashing.py          SHA-256 with hashlib (chunked for large videos)
│   ├── integrity.py        verify MATCH / MISMATCH / FILE MISSING
│   └── timeline.py         merge-sorted chronological event timeline & CSV importer
├── reports/
│   ├── __init__.py
│   └── generator.py        PDF investigation report generator (ReportLab)
├── routes/                 one Flask blueprint per area
│   ├── __init__.py
│   ├── admin.py            dashboard, assignments, users, logs, integrity demo
│   ├── ai.py               TRACE AI page + JSON endpoint
│   ├── auth.py             landing, login/logout, permission checks
│   ├── cases.py            case files, suspects, witnesses, notes, timeline, graph
│   ├── detectives.py       portal, case list, search
│   ├── evidence.py         upload, viewers, streaming, verification, custody
│   ├── inspector.py        DSA Inspector
│   └── reports.py          preview, generate, download PDF
├── static/                 
│   ├── css/
│   │   └── style.css       custom dark theme & styling
│   ├── js/                 
│   │   ├── ai.js           chat widget & AI assistant scripts
│   │   ├── app.js          core application frontend scripts
│   │   ├── graph.js        relationship network graph interactions
│   │   └── intro.js        onboarding & guidance helper
│   └── assets/             
│       ├── backgrounds/    landing backgrounds and media
│       ├── case-images/    comprehensive evidence files (c1 to c8)
│       ├── demo-videos/    cctv footage (case7cctv.mp4)
│       ├── detectives/     detective & administrator profile avatars
│       ├── suspects/       suspect photos & silhouettes
│       ├── tracex-logo.png seamless navbar header logo
│       ├── tracex-hero.png chrome & crimson landing hero banner
│       └── trace-ai-badge.png custom graphical badge for floating TRACE AI toggle
├── templates/              Jinja2 templates & case_tabs/ partials
├── tests/                  pytest suite (50 comprehensive tests)
│   ├── conftest.py         pytest fixtures and app setup
│   ├── test_auth.py        authentication & session tests
│   ├── test_dsa.py         DSA module unit tests
│   ├── test_integrity.py   SHA-256 & tamper detection tests
│   ├── test_pages.py       page rendering & route tests
│   └── test_permissions.py RBAC & access control tests
├── evidence_storage/       PRIVATE uploaded evidence (outside /static, created automatically)
└── instance/               tracex.db, generated reports, secret key

```

### Custom Branding Implementation

* **Seamless Navbar Header**: Uses the `.brand-seamless` CSS class across templates to guarantee clean alignment and transparency for `tracex-logo.png`.
* **Landing Page Hero**: Features the bold chrome-and-crimson `tracex-hero.png` wordmark banner.
* **Floating AI Chat Widget**: The bottom-right floating trigger uses the custom graphical `trace-ai-badge.png` asset with drop-shadow styling.

---

## 4. The DSA modules (all run in Python)

The **DSA Inspector** (sidebar) runs each one on live records and prints input, operation, result, and steps.

| Structure / algorithm | File | Used for | Complexity |
| --- | --- | --- | --- |
| **Linked list** | `dsa/linked_list.py` | Chain of custody: each custody event is a node | append O(1), search O(n) |
| **Stack** | `dsa/stack.py` | Undo for investigation notes (LIFO history) | push/pop O(1) |
| **Queue** | `dsa/queue.py` | Evidence-analysis tasks processed oldest first (FIFO) | enqueue/dequeue O(1) |
| **Hash table** | `dsa/hash_table.py` | Index of evidence by ID (`EV-0007`) | average O(1) |
| **Tree** | `dsa/tree.py` | Archive → case → type folder → evidence hierarchy | O(n) |
| **Graph** | `dsa/graph.py` | Suspects, evidence, witnesses, devices linked by relations | O(V + E) |
| **BFS / DFS** | `dsa/graph.py` | Shortest traversal and deep chain backtracking | O(V + E) |
| **Merge sort** | `dsa/sorting.py` | Stable chronological timeline sorting | O(n log n) |
| **Binary & Keyword search** | `dsa/searching.py` | Fast case lookup and scored keyword searching | O(log n) / O(n) |

---

## 5. Security & AI Configuration

* Passwords stored as secure Werkzeug hashes.
* HttpOnly, SameSite=Lax signed cookies with CSRF protection on every POST.
* Role-based access control (`require_case_access()`) across all endpoints.
* Read-only write-once evidence vault with SHA-256 fingerprinting.
* **AI Configuration (`config.py` & `.env`)**: Configured for high-performance cloud inference via Groq (`AI_PROVIDER=groq`) with fallback support for Ollama, Gemini, OpenRouter, and OpenAI.

```

```