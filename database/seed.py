"""
Fictional sample data for TRACE X.

This runs automatically the first time the app starts (no database yet).
To wipe everything and start again:

    python -m database.seed --reset

WARNING: --reset deletes the database, every uploaded evidence file and
every generated report.

Demo account passwords come from the environment (see .env.example):
    TRACEX_ADMIN_USERNAME / TRACEX_ADMIN_PASSWORD
    TRACEX_DETECTIVE_PASSWORD   (shared by the four detective accounts)

ALL people, places, cases and files below are fictional. Sample "photos" are
generated placeholder images and sample documents are generated text/PDF/CSV
files. No CCTV footage is generated: put your own staged videos in
static/assets/demo-videos/ before the first run (or reset) and they are
registered as CCTV evidence in CASE-001.
"""

import io
import os
import shutil
import stat
import struct
import sys
import zlib
from functools import lru_cache

from flask import current_app
from werkzeug.security import generate_password_hash

from database.db import create_schema, get_db, log_activity, now_str
from forensics.custody import record_custody_event
from forensics.integrity import verify_evidence

DETECTIVES = [
    ("amna", "Amna Fareed", "DET-101"),
    ("warisha", "Warisha Ahmed", "DET-102"),
    ("hiba", "Hiba Khan", "DET-103"),
    ("maryam", "Maryam Farhan", "DET-104"),
]


# --------------------------------------------------------- file generators

@lru_cache(maxsize=None)        # generating pixels in pure Python is slow; do each image once
def make_placeholder_png(width, height, tint):
    """Generate a 'scene photo' placeholder PNG with only the standard library:
    dark gradient, measuring grid, an evidence marker and a forensic scale bar."""
    r0, g0, b0 = tint
    cx, cy, radius = width * 0.62, height * 0.45, min(width, height) * 0.09
    rows = []
    for y in range(height):
        row = bytearray(b"\x00")                      # PNG filter byte: none
        fade = 0.25 + 0.55 * (1 - y / height)
        for x in range(width):
            r, g, b = int(r0 * fade), int(g0 * fade), int(b0 * fade)
            if x % 40 == 0 or y % 40 == 0:            # measuring grid
                r, g, b = min(r + 28, 255), min(g + 28, 255), min(b + 28, 255)
            d2 = (x - cx) ** 2 + (y - cy) ** 2
            if radius ** 2 * 0.72 <= d2 <= radius ** 2:   # evidence marker ring
                r, g, b = 240, 178, 60
            if abs(x - cx) < 2 and abs(y - cy) < radius * 1.6 or abs(y - cy) < 2 and abs(x - cx) < radius * 1.6:
                r, g, b = 240, 178, 60
            if height - 46 <= y <= height - 30 and 30 <= x <= 330:   # 10-block scale bar
                r, g, b = (235, 235, 235) if ((x - 30) // 30) % 2 == 0 else (25, 25, 25)
            row += bytes((r, g, b))
        rows.append(bytes(row))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)    # 8-bit RGB
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))


def make_pdf(title, paragraphs):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawString(56, height - 70, title)
    pdf.setFont("Helvetica-Oblique", 8.5)
    pdf.drawString(56, height - 86, "FICTIONAL DOCUMENT - created for the TRACE X training dataset")
    y = height - 120
    pdf.setFont("Helvetica", 10)
    for paragraph in paragraphs:
        words, line = paragraph.split(), ""
        for word in words:
            if pdf.stringWidth(line + " " + word, "Helvetica", 10) > width - 112:
                pdf.drawString(56, y, line)
                y -= 14
                line = word
            else:
                line = (line + " " + word).strip()
        pdf.drawString(56, y, line)
        y -= 24
    pdf.save()
    return buffer.getvalue()


# --------------------------------------------------------------- the data

CASES = [
    {
        "case_number": "CASE-001", "title": "The Riverside Library Death", "category": "Homicide",
        "status": "Under Investigation", "incident_date": "2026-03-13",
        "location": "Old Riverside Library, Rare Books Room (2nd floor)", "created_at": "2026-03-14 08:05:00",
        "description": (
            "Professor Tariq Mehmood (61), a manuscript historian, was found dead in the Rare Books Room of the "
            "Old Riverside Library at 07:10 on 14 March 2026 by the night guard at the end of his shift. The "
            "preliminary pathology summary records a blunt-force head injury and an estimated time of death "
            "between 21:30 and 23:30 on 13 March. A ledger of manuscript loans was missing from the room. "
            "There was no sign of forced entry."),
        "summary": "Access-card records conflict with one suspect's stated alibi. Alibis of the other two suspects "
                   "are only partly confirmed.",
        "team": [("amna", "lead"), ("hiba", "investigator")],
    },
    {
        "case_number": "CASE-002", "title": "Disappearance of Zoya Malik", "category": "Missing Person",
        "status": "Under Investigation", "incident_date": "2026-05-02",
        "location": "Canal View Plaza to Central Bus Terminal", "created_at": "2026-05-03 10:20:00",
        "description": (
            "Zoya Malik (24), a freelance graphic designer, was last seen leaving her shared studio at Canal View "
            "Plaza at about 18:45 on 2 May 2026. Her phone stopped connecting to the network at 19:52 near the "
            "Central Bus Terminal. Her sister reported her missing the next morning. No ransom demand or message "
            "has been received."),
        "summary": "Phone records and a bus conductor's sighting place her near the terminal; destination unknown.",
        "team": [("warisha", "lead")],
    },
    {
        "case_number": "CASE-003", "title": "Crescent Bank Phishing Breach", "category": "Cybercrime",
        "status": "Pending Review", "incident_date": "2026-06-18",
        "location": "Crescent Bank (fictional) - online banking platform", "created_at": "2026-06-19 09:00:00",
        "description": (
            "Between 18 and 19 June 2026, 37 customer accounts at the fictional Crescent Bank were accessed after "
            "customers entered their details on a cloned login page hosted at crescentbank-verify.example. "
            "Funds were moved to three mule accounts. The bank's security analyst noticed a burst of logins from a "
            "single IP range and disabled the affected sessions at 02:40 on 19 June."),
        "summary": "Server logs tie the logins to one IP range. An internal workstation appears in the logs.",
        "team": [("hiba", "lead"), ("maryam", "viewer")],
    },
    {
        "case_number": "CASE-004", "title": "Noor Gallery Painting Theft", "category": "Theft",
        "status": "Open", "incident_date": "2026-09-21",
        "location": "Noor Art Gallery (fictional), East Wing", "created_at": "2026-09-22 09:30:00",
        "description": (
            "The oil painting 'Evening at the River' (fictional artist S. Rahim, insured value recorded in the "
            "gallery inventory) was found missing from the East Wing at opening time on 22 September 2026. The "
            "frame was left behind. The gallery had hosted a private viewing the evening before."),
        "summary": "",
        "team": [],          # left unassigned on purpose: the admin assigns it during the demo
    },
]

SUSPECTS = {
    "CASE-001": [
        {"key": "kamran", "name": "Kamran Sheikh", "relationship": "Head librarian; colleague of the victim",
         "background": "Head librarian for 14 years. Responsible for the manuscript loan ledger.",
         "motive": "Staff report a heated argument with the victim about the missing loan ledger on 13 March.",
         "alibi": "States he left the library at about 20:00 and was at home all evening; his wife confirms.",
         "statements": "\"I left before eight. I did not come back that night. Anyone could have used my card.\"",
         "notes": "Card C-1001 is registered to him."},
        {"key": "sana", "name": "Sana Iqbal", "relationship": "Research assistant to the victim",
         "background": "PhD candidate working on the victim's manuscript catalogue since 2024.",
         "motive": "The victim had raised concerns about copied passages in her draft chapter.",
         "alibi": "States she was at Riverside Café from 20:30 until about 22:15, then took a rickshaw home.",
         "statements": "\"Professor Mehmood and I disagreed about my chapter, but we had sorted it out.\"",
         "notes": ""},
        {"key": "daniyal", "name": "Daniyal Raza", "relationship": "Rare-book dealer",
         "background": "Runs a private antiquarian book business; previously sold items to the library.",
         "motive": "The victim refused to authenticate a manuscript the dealer was trying to sell.",
         "alibi": "States he was at a dinner meeting until midnight. The other diner has not yet been identified.",
         "statements": "\"I wanted his signature on a certificate, nothing more.\"",
         "notes": "Sent an email to the victim on 12 March (see evidence)."},
    ],
    "CASE-002": [
        {"key": "hamza", "name": "Hamza Qureshi", "relationship": "Former fiancé",
         "background": "Engagement to Zoya ended in April 2026.",
         "motive": "Friends describe repeated messages after the engagement ended.",
         "alibi": "States he was at his cousin's wedding event from 18:00 to 23:30.",
         "statements": "\"I have not spoken to her since the 20th of April.\"", "notes": ""},
        {"key": "nadia", "name": "Nadia Butt", "relationship": "Business partner in the shared studio",
         "background": "Co-rents the studio at Canal View Plaza with Zoya.",
         "motive": "Dispute over an unpaid share of studio rent and a client payment.",
         "alibi": "States she left the studio at 18:30, before Zoya.",
         "statements": "\"She was fine when I left. She said she was meeting someone.\"", "notes": ""},
    ],
    "CASE-003": [
        {"key": "faraz", "name": "Faraz Ali", "relationship": "Former IT contractor for the bank",
         "background": "Contract for the online banking upgrade ended on 31 May 2026.",
         "motive": "Contract was ended early; payment dispute recorded with HR.",
         "alibi": "States he was at home and offline on the night of 18 June.",
         "statements": "\"My access was removed when my contract ended.\"", "notes": ""},
        {"key": "mehwish", "name": "Mehwish Anwar", "relationship": "Branch teller",
         "background": "Teller at the main branch for three years.",
         "motive": "None recorded. Her workstation ID appears in the server log.",
         "alibi": "Off duty from 17:00 on 18 June; branch closed overnight.",
         "statements": "\"I logged out at five. I never share my password.\"", "notes": ""},
        {"key": "shadow", "name": "Unknown user 'shadowteller'", "relationship": "Online alias",
         "background": "Alias advertising 'bank login kits' on a forum (fictional).",
         "motive": "Unknown.", "alibi": "Not applicable - identity unknown.", "statements": "", "notes": ""},
    ],
    "CASE-004": [
        {"key": "salman", "name": "Salman Haider", "relationship": "Contract art installer",
         "background": "Installed the East Wing exhibition on 19 September.",
         "motive": "None recorded.", "alibi": "Not yet interviewed.", "statements": "", "notes": ""},
        {"key": "kiran", "name": "Kiran Aftab", "relationship": "Guest at the private viewing",
         "background": "Private collector; enquired about buying the painting in August.",
         "motive": "Offer to buy the painting was refused.", "alibi": "Not yet interviewed.",
         "statements": "", "notes": ""},
    ],
}

ACCESS_LOG_CSV = """timestamp,door,card_id,card_holder,direction
2026-03-13 18:02:11,Main Entrance,C-1001,Kamran Sheikh,ENTRY
2026-03-13 18:15:40,Rare Books Room,C-1001,Kamran Sheikh,ENTRY
2026-03-13 19:58:03,Main Entrance,C-1001,Kamran Sheikh,EXIT
2026-03-13 20:10:27,Main Entrance,C-2044,Tariq Mehmood,ENTRY
2026-03-13 20:14:52,Rare Books Room,C-2044,Tariq Mehmood,ENTRY
2026-03-13 22:47:19,Side Entrance,C-1001,Kamran Sheikh,ENTRY
2026-03-13 22:51:05,Rare Books Room,C-1001,Kamran Sheikh,ENTRY
2026-03-13 23:20:44,Side Entrance,C-1001,Kamran Sheikh,EXIT
2026-03-14 07:10:02,Rare Books Room,G-0007,Bilal Akhtar,ENTRY
"""

CALL_RECORDS_CSV = """timestamp,type,other_party,duration_sec,cell_tower
2026-05-02 17:58:20,INCOMING CALL,+00-300-0000412 (Nadia Butt),94,Canal View North
2026-05-02 18:41:07,OUTGOING SMS,+00-321-0000777 (unknown),0,Canal View North
2026-05-02 19:12:45,INCOMING CALL,+00-321-0000777 (unknown),212,Mall Road East
2026-05-02 19:40:31,OUTGOING CALL,+00-333-0000158 (Ayesha Malik),18,Terminal Road
2026-05-02 19:52:09,NETWORK DETACH,-,0,Central Bus Terminal
"""

AUTH_LOG_CSV = """timestamp,event,account,source_ip,workstation,result
2026-06-18 17:02:44,LOGOUT,teller.mehwish,10.20.4.18,BR-TELLER-04,OK
2026-06-18 23:41:10,ADMIN LOGIN,svc.upgrade,203.0.113.45,-,OK
2026-06-18 23:44:52,CONFIG CHANGE,svc.upgrade,203.0.113.45,-,Redirect rule added
2026-06-19 00:15:03,CUSTOMER LOGIN,cust-10982,203.0.113.61,-,OK
2026-06-19 00:15:40,TRANSFER,cust-10982,203.0.113.61,-,PKR 95000 to mule account A
2026-06-19 01:02:18,WORKSTATION LOGIN,teller.mehwish,10.20.4.18,BR-TELLER-04,OK
2026-06-19 01:30:55,CUSTOMER LOGIN,cust-11247,203.0.113.62,-,OK
2026-06-19 02:40:00,SESSIONS REVOKED,security.usman,10.20.1.5,SEC-01,37 sessions
"""

GUARD_TRANSCRIPT = """INTERVIEW TRANSCRIPT (FICTIONAL)
Case: CASE-001   Interviewee: Bilal Akhtar, night guard   Interviewer: Det. Amna Fareed
Date: 14 March 2026, 09:40

AF: Tell me about your shift on the 13th.
BA: I started at 20:00. The professor came in around ten past eight. He often worked late.
AF: Did you hear anything unusual?
BA: Around half past ten I heard raised voices from the second floor. Two men, I think. It stopped after a minute.
AF: Did you go up?
BA: Not then. On my 23:00 round the Rare Books Room door was closed and the light was on. I thought he was still working.
AF: When did you open the door?
BA: At ten past seven in the morning, at the end of my shift. That is when I found him.
AF: Did you see anyone use the side entrance?
BA: No. The side entrance is not visible from my desk.
"""

DEALER_EMAIL = """From: d.raza@antiquarian-books.example
To: t.mehmood@riverside-library.example
Date: Thu, 12 Mar 2026 21:14
Subject: The Khattat manuscript

Professor,
I have a buyer waiting. Your refusal to sign the authentication certificate is costing me a great deal.
I would like to meet in person before Saturday to settle this.
You will regret blocking this sale if we cannot agree.
D. Raza
"""

MISSING_REPORT = """MISSING PERSON REPORT (FICTIONAL)
Reported by: Ayesha Malik (sister)       Received: 03 May 2026, 09:15
Missing person: Zoya Malik, female, 24, approx. 5'4", shoulder-length black hair
Last seen wearing: mustard kurta, denim jacket, black backpack with a white patch
Last seen: leaving studio, Canal View Plaza, approx. 18:45 on 02 May 2026
Phone: last call to reporting person at 19:40, 18 seconds, "she sounded rushed and said she would call back"
Medical: none known.  Bank cards: no use since 02 May (bank enquiry pending)
"""

PHISHING_EMAIL = """From: "Crescent Bank Security" <alerts@crescentbank-verify.example>
Subject: Action required: unusual sign-in detected
Date: 18 Jun 2026 22:58

Dear Customer,
We detected an unusual sign-in to your Crescent Bank account. To avoid suspension, verify your
identity within 12 hours:  https://crescentbank-verify.example/login
Crescent Bank Security Team

[Analyst note at registration: the sender domain is not a Crescent Bank domain.]
"""

GALLERY_INVENTORY = """NOOR ART GALLERY - INVENTORY EXTRACT (FICTIONAL)
Item NG-0147  'Evening at the River'  oil on canvas, 60 x 90 cm, artist S. Rahim
Location: East Wing, wall 3      Last condition check: 19 Sep 2026 (installer S. Haider present)
Status on 22 Sep 2026 08:55: painting missing, frame on floor below hanging point
Private viewing 21 Sep 2026, 19:00-22:00, 41 guests on list
"""


def _evidence_specs():
    """(case, key, filename, bytes, description, uploader, uploaded_at)."""
    return [
        ("CASE-001", "scene", "scene_photo_rare_books_room.png", make_placeholder_png(800, 500, (70, 110, 150)),
         "Scene photograph of the Rare Books Room taken after discovery (generated placeholder - replace with "
         "your own staged photo).", "amna", "2026-03-14 09:05:00"),
        ("CASE-001", "access", "library_access_log_2026-03-13.csv", ACCESS_LOG_CSV.encode(),
         "Door access-card export from the library security system for 13-14 March.", "hiba", "2026-03-14 12:30:00"),
        ("CASE-001", "autopsy", "preliminary_pathology_summary.pdf", make_pdf(
            "Preliminary Pathology Summary - Tariq Mehmood", [
                "Case reference: CASE-001. Examination date: 14 March 2026.",
                "Findings: a depressed fracture of the left parietal bone consistent with a single blow from a "
                "heavy object with a flat edge. No defensive injuries were recorded.",
                "Estimated time of death: between 21:30 and 23:30 on 13 March 2026, based on body temperature "
                "and rigor at 08:20 on 14 March.",
                "Toxicology: pending.",
            ]), "Preliminary pathology summary (fictional).", "amna", "2026-03-15 16:45:00"),
        ("CASE-001", "transcript", "guard_interview_transcript.txt", GUARD_TRANSCRIPT.encode(),
         "Transcript of the interview with night guard Bilal Akhtar.", "amna", "2026-03-14 10:30:00"),
        ("CASE-001", "email", "dealer_email_printout.txt", DEALER_EMAIL.encode(),
         "Email printout recovered from the victim's office computer.", "hiba", "2026-03-16 11:10:00"),
        ("CASE-002", "lobby", "office_lobby_still.png", make_placeholder_png(800, 500, (120, 95, 140)),
         "Still frame from the Canal View Plaza lobby camera (generated placeholder - replace with your own).",
         "warisha", "2026-05-03 15:00:00"),
        ("CASE-002", "calls", "zoya_call_detail_records.csv", CALL_RECORDS_CSV.encode(),
         "Call detail records for Zoya Malik's phone, 2 May 2026 (fictional).", "warisha", "2026-05-04 13:20:00"),
        ("CASE-002", "report", "missing_person_report.txt", MISSING_REPORT.encode(),
         "Original missing person report.", "warisha", "2026-05-03 10:25:00"),
        ("CASE-003", "authlog", "server_auth_log_2026-06-18.csv", AUTH_LOG_CSV.encode(),
         "Authentication log export from the online banking server.", "hiba", "2026-06-19 10:15:00"),
        ("CASE-003", "phish", "phishing_email_sample.txt", PHISHING_EMAIL.encode(),
         "Phishing email forwarded by customer Rabia Siddiqui.", "hiba", "2026-06-19 10:40:00"),
        ("CASE-003", "screenshot", "cloned_login_page_screenshot.png", make_placeholder_png(800, 500, (60, 130, 110)),
         "Screenshot of the cloned login page (generated placeholder - replace with your own).",
         "hiba", "2026-06-19 11:05:00"),
        ("CASE-004", "inventory", "gallery_inventory_extract.txt", GALLERY_INVENTORY.encode(),
         "Inventory extract supplied by the gallery manager.", "admin", "2026-09-22 10:00:00"),
    ]


def seed_database():
    """Create the schema and load the sample data. Call inside an app context."""
    from routes.evidence import store_evidence_file   # imported here to avoid a circular import

    db = get_db()
    create_schema(db)
    config = current_app.config
    stamp = now_str()

    # ---- users: exactly one administrator and four detectives
    users = {}
    cursor = db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, badge_id, specialization, created_at) "
        "VALUES (?, ?, ?, 'admin', 'ADM-001', 'System administration', ?)",
        (config["ADMIN_USERNAME"].lower(), generate_password_hash(config["ADMIN_PASSWORD"]),
         "TRACE X Administrator", stamp))
    users["admin"] = {"id": cursor.lastrowid, "role": "admin"}
    for username, full_name, badge, specialization in DETECTIVES:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, full_name, role, badge_id, specialization, created_at) "
            "VALUES (?, ?, ?, 'detective', ?, ?, ?)",
            (username, generate_password_hash(config["DETECTIVE_PASSWORD"]), full_name, badge, specialization, stamp))
        users[username] = {"id": cursor.lastrowid, "role": "detective"}

    # ---- cases and assignments
    cases = {}
    for case in CASES:
        cursor = db.execute(
            "INSERT INTO cases (case_number, title, category, description, summary, status, incident_date, location, "
            "created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (case["case_number"], case["title"], case["category"], case["description"], case["summary"],
             case["status"], case["incident_date"], case["location"], case["created_at"], users["admin"]["id"]))
        cases[case["case_number"]] = {"id": cursor.lastrowid, "case_number": case["case_number"]}
        for username, level in case["team"]:
            db.execute("INSERT INTO case_assignments (case_id, user_id, permission_level, assigned_at, assigned_by) "
                       "VALUES (?, ?, ?, ?, ?)", (cursor.lastrowid, users[username]["id"], level,
                                                  case["created_at"], users["admin"]["id"]))

    # ---- suspects
    suspects = {}
    for case_number, rows in SUSPECTS.items():
        for s in rows:
            cursor = db.execute(
                "INSERT INTO suspects (case_id, name, background, relationship, motive, alibi, statements, notes, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cases[case_number]["id"], s["name"], s["background"], s["relationship"], s["motive"], s["alibi"],
                 s["statements"], s["notes"], stamp, stamp))
            suspects[s["key"]] = cursor.lastrowid
    db.commit()

    # ---- evidence: real files, really hashed, stored read-only
    evidence = {}
    for case_number, key, filename, data, description, uploader, uploaded_at in _evidence_specs():
        user = {"id": users[uploader]["id"]}
        evidence[key] = store_evidence_file(cases[case_number], io.BytesIO(data), filename, user,
                                            description=description, uploaded_at=uploaded_at)

    # Optional staged CCTV videos supplied by the students.
    video_dir = config["DEMO_VIDEO_DIR"]
    if os.path.isdir(video_dir):
        videos = sorted(f for f in os.listdir(video_dir)
                        if f.lower().rsplit(".", 1)[-1] in ("mp4", "webm", "ogv", "mov", "m4v"))
        for number, name in enumerate(videos, start=1):
            with open(os.path.join(video_dir, name), "rb") as handle:
                evidence[f"video{number}"] = store_evidence_file(
                    cases["CASE-001"], handle, name, {"id": users["amna"]["id"]},
                    description="Staged CCTV footage supplied for the demonstration.",
                    camera_id=f"CAM-{number:02d}")

    # ---- witnesses
    witness_rows = [
        ("CASE-001", "Bilal Akhtar", "Night guard, Old Riverside Library",
         "Heard two raised male voices from the second floor at about 22:30. On his 23:00 round the Rare Books "
         "Room door was closed with the light on. Found the professor at 07:10 when he opened the door.",
         "2026-03-14 09:40:00", "amna", None, "transcript"),
        ("CASE-001", "Rubina Saleem", "Owner, Riverside Café",
         "Sana Iqbal sat at the corner table from about 20:30 and paid and left at about 22:00, not later.",
         "2026-03-15 14:10:00", "amna", "sana", None),
        ("CASE-001", "Aslam Javed", "Taxi driver",
         "Dropped a male passenger carrying a long flat parcel at the library's side entrance at about 22:40. "
         "Could not see his face clearly; the fare was paid in cash.",
         "2026-03-16 17:25:00", "hiba", None, None),
        ("CASE-002", "Ayesha Malik", "Sister of the missing person",
         "Zoya called at 19:40 sounding rushed and said she would call back. She did not mention where she was going.",
         "2026-05-03 09:20:00", "warisha", None, "calls"),
        ("CASE-002", "Shahid Mehmood", "Bus conductor, intercity coach",
         "A young woman with a black backpack with a white patch boarded the 20:10 coach at the Central Bus Terminal "
         "and got off at the first stop. He did not see if anyone was with her.",
         "2026-05-05 12:00:00", "warisha", None, None),
        ("CASE-003", "Usman Ghani", "Security analyst, Crescent Bank",
         "Noticed 30+ customer logins from 203.0.113.x within an hour after midnight and revoked all sessions at 02:40. "
         "Found a redirect rule added at 23:44 by the service account svc.upgrade.",
         "2026-06-19 09:30:00", "hiba", "faraz", "authlog"),
        ("CASE-003", "Rabia Siddiqui", "Bank customer",
         "Received the 'unusual sign-in' email at 22:58, entered her details on the linked page, and saw a transfer "
         "she did not make the next morning.", "2026-06-19 13:00:00", "hiba", None, "phish"),
        ("CASE-004", "Zainab Ali", "Gallery receptionist",
         "Locked the East Wing at 22:20 after the private viewing. The painting was on the wall at that time.",
         "2026-09-22 10:30:00", "admin", None, None),
    ]
    witnesses = {}
    for case_number, name, contact, statement, recorded_at, by, suspect_key, evidence_key in witness_rows:
        cursor = db.execute(
            "INSERT INTO witnesses (case_id, name, contact, statement, recorded_at, recorded_by, related_suspect_id, "
            "related_evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (cases[case_number]["id"], name, contact, statement, recorded_at, users[by]["id"],
             suspects.get(suspect_key), evidence.get(evidence_key)))
        witnesses[name.split()[0].lower()] = cursor.lastrowid
    # One statement that was corrected later, to show the audit history.
    db.execute("INSERT INTO witness_history (witness_id, previous_statement, edited_by, edited_at, reason) "
               "VALUES (?, ?, ?, ?, ?)",
               (witnesses["rubina"], "Sana Iqbal was at the café from about 20:30 until after 22:00.",
                users["amna"]["id"], "2026-03-15 16:00:00", "Witness corrected the time after checking her till receipt."))

    # ---- incident timeline (CSV logs are imported through the analysis queue)
    timeline_rows = [
        ("CASE-001", "2026-03-12 21:14:00", "Email sent", "Daniyal Raza emails the victim about the manuscript sale.",
         "Email printout", "email"),
        ("CASE-001", "2026-03-13 17:30:00", "Argument reported",
         "Two staff members report an argument between the victim and Kamran Sheikh about the loan ledger.",
         "Staff interviews (notes)", None),
        ("CASE-001", "2026-03-13 22:30:00", "Raised voices heard", "Night guard hears two raised male voices upstairs.",
         "Witness W-001 statement", "transcript"),
        ("CASE-001", "2026-03-13 22:40:00", "Passenger dropped at side entrance",
         "Taxi driver drops a man with a long parcel at the side entrance.", "Witness W-003 statement", None),
        ("CASE-001", "2026-03-13 23:00:00", "Guard round", "Rare Books Room door closed, light on.",
         "Witness W-001 statement", "transcript"),
        ("CASE-001", "2026-03-14 07:10:00", "Body discovered", "Night guard finds the victim in the Rare Books Room.",
         "Witness W-001 statement", "transcript"),
        ("CASE-001", "2026-03-14 07:25:00", "Police notified", "Emergency call logged by the library.",
         "Control room log reference CR-5521", None),
        ("CASE-002", "2026-05-02 18:45:00", "Last seen at studio", "Zoya leaves the Canal View Plaza studio.",
         "Lobby still (EV) and Nadia Butt's statement", "lobby"),
        ("CASE-002", "2026-05-02 20:10:00", "Possible sighting", "Woman matching description boards the 20:10 coach.",
         "Witness W-005 statement", None),
        ("CASE-002", "2026-05-03 09:15:00", "Reported missing", "Ayesha Malik files the missing person report.",
         "Missing person report", "report"),
        ("CASE-003", "2026-06-18 22:58:00", "Phishing email received", "Customers receive the fake security alert.",
         "Phishing email sample", "phish"),
        ("CASE-003", "2026-06-19 02:40:00", "Sessions revoked", "Security analyst revokes 37 sessions.",
         "Witness W-006 statement", None),
        ("CASE-004", "2026-09-21 22:20:00", "East Wing locked", "Receptionist locks the East Wing after the viewing.",
         "Witness W-008 statement", None),
        ("CASE-004", "2026-09-22 08:55:00", "Theft discovered", "Painting found missing; frame on the floor.",
         "Gallery inventory extract", "inventory"),
    ]
    events = {}
    for case_number, when, kind, text, source, evidence_key in timeline_rows:
        cursor = db.execute(
            "INSERT INTO timeline_events (case_id, event_time, event_type, description, source, source_evidence_id, "
            "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (cases[case_number]["id"], when, kind, text, source, evidence.get(evidence_key),
             users["admin"]["id"], stamp))
        events[(case_number, kind)] = cursor.lastrowid

    # ---- relationships (every link states its recorded basis)
    def node(kind, key):
        table = {"suspect": suspects, "evidence": evidence, "witness": witnesses}
        return f"{kind}:{table[kind][key]}" if kind in table else f"{kind}:{key}"

    rel_rows = [
        ("CASE-001", node("device", "Access card C-1001"), node("suspect", "kamran"), "registered holder",
         "Library security system records C-1001 as issued to Kamran Sheikh.", "hiba"),
        ("CASE-001", node("device", "Access card C-1001"), node("evidence", "access"), "appears in",
         "C-1001 is logged at the side entrance at 22:47 and the Rare Books Room at 22:51.", "hiba"),
        ("CASE-001", node("evidence", "access"), node("location", "Side Entrance"), "records activity at",
         "Access log rows for the side entrance door.", "hiba"),
        ("CASE-001", node("witness", "aslam"), node("location", "Side Entrance"), "observed activity at",
         "Taxi driver statement: passenger dropped at side entrance about 22:40.", "hiba"),
        ("CASE-001", node("witness", "rubina"), node("suspect", "sana"), "mentions",
         "Café owner states Sana Iqbal left at about 22:00.", "amna"),
        ("CASE-001", node("suspect", "daniyal"), node("evidence", "email"), "author of",
         "Sender address on the printout belongs to Daniyal Raza's business.", "hiba"),
        ("CASE-001", node("evidence", "scene"), node("location", "Rare Books Room"), "taken at",
         "Photograph registered as taken in the Rare Books Room after discovery.", "amna"),
        ("CASE-001", node("evidence", "autopsy"), node("location", "Rare Books Room"), "victim recovered from",
         "Pathology summary refers to the body recovered from the Rare Books Room.", "amna"),
        ("CASE-001", node("witness", "bilal"), node("evidence", "transcript"), "interview recorded in",
         "Transcript of the guard's interview on 14 March.", "amna"),
        ("CASE-001", node("event", events[("CASE-001", "Raised voices heard")]), node("location", "Rare Books Room"),
         "heard near", "Guard places the voices on the second floor near the Rare Books Room.", "amna"),
        ("CASE-001", node("suspect", "kamran"), node("event", events[("CASE-001", "Argument reported")]),
         "involved in", "Two staff members name him in the 17:30 argument.", "amna"),
        ("CASE-002", node("evidence", "calls"), node("location", "Central Bus Terminal"), "last network contact at",
         "Network detach recorded on the Central Bus Terminal tower at 19:52.", "warisha"),
        ("CASE-002", node("witness", "shahid"), node("location", "Central Bus Terminal"), "observed activity at",
         "Conductor's sighting at the 20:10 coach.", "warisha"),
        ("CASE-002", node("suspect", "nadia"), node("evidence", "calls"), "appears in",
         "Incoming call from Nadia Butt's number at 17:58.", "warisha"),
        ("CASE-002", node("evidence", "lobby"), node("location", "Canal View Plaza"), "taken at",
         "Lobby camera still registered from Canal View Plaza.", "warisha"),
        ("CASE-003", node("evidence", "authlog"), node("device", "Workstation BR-TELLER-04"), "records activity on",
         "Log row 01:02:18 shows a login on BR-TELLER-04.", "hiba"),
        ("CASE-003", node("suspect", "mehwish"), node("device", "Workstation BR-TELLER-04"), "assigned user of",
         "Bank asset register lists BR-TELLER-04 as Mehwish Anwar's workstation.", "hiba"),
        ("CASE-003", node("suspect", "faraz"), node("device", "Service account svc.upgrade"), "previously administered",
         "HR records show the upgrade service account was managed by Faraz Ali's contract team.", "hiba"),
        ("CASE-003", node("evidence", "authlog"), node("device", "Service account svc.upgrade"), "records activity of",
         "Admin login and redirect rule at 23:41-23:44.", "hiba"),
        ("CASE-003", node("evidence", "phish"), node("evidence", "screenshot"), "links to",
         "The email's link opens the page shown in the screenshot.", "hiba"),
        ("CASE-004", node("evidence", "inventory"), node("location", "East Wing"), "describes",
         "Inventory location for item NG-0147.", "admin"),
    ]
    for case_number, source, target, kind, text, by in rel_rows:
        db.execute("INSERT INTO evidence_relationships (case_id, source_node, target_node, relationship_type, "
                   "description, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (cases[case_number]["id"], source, target, kind, text, users[by]["id"], stamp))

    # ---- notes (one with an earlier version so Undo / the Stack can be demonstrated)
    cursor = db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-001"]["id"], users["amna"]["id"], "Access card discrepancy",
         "Card C-1001 (Kamran Sheikh) is logged at the side entrance at 22:47, after he says he went home. "
         "Need: whether the card can be cloned or was lent; side-entrance camera coverage; his wife's exact timings.",
         "2026-03-14 13:00:00", "2026-03-15 18:20:00"))
    db.execute("INSERT INTO note_history (note_id, title, content, saved_by, saved_at) VALUES (?, ?, ?, ?, ?)",
               (cursor.lastrowid, "Access card discrepancy",
                "Kamran's card appears in the log late at night. Check with security.",
                users["amna"]["id"], "2026-03-15 18:20:00"))
    db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-001"]["id"], users["hiba"]["id"], "Taxi passenger",
         "Driver's passenger arrived at 22:40, seven minutes before C-1001 was used. Ask the dispatcher for the pickup "
         "address.", "2026-03-16 18:00:00", "2026-03-16 18:00:00"))
    db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-003"]["id"], users["hiba"]["id"], "Service account",
         "svc.upgrade should have been disabled when the contract ended on 31 May. Request the IAM change ticket.",
         "2026-06-20 10:00:00", "2026-06-20 10:00:00"))

    # ---- one pending analysis task so the Queue has something to process
    db.execute("INSERT INTO analysis_tasks (case_id, evidence_id, task_type, requested_by, created_at) "
               "VALUES (?, ?, 'import_csv_timeline', ?, ?)",
               (cases["CASE-001"]["id"], evidence["access"], users["hiba"]["id"], "2026-03-14 12:35:00"))
    db.commit()

    # ---- extra custody history, then real SHA-256 verifications for some items
    record_custody_event(evidence["scene"], users["hiba"]["id"], "Evidence viewed", "Reviewed scene photograph",
                         timestamp="2026-03-14 11:02:00")
    record_custody_event(evidence["access"], users["amna"]["id"], "Evidence viewed", "Reviewed access log",
                         timestamp="2026-03-14 13:05:00")
    for key, username in (("scene", "amna"), ("autopsy", "amna"), ("transcript", "amna"),
                          ("authlog", "hiba"), ("phish", "hiba"), ("report", "warisha")):
        verify_evidence(get_db().execute("SELECT * FROM evidence WHERE id = ?", (evidence[key],)).fetchone(),
                        users[username]["id"])

    log_activity(users["admin"]["id"], "Database initialised", "system", None,
                 f"{len(CASES)} cases, {len(evidence)} evidence files")


# ---------------------------------------------------------------- reset CLI

def _remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def reset():
    from app import create_app
    from config import Config

    for folder in (Config.EVIDENCE_DIR, Config.REPORTS_DIR, Config.TEMP_DIR):
        if os.path.isdir(folder):
            shutil.rmtree(folder, onerror=_remove_readonly)
    if os.path.exists(Config.DATABASE):
        os.remove(Config.DATABASE)
    create_app()            # recreates folders, schema and sample data
    print("TRACE X reset complete. Sample data loaded.")


if __name__ == "__main__":
    if "--reset" in sys.argv:
        reset()
    else:
        print(__doc__)
