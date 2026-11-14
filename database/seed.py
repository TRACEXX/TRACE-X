"""
Case archive data for TRACE X.

This runs automatically the first time the app starts (no database yet).
To wipe everything and start again:

    python -m database.seed --reset

WARNING: --reset deletes the database, every uploaded evidence file and
every generated report.

Account passwords come from the environment (see .env.example):
    TRACEX_ADMIN_USERNAME / TRACEX_ADMIN_PASSWORD
    TRACEX_DETECTIVE_PASSWORD   (shared by the four detective accounts)

Every case file below forms the starting archive of a new install (CASE-005 summarises
public reporting of a real event and names no individual as a suspect).

WHERE THE EVIDENCE FILES LIVE
    static/assets/case-images/   every evidence file (photos, CCTV stills, chat
                                 screenshots, PDFs, CSV logs, text reports)
    static/assets/demo-videos/   videos (case7cctv.mp4 belongs to CASE-007)
    static/assets/suspects/      suspect photos
    static/assets/detectives/    detective photos
The seed copies each evidence file into evidence_storage/<CASE-NNN>/, hashes it
(SHA-256) and registers it. If a file is missing, that one item is skipped with
a warning instead of crashing the deploy.
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

# Updated with correct static paths for avatar macro resolution
DETECTIVES = [
    ("amna", "Amna Fareed", "DET-101", "Homicide & Forensics", "assets/detectives/amna.jpeg"),
    ("warisha", "Warisha Ahmed", "DET-102", "Cyber & Digital Forensics", "assets/detectives/warisha.jpeg"),
    ("hiba", "Hiba Khan", "DET-103", "Financial & Cybercrime", "assets/detectives/hiba.jpeg"),
    ("maryam", "Maryam Farhan", "DET-104", "Evidence & Intelligence", "assets/detectives/maryam.jpeg"),
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
        row = bytearray(b"\x00")                  # PNG filter byte: none
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
    pdf.drawString(56, height - 86, "CONFIDENTIAL - TRACE X case document - restricted circulation")
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


# ------------------------------------------------------ evidence file loaders
# Paths are built from the app's own folder (current_app.root_path / config), NEVER from the
# current working directory. A relative path such as Path("static/assets/...") only works when
# the server is started from inside the project folder; on Render it crashed the seed.

def _case_file(filename):
    """Bytes of static/assets/case-images/<filename>, or None (with a warning) if it is missing."""
    path = os.path.join(current_app.root_path, "static", "assets", "case-images", filename)
    if not os.path.isfile(path):
        print(f"[seed] WARNING: evidence file not found, skipped: static/assets/case-images/{filename}")
        return None
    with open(path, "rb") as handle:
        return handle.read()


def _video_file(filename):
    """Bytes of static/assets/demo-videos/<filename>, or None (with a warning) if it is missing."""
    path = os.path.join(current_app.config["DEMO_VIDEO_DIR"], filename)
    if not os.path.isfile(path):
        print(f"[seed] WARNING: video not found, skipped: static/assets/demo-videos/{filename}")
        return None
    with open(path, "rb") as handle:
        return handle.read()


def _static_photo(path):
    """Keep a photo path (relative to static/) only if the file exists, so a missing photo shows
    initials instead of a broken image."""
    if path and os.path.isfile(os.path.join(current_app.root_path, "static", path)):
        return path
    if path:
        print(f"[seed] WARNING: photo not found, showing initials instead: static/{path}")
    return None


# --------------------------------------------------------------- the data

CASES = [
    {
        "case_number": "CASE-001", "title": "The Riverside Library Death", "category": "Homicide",
        "status": "Under Investigation", "incident_date": "2026-03-13",
        "location": "Old Riverside Library, Rare Books Room (2nd floor)", "created_at": "2026-03-14 08:05:00",
        "description": (
            "Professor Tariq Rafiq (61), a university teacher, was found dead in the Rare Books Room of the "
            "Old Riverside Library at 07:10 on 14 March 2026 by the night guard at the end of his shift. The "
            "preliminary pathology summary records a blunt-force head injury and an estimated time of death "
            "between 21:30 and 23:30 on 13 March. A ledger of manuscript loans was missing from the room. "
            "There was no sign of forced entry."),
        "summary": "Access-card records conflict with one suspect's stated alibi. Alibis of the other two suspects "
                   "are only partly confirmed.",
        "team": [("warisha", "lead"), ("hiba", "investigator")],
    },
    {
        "case_number": "CASE-002", "title": "Disappearance of Aira Shakir", "category": "Missing Person",
        "status": "Under Investigation", "incident_date": "2026-05-02",
        "location": "DUET Gulberg Campus", "created_at": "2026-05-03 10:20:00",
        "description": (
            "Aira Shakir (19), a student, was last seen leaving for university at North Nazimabad - "
            "Five Star at about 18:45 on 2 May 2026. Her phone stopped connecting to the network at 19:52 near the "
            "Central Bus Terminal. Her sister reported her missing the next morning. No ransom demand or message "
            "has been received."),
        "summary": "Phone records and a bus conductor's sighting place her near the terminal; destination unknown.",
        "team": [("maryam", "lead"), ("amna", "investigator"), ("warisha", "viewer")],
    },
    {
        "case_number": "CASE-003", "title": "Crescent Bank Phishing Breach", "category": "Cybercrime",
        "status": "Pending Review", "incident_date": "2026-06-18",
        "location": "Crescent Bank - online banking platform", "created_at": "2026-06-19 09:00:00",
        "description": (
            "Between 18 and 19 June 2026, 37 customer accounts at Crescent Bank were accessed after "
            "customers entered their details on a cloned login page hosted at crescentbank-verify.example. "
            "Funds were moved to three mule accounts. The bank's security analyst noticed a burst of logins from a "
            "single IP range and disabled the affected sessions at 02:40 on 19 June."),
        "summary": "Server logs tie the logins to one IP range. An internal workstation appears in the logs.",
        "team": [("amna", "lead"), ("maryam", "investigator")],
    },
    {
        "case_number": "CASE-004",
        "title": "The Indigo Veil",
        "category": "Narcotics Offence",
        "status": "Open",
        "incident_date": "2026-03-13",
        "location": "West Wharf District, Karachi",
        "created_at": "2026-03-14 08:05:00",
        "description": (
            "On 13 March 2026, suspected narcotics activities were reported near "
            "Warehouse 03 in Karachi's West Wharf District. A hospital incident "
            "and CCTV footage of a suspicious duffel-bag exchange prompted an "
            "investigation. Unidentified packages marked with an indigo crescent, "
            "a handwritten ledger, and a mobile phone were recovered. "
            "Anmol Pinky and Walter White were identified as persons of interest. "
            "Their involvement remains unconfirmed."
        ),
        "summary": (
            "An ongoing narcotics investigation involving suspicious warehouse "
            "activity, conflicting witness statements, and unidentified packages "
            "bearing an indigo crescent symbol. Two suspects remain under "
            "investigation, with no confirmed culprit."
        ),
        "team": [("hiba", "lead"), ("warisha", "investigator")],  # Admin assigns detectives after intake
    },
    {
        "case_number": "CASE-005",
        "title": "Binance Wallet Theft",
        "category": "Cybercrime",
        "status": "Under Investigation",
        "incident_date": "2026-10-29",
        "location": "Binance Cryptocurrency Exchange (Global)",
        "created_at": "2026-10-29 20:25:00",
        "description": (
            "On October 29, 2026, Binance reportedly suffered a massive "
            "cryptocurrency theft involving approximately $6.36 billion across "
            "ten blockchains within just 20 minutes, beginning at 20:05 UTC. "
            "Attackers allegedly compromised hot wallet signing infrastructure "
            "through a DevOps engineer's laptop, impersonating authorized "
            "withdrawal services without obtaining master private keys. "
            "Ethereum wallets were reportedly exploited using EIP-7702 "
            "authorizations, while additional funds were transferred across "
            "Bitcoin, Tron, Solana, XRP, and other networks. "
            "Security organizations and stablecoin issuers reportedly froze "
            "approximately $2.7 billion in stolen assets, while Binance "
            "mobilized corporate reserves to cover remaining losses."
        ),
        "summary": (
            "Attackers reportedly stole $6.36 billion from Binance hot wallets "
            "across ten blockchains in 20 minutes. "
            "Approximately $2.7 billion was reportedly frozen as investigators "
            "traced the compromised signing infrastructure."
        ),
        "team": [("maryam", "lead"), ("warisha", "investigator")],
    },
    # ------------------------------------------------ CASE-006: THE RED SIGNATURE MURDERS
    {
        
"case_number": "CASE-006",
"title": "The Mentalist",
"category": "Homicide",
"status": "Under Investigation",
"incident_date": "2026-01-12",
"location": "Multiple crime scenes; Crimson Task Force jurisdiction",
"created_at": "2026-04-18 09:00:00",

"description": (
    "CASE-006: THE RED JOHN INVESTIGATION. "
    "A series of connected murders is attributed to the notorious serial killer "
    "known as Red John, whose true identity remains unknown to investigators. "
    "The offender is recognized for leaving a distinctive red smiley-face "
    "signature at crime scenes and psychologically manipulating law-enforcement "
    "personnel. The Administrator's wife and daughter were murdered by Red John, "
    "making the case personally significant to the department. Due to this "
    "conflict of interest, the Administrator is formally recused from operational "
    "command. Detective Warisha has been appointed Lead Investigating Officer. "
    "The investigation focuses on three suspects: Red John, Gale Bertram, "
    "and Bret Stiles. Evidence suggests possible connections to the Visualize "
    "organization, the secret Blake Association, confidential information leaks, "
    "and anonymous communications directed toward investigators. "
    "Incident classification: serial homicide, targeted family murders, "
    "psychological intimidation, organized corruption, and possible "
    "evidence manipulation. The Crimson Task Force is responsible for "
    "identifying Red John's true identity and establishing the involvement "
    "of other suspects."
),

"summary": (
    "Active serial-homicide investigation involving Red John, an unidentified "
    "killer responsible for multiple murders, including the Administrator's "
    "wife and daughter. The offender leaves a red smiley-face signature "
    "and appears to possess confidential investigative information. "
    "Three suspects are under investigation: Red John, Gale Bertram, "
    "and Bret Stiles. Detective Warisha leads the Crimson Task Force "
    "in examining forensic evidence, witness statements, possible "
    "Blake Association connections, and the offender's true identity."
),

"team": [
    ("warisha", "lead"),
    ("amna", "investigator"),
    ("hiba", "investigator"),
    ("maryam", "investigator")
],

    },
    # ------------------------------------------------ CASE-007: THE DUET CAMPUS THEFT
    {
        "case_number": "CASE-007", "title": "The DUET Campus Theft", "category": "Theft",
        "status": "Pending Review", "incident_date": None,
        "location": "DUET Gulberg Campus",
        "created_at": "2026-11-07 12:00:00",
        "description": (
            "In a campus classroom, student belongings including a mobile phone were reportedly "
            "taken near chairs. Uswa and Fatima are the persons of interest, and Darishna reports observing "
            "activity near the corridor. A complainant-supplied classroom video, seven extracted frames, two "
            "portraits and recovered chat messages are available for review. The actual incident "
            "date is unknown, and the source footage alone does not establish criminal wrongdoing."
        ),
        "summary": (
            "DUET student-property theft: Uswa and Fatima are the persons of interest on the current "
            "working theory only. Original video and supplied portraits are separate from recovered chat exhibits."
        ),
        "team": [("amna", "lead"), ("hiba", "investigator")],  # The admin assigns the case after intake
    },
    # ------------------------------------------------ CASE-008: THE BLACK LEDGER
    {
        "case_number": "CASE-008", "title": "The Black Ledger", "category": "Criminal Conspiracy",
        "status": "Open", "incident_date": None,
        "location": "Old Port District, Karachi",
        "created_at": "2026-11-07 12:10:00",
        "description": (
            "A sealed ledger bearing a black chess-knight emblem appears after a port firm's "
            "records disappear. Anonymous claims name two people of interest, Rehman Dakait and Pablo, "
            "but investigators cannot yet verify their involvement. Abdul Wahid and Ali Ahmed are "
            "potential witnesses to unusual meetings and records transfers. The suspected conspiracy "
            "and the source of the ledger remain unresolved. All allegations are unverified and under review."
        ),
        "summary": (
            "Open organized-crime conspiracy involving a missing ledger, conflicting accounts "
            "and two persons of interest. Evidence is preliminary; no culprit has been identified."
        ),
        "team": [("hiba", "lead"), ("maryam", "investigator")],  # FIXED typo "investiagtor" (crashed the seed)
    },
]

SUSPECTS = {
    "CASE-001": [
        {"key": "wahid", "name": "Abdul Wahid", "relationship": "Head librarian; colleague of the victim",
         "background": "Head librarian for 14 years. Responsible for the manuscript loan ledger.",
         "motive": "Staff report a heated argument with the victim about the missing loan ledger on 13 March.",
         "alibi": "States he left the library at about 20:00 and was at home all evening; his wife confirms.",
         "statements": "\"I left before eight. I did not come back that night. Anyone could have used my card.\"",
         "notes": "Card C-1001 is registered to him.", "photo_path": "assets/suspects/wahid.jpg" },

        {"key": "daniyal", "name": "Muhammad Daniyal", "relationship": "Research assistant to the victim",
         "background": "PhD candidate working on the victim's manuscript catalogue since 2024.",
         "motive": "The victim had raised concerns about copied passages in his draft chapter.",
         "alibi": "States he was at Riverside Café from 20:30 until about 22:15, then took a rickshaw home.",
         "statements": "\"Professor Rafiq and I disagreed about my chapter, but we had sorted it out.\"",
         "notes": "", "photo_path": "assets/suspects/daniyal.jpg" },

        {"key": "hasnain", "name": "Syed Hasnain", "relationship": "Rare-book dealer",
         "background": "Runs a private antiquarian book business; previously sold items to the library.",
         "motive": "The victim refused to authenticate a manuscript the dealer was trying to sell.",
         "alibi": "States he was at a dinner meeting until midnight. The other diner has not yet been identified.",
         "statements": "\"I wanted his signature on a certificate, nothing more.\"",
         "notes": "Sent an email to the victim on 12 March (see evidence).",
         # the image file in static/assets/suspects/ is spelled "hasnian.jpg"
         "photo_path": "assets/suspects/hasnian.jpg" },
    ],
    "CASE-002": [
        {"key": "mahzaib", "name": "Mahzaib", "relationship": "Classmate",
         "background": "Didn't talk much, just made Aira work as a GR",
         "motive": "Friends describe repeated messages after she refused to do her work.",
         "alibi": "States she was at her cousin's wedding event from 18:00 to 23:30.",
         "statements": "\"I have not spoken to her since the 20th of April.\"", "notes": "",
         "photo_path": "assets/suspects/mahzaib.jpg" },

        {"key": "ruba", "name": "Ruba Mazhar", "relationship": "Close friend, Roommate & Classmate",
         "background": "Roommate of Aira.",
         "motive": "Dispute over an unpaid share of room rent.",
         "alibi": "States she left the hostel at 18:30, before Aira.",
         "statements": "\"She was fine when I left. She said she will leave for University in a bit.\"", "notes": "",
         # ADD PHOTO: ruba.jpg is not in static/assets/suspects/ yet - put it there (initials show until then)
         "photo_path": "assets/suspects/ruba.jpg" },
    ],
    "CASE-003": [
        {"key": "ali", "name": "Ali Ahmed", "relationship": "Former IT contractor for the bank",
         "background": "Contract for the online banking upgrade ended on 31 May 2026.",
         "motive": "Contract was ended early; payment dispute recorded with HR.",
         "alibi": "States he was at home and offline on the night of 18 June.",
         "statements": "\"My access was removed when my contract ended.\"", "notes": "",
         "photo_path": "assets/suspects/ali.jpg" },

        {"key": "tayyab", "name": "Muhammad Tayyab", "relationship": "Branch teller",
         "background": "Teller at the main branch for three years.",
         "motive": "None recorded. His workstation ID appears in the server log.",
         "alibi": "Off duty from 17:00 on 18 June; branch closed overnight.",
         "statements": "\"I logged out at five. I never share my password.\"", "notes": "",
         "photo_path": "assets/suspects/tayyab.jpg" },

        {"key": "shadow", "name": "Unknown user 'shadowteller'", "relationship": "Online alias",
         "background": "Alias advertising 'bank login kits' on an underground forum.",
         "motive": "Unknown.", "alibi": "Not applicable - identity unknown.", "statements": "", "notes": "",
         "photo_path": "assets/suspects/unidentified.jpg" },   # silhouette placeholder (new file)
    ],
    "CASE-004": [
        {
            "key": "pinky",
            "name": "Anmol Pinky",
            "relationship": "Linked to a suspicious bag exchange near Warehouse 03.",
            "background": "Nightlife event coordinator at Neon Wharf Lounge.",
            "motive": "Possible financial gain from narcotics distribution.",
            "alibi": "Claims she was arranging event equipment at the lounge.",
            "statements": "Denies involvement; says the bag contained audio equipment.",
            "notes": "CCTV places her near the warehouse. Bag contents unverified.",
            "photo_path": "assets/suspects/pinky.jpg"
        },
        {
            "key": "walter",
            "name": "Walter White",
            "relationship": "Seen near a restricted warehouse storage area.",
            "background": "Former chemistry teacher and industrial consultant.",
            "motive": "Possible financial gain from illegal operations.",
            "alibi": "Claims he attended a scheduled technical consultation.",
            "statements": "Denies involvement; says his case held measuring equipment.",
            "notes": "Late-night visit and connection to Pinky remain unverified.",
            "photo_path": "assets/suspects/walter.jpg"
        }
    ],
    # ------------------------------------------------ CASE-005 (real event: no individual is named as a suspect)
    "CASE-005": [
        {"key": "c5_group", "name": "TraderTraitor (attributed group)",
         "relationship": "Threat actor attributed by blockchain-analytics firms TRM Labs and Chainalysis.",
         "background": "North Korea-linked hacking group reported as part of the Lazarus umbrella; the FBI named the same group "
                       "for the February 2025 Bybit hack (USD 1.5B).",
         "motive": "Financial theft, consistent with previously attributed incidents.",
         "alibi": "Not applicable - individual operators unknown.",
         "statements": "No claim of responsibility.",
         "notes": "Attribution is by analytics firms (high confidence), not a law-enforcement finding.",
         "photo_path": "assets/suspects/unidentified.jpg"},
        {"key": "c5_wallet", "name": "Operator wallet (identity unknown)",
         "relationship": "Blockchain wallet that prepared and launched the attack.",
         "background": "Funded on 28 Oct 2026 with three small Tornado Cash withdrawals; tested attack code on test wallets; "
                       "submitted 50 pre-signed EIP-7702 authorizations at 20:20 UTC on 29 Oct.",
         "motive": "Not determinable from the wallet alone.",
         "alibi": "Not applicable.", "statements": "None.",
         "notes": "TRM Labs links this activity to TraderTraitor.",
         "photo_path": "assets/suspects/unidentified.jpg"},
    ],
    # ------------------------------------------------ CASE-006
    "CASE-006": [
        
{"key": "redjohn",
 "name": "Red John",
 "relationship": "Primary suspect in the serial-homicide investigation; responsible for the murders of the Administrator's wife and daughter in the adapted case.",
 "background": "An unidentified serial killer known for leaving a red smiley-face signature at crime scenes. Connected to numerous murders and psychological manipulation of investigators.",
 "motive": "Possible retaliation against the Administrator, psychological control, and a desire to demonstrate superiority over investigators. Full motive remains under investigation.",
 "alibi": "Unknown. True identity has not been established.",
 "statements": "No formal interview. Anonymous communications attributed to Red John are under examination.",
 "notes": "PRIMARY SUSPECT. His actual identity is Thomas McAllister in The Mentalist, but this information must remain classified and hidden from the detectives until the final case reveal.",
 "photo_path": "assets/suspects/redjohn.jpg"},

{"key": "gale",
 "name": "Gale Bertram",
 "relationship": "Director of the California Bureau of Investigation (CBI); potential connection to Red John through the Blake Association.",
 "background": "Senior law-enforcement official with access to confidential investigations. His involvement with the secret Blake Association raises serious concerns about corruption and information leaks.",
 "motive": "Possible involvement in protecting Red John's identity, concealing confidential information, or supporting the Blake Association.",
 "alibi": "Requires verification against the timeline of the murders.",
 "statements": "Denies involvement in the Red John murders. Statements require comparison with available evidence.",
 "notes": "HIGH-PRIORITY SUSPECT. Investigate possible Blake Association involvement, confidential case access, and connections to Red John. Association membership alone does not establish responsibility for the murders.",
 "photo_path": "assets/suspects/gale.jpg"},

{"key": "bret",
 "name": "Bret Stiles",
 "relationship": "Leader of the Visualize organization; possible historical connection to Red John.",
 "background": "Influential leader of the Visualize organization. Appears to possess information about Red John's past and has connections to individuals associated with the investigation.",
 "motive": "Unknown. Possible desire to protect organizational secrets or conceal information concerning Red John's background.",
 "alibi": "Requires verification for the relevant incidents.",
 "statements": "Claims to possess knowledge concerning Red John but does not provide a complete explanation of his connection to the killer.",
 "notes": "PERSON OF INTEREST. Investigate Visualize records, historical connections to Red John, and his knowledge of the offender. No confirmed evidence establishes that Bret Stiles is Red John.",
 "photo_path": "assets/suspects/bret.jpg"},

    ],
    # ------------------------------------------------ CASE-007
    "CASE-007": [
        {"key": "c7_uswa", "name": "Uswa", "relationship": "Named participant in missing-belongings incident.",
         "background": "Student; maroon outfit in supplied classroom video.",
         "motive": "Not established from source footage.",
         "alibi": "No authenticated alibi supplied.",
         "statements": "No verified interrogation; working theory assigns joint responsibility.",
         "notes": "Portrait and video identification supplied by user; not independent proof.",
         "photo_path": "assets/suspects/uswa.jpeg"},
        {"key": "c7_fatima", "name": "Fatima", "relationship": "Named participant in missing-belongings incident.",
         "background": "Student; lighter outfit and green headscarf in video.",
         "motive": "Not established from source footage.",
         "alibi": "No authenticated alibi supplied.",
         "statements": "No verified interrogation; working theory assigns joint responsibility.",
         "notes": "Portrait and video identification supplied by user; not independent proof.",
         "photo_path": "assets/suspects/fatima.jpeg"},
    ],
    # ------------------------------------------------ CASE-008
    "CASE-008": [
        {"key": "c8_rehman", "name": "Rehman Dakait", "relationship": "Individual named in an anonymous conspiracy allegation.",
         "background": "Reputed underworld figure, widely known by his alias.",
         "motive": "Possible influence over disputed port records; unverified.",
         "alibi": "Not yet interviewed.", "statements": "No authenticated statement.",
         "notes": "Treat the allegation as unconfirmed; verify claims independently.", 
         "photo_path": "assets/suspects/rehman.jpg" },

        {"key": "c8_pablo", "name": "Pablo", "relationship": "Contact named alongside Rehman in an anonymous tip.",
         "background": "Mysterious business intermediary; identity details pending.",
         "motive": "Unknown possible interest in missing company ledger.",
         "alibi": "Not yet interviewed.", "statements": "No authenticated statement.",
         "notes": "No confirmed association with any offence.", 
         "photo_path": "assets/suspects/pablo.jpg" },

    ],
}

# ------------------------------------------------------------ evidence files
# Every file below must be in   static/assets/case-images/   (videos: static/assets/demo-videos/).
# Comment format on each entry:   TYPE  - what the file is.
# To swap in your own file, keep the same file name (or change the name here as well).

def _evidence_specs():
    """(case, key, filename, bytes, description, uploader, uploaded_at)."""
    return [
        # ------------------------------------------------ CASE-001: The Riverside Library Death
        # IMAGE (jpg)  - scene photo with numbered evidence markers
        ("CASE-001", "scene", "c1_scene_rare_books_room.jpg", _case_file("c1_scene_rare_books_room.jpg"),
         "Rare Books Room after discovery: (1) body position, (2) overturned chair, (3) empty shelf slot where the loan "
         "ledger was kept, (4) dust outline of a missing brass bookend.", "warisha", "2026-03-14 09:05:00"),
        # CSV LOG      - door access-card export (imports into the timeline through the analysis queue)
        ("CASE-001", "access", "c1_library_access_log.csv", _case_file("c1_library_access_log.csv"),
         "Door access-card export for 13-14 March. Card C-1001 (Abdul Wahid) is used at the side entrance at 22:47, "
         "three hours after he says he went home.", "hiba", "2026-03-14 12:30:00"),
        # PDF          - forensic pathology report
        ("CASE-001", "autopsy", "c1_pathology_summary.pdf", _case_file("c1_pathology_summary.pdf"),
         "Preliminary pathology summary: single blow consistent with the base of the missing brass bookend; "
         "time of death 21:30-23:30.", "warisha", "2026-03-15 16:45:00"),
        # TEXT (txt)   - interview transcript
        ("CASE-001", "transcript", "c1_guard_interview_transcript.txt", _case_file("c1_guard_interview_transcript.txt"),
         "Interview with night guard Ghufran Siddique: raised voices at 22:55 ('that ledger is not yours to sell').",
         "warisha", "2026-03-14 10:30:00"),
        # TEXT (txt)   - email printout
        ("CASE-001", "email", "c1_dealer_email.txt", _case_file("c1_dealer_email.txt"),
         "Email from Syed Hasnain to the victim, 12 March: 'Ledgers can be lost.'", "hiba", "2026-03-16 11:10:00"),
        # IMAGE (jpg)  - CCTV still
        ("CASE-001", "c1_cctv", "c1_side_entrance_cctv.jpg", _case_file("c1_side_entrance_cctv.jpg"),
         "Side-entrance camera CAM-05 at 22:46:58: capped figure with a long flat parcel at the card reader; "
         "face not visible.", "hiba", "2026-03-15 10:20:00"),
        # CSV LOG      - taxi company dispatch records
        ("CASE-001", "c1_taxi", "c1_taxi_dispatch_log.csv", _case_file("c1_taxi_dispatch_log.csv"),
         "Taxi dispatch log: trip from Hasnain Antiques to the library side gate (22:40) and back (23:29), "
         "booked from a number ending 4471.", "hiba", "2026-03-17 12:00:00"),
        # IMAGE (png)  - chat screenshot (deleted chat recovered by forensic tool)
        ("CASE-001", "c1_chat", "c1_wahid_hasnain_chat.png", _case_file("c1_wahid_hasnain_chat.png"),
         "Deleted chat recovered from Abdul Wahid's phone: card C-1001 left under the side-door mat for S. Hasnain; "
         "'Done' at 23:31.", "warisha", "2026-03-18 15:40:00"),
        # IMAGE (png)  - till receipt
        ("CASE-001", "c1_receipt", "c1_cafe_receipt.png", _case_file("c1_cafe_receipt.png"),
         "Riverside Cafe receipt, 13 March 21:58, table 6 - checks Muhammad Daniyal's alibi.", "hiba", "2026-03-15 14:30:00"),

        # ------------------------------------------------ CASE-002: Disappearance of Aira Shakir
        # TEXT (txt)   - missing person report
        ("CASE-002", "report", "c2_missing_person_report.txt", _case_file("c2_missing_person_report.txt"),
         "Missing person report filed by sister Hira Shakir.", "maryam", "2026-05-03 10:25:00"),
        # CSV LOG      - phone call detail records
        ("CASE-002", "calls", "c2_aira_call_records.csv", _case_file("c2_aira_call_records.csv"),
         "Call detail records for Aira Shakir's phone, 2 May 2026: SMS and call with an unknown number before she vanished.",
         "maryam", "2026-05-04 13:20:00"),
        # IMAGE (png)  - photographed hostel register
        ("CASE-002", "c2_register", "c2_hostel_gate_register.png", _case_file("c2_hostel_gate_register.png"),
         "Hostel gate register, 2 May: Ruba Mazhar signed out at 19:05 (she claims 18:30) and back at 02:40.",
         "amna", "2026-05-03 16:00:00"),
        # IMAGE (png)  - chat screenshot
        ("CASE-002", "c2_chat", "c2_mahzaib_messages.png", _case_file("c2_mahzaib_messages.png"),
         "Messages from Mahzaib to Aira, 1 May: threat to reveal 'your secret' unless Aira does the assignment.",
         "amna", "2026-05-05 11:00:00"),
        # TEXT (txt)   - mobile operator reply to a legal request
        ("CASE-002", "c2_telco", "c2_telco_subscriber_reply.txt", _case_file("c2_telco_subscriber_reply.txt"),
         "Operator reply: the unknown number +92 321-***-0777 is Ruba Mazhar's second SIM; it travelled towards Hyderabad.",
         "maryam", "2026-05-06 17:30:00"),
        # IMAGE (jpg)  - CCTV still
        ("CASE-002", "c2_cctv", "c2_bus_terminal_cctv.jpg", _case_file("c2_bus_terminal_cctv.jpg"),
         "Central Bus Terminal camera CAM-07 at 20:06: two young women walk to the Hyderabad coach bay.",
         "amna", "2026-05-07 12:10:00"),
        # CSV LOG      - coach ticket sales
        ("CASE-002", "c2_tickets", "c2_coach_ticket_record.csv", _case_file("c2_coach_ticket_record.csv"),
         "Coach ticket sales: two Karachi-Hyderabad tickets paid with Ruba Mazhar's card; Ruba returns alone at 00:55.",
         "maryam", "2026-05-07 15:45:00"),

        # ------------------------------------------------ CASE-003: Crescent Bank Phishing Breach
        # CSV LOG      - server authentication log
        ("CASE-003", "authlog", "c3_server_auth_log.csv", _case_file("c3_server_auth_log.csv"),
         "Online-banking server log: svc.upgrade admin login, redirect rule, and a remote-desktop session on teller "
         "workstation BR-TELLER-04 at 01:02.", "amna", "2026-06-19 10:15:00"),
        # TEXT (txt)   - phishing email
        ("CASE-003", "phish", "c3_phishing_email.txt", _case_file("c3_phishing_email.txt"),
         "Phishing email forwarded by customer Rabia Siddiqui.", "amna", "2026-06-19 10:40:00"),
        # IMAGE (png)  - screenshot of the cloned website
        ("CASE-003", "screenshot", "c3_cloned_login_page.png", _case_file("c3_cloned_login_page.png"),
         "Screenshot of the cloned login page at crescentbank-verify.example.", "amna", "2026-06-19 11:05:00"),
        # IMAGE (png)  - forum post screenshot
        ("CASE-003", "c3_forum", "c3_forum_post_shadowteller.png", _case_file("c3_forum_post_shadowteller.png"),
         "Underground forum post by 'shadowteller' selling the Crescent kit: 'they forgot to kill it when my contract ended'.",
         "maryam", "2026-06-21 16:20:00"),
        # TEXT (txt)   - domain registration (WHOIS) record
        ("CASE-003", "c3_whois", "c3_domain_whois.txt", _case_file("c3_domain_whois.txt"),
         "WHOIS record: phishing domain registered 9 June, paid with debit card ending 8823, hosted on 203.0.113.45.",
         "maryam", "2026-06-21 18:05:00"),
        # PDF          - bank statement + IT ticket
        ("CASE-003", "c3_bank", "c3_bank_statement_and_iam_ticket.pdf", _case_file("c3_bank_statement_and_iam_ticket.pdf"),
         "Ali Ahmed's bank statement (card 8823 paid for the domain and VPS; mule money received) and IT ticket IAM-412.",
         "amna", "2026-06-22 14:00:00"),

        # ------------------------------------------------ CASE-004: The Indigo Veil
        # TEXT (txt)   - incident report
        ("CASE-004", "inventory", "c4_warehouse_incident_report.txt", _case_file("c4_warehouse_incident_report.txt"),
         "Initial incident report: indigo-crescent packets, handwritten ledger and a phone recovered at Warehouse 03.",
         "hiba", "2026-03-14 10:30:00"),
        # IMAGE (jpg)  - CCTV still
        ("CASE-004", "c4_cctv", "c4_warehouse_gate_cctv.jpg", _case_file("c4_warehouse_gate_cctv.jpg"),
         "Warehouse 03 rear-gate camera CAM-3 at 01:14: two duffel bags exchanged.", "hiba", "2026-03-14 11:15:00"),
        # PDF          - forensic lab report
        ("CASE-004", "c4_lab", "c4_lab_analysis_report.pdf", _case_file("c4_lab_analysis_report.pdf"),
         "Lab report: 96% pure blue-tinted methamphetamine; hospital packet from the same batch; one fingerprint "
         "matched to Anmol Pinky.", "warisha", "2026-03-16 17:00:00"),
        # IMAGE (png)  - chat screenshot from the recovered phone
        ("CASE-004", "c4_chat", "c4_burner_phone_chat.png", _case_file("c4_burner_phone_chat.png"),
         "Chat on the phone found at Warehouse 03 between 'P.' and 'Teacher': '2 kilos. Blue.' / 'Audio gear on top'.",
         "warisha", "2026-03-15 19:30:00"),
        # IMAGE (png)  - photographed handwritten ledger
        ("CASE-004", "c4_ledger", "c4_handwritten_ledger.png", _case_file("c4_handwritten_ledger.png"),
         "Handwritten ledger page: deliveries 'WW -> AP', 'purity 96', next drop 19/3.", "hiba", "2026-03-14 12:00:00"),
        # TEXT (txt)   - hospital emergency record
        ("CASE-004", "c4_er", "c4_hospital_er_record.txt", _case_file("c4_hospital_er_record.txt"),
         "Hospital emergency record: overdose patient from the Neon Wharf Lounge after-party with an indigo-crescent packet.",
         "warisha", "2026-03-14 09:30:00"),
        # CSV LOG      - vehicle GPS tracker export
        ("CASE-004", "c4_gps", "c4_lounge_van_gps.csv", _case_file("c4_lounge_van_gps.csv"),
         "GPS of the Neon Wharf Lounge van: at Warehouse 03 from 01:09 to 01:27, contradicting Pinky's alibi.",
         "hiba", "2026-03-17 13:10:00"),

        # ------------------------------------------------ CASE-005: Binance Wallet Theft (public reporting)
        # CSV LOG      - blockchain outflows
        ("CASE-005", "c5_outflows", "c5_binance_outflows.csv", _case_file("c5_binance_outflows.csv"),
         "Outflows from Binance hot wallets, 28-29 Oct 2026 (UTC), from TRM Labs' analysis. Wallet names are masked for confidentiality.",
         "maryam", "2026-10-30 09:00:00"),
        # CSV LOG      - freezes and response actions
        ("CASE-005", "c5_freezes", "c5_freezes_response_log.csv", _case_file("c5_freezes_response_log.csv"),
         "Freezes by Tether, Circle, Ripple, World Liberty Financial and the Arbitrum Security Council.",
         "maryam", "2026-10-30 09:10:00"),
        # CSV LOG      - laundering activity
        ("CASE-005", "c5_laundering", "c5_laundering_activity.csv", _case_file("c5_laundering_activity.csv"),
         "Laundering steps: stablecoin swaps to ETH, Aave and JustLend borrowing, Bitcoin peel chain.",
         "warisha", "2026-10-30 09:20:00"),
        # TEXT (txt)   - analyst note
        ("CASE-005", "c5_technique", "c5_eip7702_attack_technique.txt", _case_file("c5_eip7702_attack_technique.txt"),
         "Analyst note: how 50 pre-signed EIP-7702 authorizations emptied the Ethereum hot wallet.",
         "warisha", "2026-10-30 10:00:00"),
        # TEXT (txt)   - public statements with sources
        ("CASE-005", "c5_statements", "c5_public_statements.txt", _case_file("c5_public_statements.txt"),
         "Exact public statements by Binance and analysts at TRM Labs, Chainalysis and Elliptic, with sources.",
         "maryam", "2026-10-31 11:00:00"),
        # PDF          - incident brief
        ("CASE-005", "c5_brief", "c5_incident_brief.pdf", _case_file("c5_incident_brief.pdf"),
         "Two-page incident brief compiled from public reporting.", "maryam", "2026-10-31 12:00:00"),
        # IMAGE (png)  - analyst diagrams
        ("CASE-005", "c5_chain", "c5_attack_chain_diagram.png", _case_file("c5_attack_chain_diagram.png"),
         "Analyst diagram: attack chain from preparation to laundering.", "warisha", "2026-10-31 12:10:00"),
        ("CASE-005", "c5_timeline_chart", "c5_incident_timeline.png", _case_file("c5_incident_timeline.png"),
         "Analyst chart: incident timeline, 29-30 Oct 2026 UTC.", "warisha", "2026-10-31 12:15:00"),
        ("CASE-005", "c5_frozen", "c5_stolen_vs_frozen.png", _case_file("c5_stolen_vs_frozen.png"),
         "Analyst chart: stolen vs frozen as of 30 Oct 00:30 UTC.", "warisha", "2026-10-31 12:20:00"),

        # ------------------------------------------------ CASE-006: The Mentalist (Red John)
        # PDF          - signature comparison across scenes
        ("CASE-006", "c6_smiley", "c6_signature_comparison.pdf", _case_file("c6_signature_comparison.pdf"),
         "Red smiley-face signature compared across four scenes: same stroke order and height; never released to the press.",
         "hiba", "2026-04-22 10:00:00"),
        # IMAGE (jpg)  - scene photo of the wall marking
        ("CASE-006", "c6_smiley_photo", "c6_red_smiley_scene.jpg", _case_file("c6_red_smiley_scene.jpg"),
         "Scene 4 wall marking: red smiley face, height 1.62 m; pigment sample R-4 sent to lab.", "hiba", "2026-03-18 09:00:00"),
        # IMAGE (png)  - photographed handwritten note
        ("CASE-006", "c6_note", "c6_handwritten_note.png", _case_file("c6_handwritten_note.png"),
         "Handwritten note found at scene 3 quoting William Blake's 'The Tyger'; handwriting comparison pending.",
         "hiba", "2026-03-18 09:10:00"),
        # PDF          - forensic exhibit register
        ("CASE-006", "c6_trace", "c6_physical_trace_register.pdf", _case_file("c6_physical_trace_register.pdf"),
         "Physical trace register: tweed fibre at scenes 2 and 4, short grey hair, size-43 shoe print.",
         "hiba", "2026-04-20 10:10:00"),
        # IMAGE (jpg)  - CCTV stills
        ("CASE-006", "c6_cam1", "c6_cctv_first_location.jpg", _case_file("c6_cctv_first_location.jpg"),
         "Alley camera behind the first scene, 23:12: unidentified person, hood up, walking away.", "hiba", "2026-04-20 10:20:00"),
        ("CASE-006", "c6_cam2", "c6_cctv_vehicle.jpg", _case_file("c6_cctv_vehicle.jpg"),
         "Service-road camera, 00:47: headlights of a dark sedan; plate only partly visible.", "hiba", "2026-04-20 10:25:00"),
        # TEXT (txt)   - anonymous email
        ("CASE-006", "c6_mail", "c6_anonymous_email.txt", _case_file("c6_anonymous_email.txt"),
         "Anonymous email to the Administrator: 'Tyger Tyger... Your family sends their regards.'", "maryam", "2026-04-20 10:30:00"),
        # IMAGE (png)  - SMS screenshot
        ("CASE-006", "c6_sms", "c6_investigation_unit_message.png", _case_file("c6_investigation_unit_message.png"),
         "SMS to the Investigation Unit naming all four detectives: 'Look at hands.'", "maryam", "2026-05-19 11:00:00"),
        # PDF          - restricted membership list
        ("CASE-006", "c6_blake", "c6_blake_association_list.pdf", _case_file("c6_blake_association_list.pdf"),
         "Blake Association partial membership list: Gale Bertram listed as a sponsor; one torn entry with initials 'T. M.'",
         "warisha", "2026-10-01 09:00:00"),
        # TEXT (txt)   - organisation record
        ("CASE-006", "c6_visualize", "c6_visualize_records.txt", _case_file("c6_visualize_records.txt"),
         "Visualize intake card (1994) interviewed by Bret Stiles: member 'T.M.' with three dots tattooed on the left hand.",
         "amna", "2026-10-14 16:00:00"),
        # TEXT (txt)   - restricted lead
        ("CASE-006", "c6_secret", "c6_restricted_complaint.txt", _case_file("c6_restricted_complaint.txt"),
         "Restricted lead: the Administrator mocked 'Red John' on television weeks before the family murders.",
         "warisha", "2026-11-01 10:00:00"),

        # ------------------------------------------------ CASE-007: The DUET Campus Theft
        # VIDEO (mp4)  - lives in static/assets/demo-videos/ (not case-images)
        ("CASE-007", "c7_video", "case7cctv.mp4", _video_file("case7cctv.mp4"),
         "Original user-supplied classroom video (18 s); the on-screen clock is part of the original recording.",
         "admin", "2026-11-07 12:05:00"),
        # IMAGE (jpg)  - 7 frames extracted from the video (time = position in the video)
        ("CASE-007", "c7_frame1", "c7_frame_01.jpg", _case_file("c7_frame_01.jpg"),
         "Frame at 0:01.3 - a person enters the classroom from the right.", "amna", "2026-11-07 12:06:00"),
        ("CASE-007", "c7_frame2", "c7_frame_02.jpg", _case_file("c7_frame_02.jpg"),
         "Frame at 0:03.9 - two people at the window-row chairs, bending over the bags.", "amna", "2026-11-07 12:06:10"),
        ("CASE-007", "c7_frame3", "c7_frame_03.jpg", _case_file("c7_frame_03.jpg"),
         "Frame at 0:06.5 - both handle items on the chairs.", "amna", "2026-11-07 12:06:20"),
        ("CASE-007", "c7_frame4", "c7_frame_04.jpg", _case_file("c7_frame_04.jpg"),
         "Frame at 0:09.1 - one person bends over a bag on a chair.", "amna", "2026-11-07 12:06:30"),
        ("CASE-007", "c7_frame5", "c7_frame_05.jpg", _case_file("c7_frame_05.jpg"),
         "Frame at 0:11.7 - one person moves towards the back row.", "amna", "2026-11-07 12:06:40"),
        ("CASE-007", "c7_frame6", "c7_frame_06.jpg", _case_file("c7_frame_06.jpg"),
         "Frame at 0:14.3 - one person walks towards the exit at the back.", "amna", "2026-11-07 12:06:50"),
        ("CASE-007", "c7_frame7", "c7_frame_07.jpg", _case_file("c7_frame_07.jpg"),
         "Frame at 0:16.9 - the classroom is empty.", "amna", "2026-11-07 12:07:00"),
        # TEXT (txt)   - missing property report
        ("CASE-007", "c7_report", "c7_missing_property_report.txt", _case_file("c7_missing_property_report.txt"),
         "Missing property report: phone, pencil pouch and power bank taken from the window-row chairs.",
         "admin", "2026-11-07 12:15:00"),
        # IMAGE (png)  - chat screenshot recovered from the handset
        ("CASE-007", "c7_chat", "c7_simulated_messages.png", _case_file("c7_simulated_messages.png"),
         "Chat recovered from the handset: 'We give it back after class... just a prank.'",
         "admin", "2026-11-07 12:20:00"),

        # ------------------------------------------------ CASE-008: The Black Ledger
        # IMAGE (png)  - photographed ledger page
        ("CASE-008", "c8_ledger", "c8_black_ledger_page.png", _case_file("c8_black_ledger_page.png"),
         "Anonymous copy of ledger VII page 112 with the black chess-knight emblem; entries for 'R.D.', 'P.' and container MSKU-48213.",
         "admin", "2026-11-07 12:20:00"),
        # TEXT (txt)   - call transcript
        ("CASE-008", "c8_tip", "c8_anonymous_tip_transcript.txt", _case_file("c8_anonymous_tip_transcript.txt"),
         "Anonymous tip: 'Ask Rehman. Ask Pablo... Container MSKU-48213 isn't machinery. Check the weight.'",
         "admin", "2026-11-07 12:25:00"),
        # IMAGE (jpg)  - CCTV still
        ("CASE-008", "c8_cam", "c8_port_gate_cctv.jpg", _case_file("c8_port_gate_cctv.jpg"),
         "Port camera 14, berth 6, 22:58 on 4 Nov - 48 minutes after visitor V-117 left the records room.",
         "admin", "2026-11-07 12:30:00"),
        # CSV LOG      - shipping manifest with weighbridge weights
        ("CASE-008", "c8_manifest", "c8_shipping_manifest.csv", _case_file("c8_shipping_manifest.csv"),
         "Shipping manifest: container MSKU-48213 is 4,200 kg heavier than declared; released by records-office override.",
         "hiba", "2026-11-07 13:00:00"),
        # CSV LOG      - records-room badge log
        ("CASE-008", "c8_access", "c8_records_room_access.csv", _case_file("c8_records_room_access.csv"),
         "Records-room badge log, 4 Nov: visitor badge V-117 ('P. Rodrigues') in at 21:52, out at 22:10; clerk's override at 23:10.",
         "hiba", "2026-11-07 13:10:00"),
        # PDF          - company registry extract
        ("CASE-008", "c8_registry", "c8_company_registry_extract.pdf", _case_file("c8_company_registry_extract.pdf"),
         "Company registry: Knight Holdings (chess-knight logo), director 'P. Rodrigues', hidden owner via a Gulf trust.",
         "maryam", "2026-11-07 13:30:00"),
    ]


def seed_database():
    """Create the schema and load the case data. Call inside an app context."""
    from routes.evidence import store_evidence_file   # imported here to avoid a circular import

    db = get_db()
    create_schema(db)
    config = current_app.config
    stamp = now_str()

    # ---- users: administrator and detectives with relative image paths for static assets
    users = {}
    cursor = db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, badge_id, specialization, profile_image, created_at) "
        "VALUES (?, ?, ?, 'admin', 'ADM-001', 'System administration', 'assets/detectives/admin.png', ?)",
        (config["ADMIN_USERNAME"].lower(), generate_password_hash(config["ADMIN_PASSWORD"]),
         "TRACE X Administrator", stamp))
    users["admin"] = {"id": cursor.lastrowid, "role": "admin"}

    for username, full_name, badge, specialization, profile_image in DETECTIVES:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, full_name, role, badge_id, specialization, profile_image, created_at) "
            "VALUES (?, ?, ?, 'detective', ?, ?, ?, ?)",
            (username, generate_password_hash(config["DETECTIVE_PASSWORD"]), full_name, badge, specialization, profile_image, stamp))
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
            photo_path = _static_photo(s.get("photo_path"))      # missing photo -> initials, not a broken image
            cursor = db.execute(
                "INSERT INTO suspects (case_id, name, photo_path, background, relationship, motive, alibi, statements, notes, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cases[case_number]["id"], s["name"], photo_path, s["background"], s["relationship"], s["motive"], s["alibi"],
                 s["statements"], s["notes"], stamp, stamp))
            suspects[s["key"]] = cursor.lastrowid
    db.commit()

    # ---- evidence: real files, really hashed, stored read-only
    evidence = {}
    registered_files = set()
    for case_number, key, filename, data, description, uploader, uploaded_at in _evidence_specs():
        if data is None:                                # file missing: skip this item, keep seeding the rest
            continue
        user = {"id": users[uploader]["id"]}
        evidence[key] = store_evidence_file(cases[case_number], io.BytesIO(data), filename, user,
                                            description=description, uploaded_at=uploaded_at)
        registered_files.add(filename)

    # Extra CCTV videos in static/assets/demo-videos/ that are NOT already listed in
    # _evidence_specs() are registered in CASE-001 (case7cctv.mp4 is skipped: it belongs to CASE-007).
    video_dir = config["DEMO_VIDEO_DIR"]
    if os.path.isdir(video_dir):
        videos = sorted(f for f in os.listdir(video_dir)
                        if f.lower().rsplit(".", 1)[-1] in ("mp4", "webm", "ogv", "mov", "m4v")
                        and f not in registered_files)
        for number, name in enumerate(videos, start=1):
            with open(os.path.join(video_dir, name), "rb") as handle:
                evidence[f"video{number}"] = store_evidence_file(
                    cases["CASE-001"], handle, name, {"id": users["amna"]["id"]},
                    description="CCTV footage supplied by the premises security office.",
                    camera_id=f"CAM-{number:02d}")

    # ---- witnesses
    witness_rows = [
        # (case, name, role/contact, statement, recorded_at, recorded_by, related suspect key, related evidence key)
        # ------------------------------------------------ CASE-001
        ("CASE-001", "Ghufran Siddique", "Night guard, Old Riverside Library",
         "Heard two raised male voices from the second floor at about 22:55; one shouted 'that ledger is not yours to "
         "sell'. Heard the side door bang at about 23:20. Found the professor at 07:10 when he opened the door.",
         "2026-03-14 09:40:00", "warisha", None, "transcript"),
        ("CASE-001", "Rubina Saleem", "Owner, Riverside Cafe",
         "Muhammad Daniyal sat at table 6 from about 20:30 and paid and left at 21:58, not 22:15. He looked upset and "
         "kept checking his phone.",
         "2026-03-15 14:10:00", "hiba", "daniyal", "c1_receipt"),
        ("CASE-001", "Aslam Javed", "Taxi driver",
         "Picked up a man in a cap outside Hasnain Antiques, Saddar at 22:21 and dropped him at the library's side gate "
         "at 22:40. He carried a long flat parcel wrapped in cloth and paid in cash.",
         "2026-03-16 17:25:00", "hiba", "hasnain", "c1_taxi"),

        # ------------------------------------------------ CASE-002
        ("CASE-002", "Hira Shakir", "Sister of the missing person",
         "Aira called at 19:40 whispering that she was fine and would explain later; it sounded like a bus stand. For two "
         "weeks she had said she was scared of someone in her class.",
         "2026-05-03 09:20:00", "maryam", "mahzaib", "calls"),
        ("CASE-002", "Shahid Mehmood", "Conductor, Karachi-Hyderabad coach",
         "Two young women boarded the 20:10 coach to Hyderabad: one with a black backpack with a white patch, one in a grey "
         "hoodie. The one in the hoodie did all the talking and showed both tickets.",
         "2026-05-05 12:00:00", "amna", "ruba", "c2_cctv"),
        ("CASE-002", "Shamim Bibi", "Gate guard, girls' hostel",
         "Aira signed out at 18:45 'for university'. Ruba went out at 19:05, not 18:30, and came back alone at 02:40 "
         "saying her bus from Hyderabad was late.",
         "2026-05-04 11:30:00", "amna", "ruba", "c2_register"),

        # ------------------------------------------------ CASE-003
        ("CASE-003", "Usman Ghani", "Security analyst, Crescent Bank",
         "Noticed 30+ customer logins from 203.0.113.x after midnight and revoked all sessions at 02:40. Found a redirect "
         "rule added at 23:44 by svc.upgrade - an account that should have been disabled when Ali Ahmed's contract ended.",
         "2026-06-19 09:30:00", "amna", "ali", "authlog"),
        ("CASE-003", "Rabia Siddiqui", "Bank customer",
         "Received the 'unusual sign-in' email at 22:58, entered her details on the linked page, and saw a transfer "
         "she did not make the next morning.", "2026-06-19 13:00:00", "amna", None, "phish"),
        ("CASE-003", "Nazia Parveen", "HR officer, Crescent Bank",
         "Raised ticket IAM-412 on 31 May to remove all of Ali Ahmed's access. IT closed his personal account but not the "
         "service account or the remote-desktop profiles he had set up on the teller PCs.",
         "2026-06-22 11:00:00", "maryam", "ali", "c3_bank"),
        ("CASE-003", "Imran Butt", "Branch manager, main branch",
         "Tayyab left at 17:05 on 18 June and the branch was locked and alarmed at 18:00. Nobody was inside at 01:02; the "
         "alarm log shows no entry.",
         "2026-06-20 10:00:00", "amna", "tayyab", "authlog"),

        # ------------------------------------------------ CASE-004
        ("CASE-004", "Karim Bux", "Night watchman, Warehouse 03",
         "At about 01:10 a white van with 'Neon Wharf' lettering stopped at the rear gate. A woman and a tall man in glasses "
         "swapped two duffel bags. The man held a small metal case and never let go of it.",
         "2026-03-13 04:30:00", "hiba", "pinky", "c4_cctv"),
        ("CASE-004", "Sadia Noor", "Emergency doctor, Civil Hospital",
         "Treated a 22-year-old with a stimulant overdose at 03:40. He said a woman from the lounge staff handed out "
         "'blue moons' after midnight. A packet stamped with an indigo crescent was in his pocket.",
         "2026-03-13 11:00:00", "warisha", None, "c4_er"),
        ("CASE-004", "Faraz Qadri", "Sound technician, Neon Wharf Lounge",
         "The audio cases stayed in the store room all night. Pinky took the van keys at about 00:40 and said she was "
         "'collecting a delivery'.",
         "2026-03-15 18:00:00", "warisha", "pinky", "c4_gps"),

        # ------------------------------------------------ CASE-005 (real public statements, quoted exactly)
        ("CASE-005", "Ross O'Leary", "Binance spokesperson (via TechCrunch)",
         "Binance \"temporarily suspended withdrawals on multiple networks following a security incident as a "
         "precautionary measure.\" Binance said \"user funds are completely safe\".",
         "2026-10-29 22:27:00", "maryam", None, "c5_statements"),
        ("CASE-005", "Ari Redbord", "Global Head of Policy, TRM Labs (via CNBC)",
         "\"Ultimately, they're [hackers] trying to off-ramp it [crypto] to fiat.\" TRM Labs attributes the theft to "
         "TraderTraitor with high confidence.",
         "2026-10-30 18:08:00", "maryam", "c5_group", "c5_statements"),
        ("CASE-005", "Jonathan Levin", "CEO, Chainalysis (via CNBC)",
         "\"We've got teams working around the clock to continue to follow that.\" Chainalysis said it has \"high "
         "confidence\" North Korea was responsible.",
         "2026-10-30 18:08:00", "warisha", "c5_group", "c5_statements"),
        # ------------------------------------------------ CASE-006
("CASE-006", "Sarah Mitchell", "Neighbour of first victim",
         "Reported unfamiliar activity near the victim's home; person not identified.",
         "2026-04-20 13:00:00", "amna", None, "c6_cam1"),
        ("CASE-006", "James Carter", "Security guard",
         "Observed an unidentified visitor near a crime-scene approach; identification pending.",
         "2026-04-20 13:20:00", "amna", "redjohn", "c6_cam1"),
        ("CASE-006", "Emily Brooks", "Friend of Administrator's wife",
         "Reports that the victim mentioned unsettling phone calls; call source unverified.",
         "2026-04-20 13:40:00", "amna", None, "c6_mail"),
        ("CASE-006", "Michael Reed", "Former colleague of one victim",
         "May know about earlier workplace disagreements; recollection needs corroboration.",
         "2026-04-20 14:00:00", "maryam", None, None),
        ("CASE-006", "David Wilson", "CCTV operator",
         "Can explain camera placement and export limitations across relevant locations.",
         "2026-04-20 14:20:00", "hiba", None, "c6_cam2"),
        ("CASE-006", "Anonymous Caller", "Unidentified caller",
         "Claims knowledge of the offender. Identity and reliability unknown.",
         "2026-04-20 14:40:00", "maryam", None, "c6_sms"),
        # ------------------------------------------------ CASE-007
        ("CASE-007", "Darishna", "Eyewitness; campus corridor",
         "Reports seeing Uswa and Fatima near belongings. No signed interview or verified clock time supplied.",
         "2026-11-07 12:30:00", "admin", "c7_uswa", "c7_video"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", "Abdul Wahid", "Witness; port-records clerk",
         "Reports a ledger transfer and an unfamiliar visitor; has not identified either suspect.",
         "2026-11-07 12:35:00", "admin", None, "c8_ledger"),
        ("CASE-008", "Ali Ahmed", "Witness; nearby café employee",
         "Reports an unusual meeting near the port office; participants remain unidentified.",
         "2026-11-07 12:40:00", "admin", None, "c8_cam"),
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
               (witnesses["rubina"], "Muhammad Daniyal was at the cafe from about 20:30 until about 22:15.",
                users["hiba"]["id"], "2026-03-15 16:00:00", "Witness corrected the time after checking her till receipt (21:58)."))

    # ---- incident timeline (CSV logs are imported through the analysis queue)
    timeline_rows = [
        # (case, when, event type, description, source, related evidence key)
        # ------------------------------------------------ CASE-001
        ("CASE-001", "2026-03-12 21:14:00", "Threatening email", "Syed Hasnain emails the victim: 'Ledgers can be lost.'",
         "Dealer email printout", "email"),
        ("CASE-001", "2026-03-13 19:52:00", "Card handover arranged",
         "Hasnain tells Abdul Wahid to leave card C-1001 under the side-door mat.", "Recovered chat (Wahid's phone)", "c1_chat"),
        ("CASE-001", "2026-03-13 21:58:00", "Daniyal pays at cafe", "Muhammad Daniyal pays his bill at Riverside Cafe.",
         "Till receipt + Rubina Saleem", "c1_receipt"),
        ("CASE-001", "2026-03-13 22:40:00", "Passenger dropped at side gate",
         "Taxi from Hasnain Antiques drops a capped man with a long parcel at the side gate.", "Taxi dispatch log", "c1_taxi"),
        ("CASE-001", "2026-03-13 22:46:58", "Side entrance camera",
         "Capped figure uses card C-1001 at the side-entrance reader.", "CCTV CAM-05", "c1_cctv"),
        ("CASE-001", "2026-03-13 22:55:00", "Raised voices heard",
         "Guard hears two men upstairs: 'that ledger is not yours to sell'.", "Guard interview", "transcript"),
        ("CASE-001", "2026-03-13 23:31:00", "'Done' message",
         "Hasnain to Wahid: 'Done. Card is back under the mat. Forget tonight.'", "Recovered chat (Wahid's phone)", "c1_chat"),
        ("CASE-001", "2026-03-14 07:10:00", "Body discovered", "Night guard finds the victim in the Rare Books Room.",
         "Guard interview", "transcript"),
        # ------------------------------------------------ CASE-002
        ("CASE-002", "2026-05-01 21:03:00", "Threatening messages",
         "Mahzaib threatens to reveal Aira's 'secret'; Aira replies she will leave tomorrow.", "Laptop chat backup", "c2_chat"),
        ("CASE-002", "2026-05-02 18:41:00", "SMS to unknown number", "Aira texts +92 321-***-0777 (not in her contacts).",
         "Call detail records", "calls"),
        ("CASE-002", "2026-05-02 18:45:00", "Aira leaves hostel", "Aira signs out 'for university'.", "Hostel gate register", "c2_register"),
        ("CASE-002", "2026-05-02 19:05:00", "Ruba leaves hostel", "Ruba signs out 'to the market' (she claims 18:30).",
         "Hostel gate register", "c2_register"),
        ("CASE-002", "2026-05-02 19:58:00", "Two coach tickets bought",
         "Two Karachi-Hyderabad tickets paid with Ruba Mazhar's card.", "Coach ticket record", "c2_tickets"),
        ("CASE-002", "2026-05-02 20:06:41", "Terminal camera sighting", "Two young women walk to the Hyderabad coach bay.",
         "CCTV CAM-07", "c2_cctv"),
        ("CASE-002", "2026-05-03 02:40:00", "Ruba returns alone", "Ruba signs back in, saying her bus from Hyderabad was late.",
         "Hostel gate register", "c2_register"),
        ("CASE-002", "2026-05-03 09:15:00", "Reported missing", "Hira Shakir files the missing person report.",
         "Missing person report", "report"),
        # ------------------------------------------------ CASE-003
        ("CASE-003", "2026-05-31 17:40:00", "Access removal requested",
         "HR asks IT to remove all of Ali Ahmed's access (ticket IAM-412).", "IAM ticket", "c3_bank"),
        ("CASE-003", "2026-06-09 14:22:00", "Phishing domain registered",
         "crescentbank-verify.example registered with card ending 8823.", "WHOIS record", "c3_whois"),
        ("CASE-003", "2026-06-10 01:12:00", "Kit advertised", "'shadowteller' offers a Crescent login kit with a live service account.",
         "Forum post", "c3_forum"),
        ("CASE-003", "2026-06-18 22:58:00", "Phishing email received", "Customers receive the fake security alert.",
         "Phishing email sample", "phish"),
        ("CASE-003", "2026-06-18 23:44:52", "Redirect rule added", "svc.upgrade adds a redirect from the real login page.",
         "Server auth log", "authlog"),
        ("CASE-003", "2026-06-19 01:02:18", "Remote session on teller PC",
         "RDP login as teller.tayyab from 203.0.113.45 while the branch is locked.", "Server auth log", "authlog"),
        ("CASE-003", "2026-06-19 02:40:00", "Sessions revoked", "Security analyst revokes 37 sessions.", "Usman Ghani statement", "authlog"),
        ("CASE-003", "2026-06-19 03:11:00", "Mule money reaches Ali Ahmed", "PKR 790,000 from mule accounts arrives in Ali Ahmed's account.",
         "Bank statement", "c3_bank"),
        # ------------------------------------------------ CASE-004
        ("CASE-004", "2026-03-12 22:14:00", "Delivery arranged", "'Teacher': '2 kilos. Blue.'  'P.': 'Lounge van at 1.'",
         "Recovered phone chat", "c4_chat"),
        ("CASE-004", "2026-03-13 00:48:10", "Lounge van departs", "Neon Wharf Lounge van LDR-4418 leaves the lounge.",
         "Van GPS export", "c4_gps"),
        ("CASE-004", "2026-03-13 01:14:22", "Duffel exchange", "Two duffel bags exchanged at the Warehouse 03 rear gate.",
         "CCTV CAM-3", "c4_cctv"),
        ("CASE-004", "2026-03-13 02:10:00", "Packets recovered", "Patrol recovers packets, ledger and phone at the loading bay.",
         "Incident report", "inventory"),
        ("CASE-004", "2026-03-13 03:40:00", "Overdose patient admitted", "22-year-old from the lounge after-party admitted with an indigo-crescent packet.",
         "Hospital record", "c4_er"),
        ("CASE-004", "2026-03-16 17:00:00", "Lab confirms same batch", "Warehouse and hospital packets are the same batch; Pinky's print on packet 7.",
         "Lab report", "c4_lab"),
        # ------------------------------------------------ CASE-005 (UTC, public reporting)
        ("CASE-005", "2026-10-29 20:05:00", "First wallets drained", "Five Binance XRP Ledger wallets send 233.46M XRP to the attacker.",
         "TRM Labs analysis", "c5_outflows"),
        ("CASE-005", "2026-10-29 20:20:00", "50 authorizations submitted", "One transaction with 50 pre-signed EIP-7702 authorizations; BTC and Tron wallets drained.",
         "TRM Labs analysis", "c5_technique"),
        ("CASE-005", "2026-10-29 20:23:24", "Ethereum hot wallet swept", "167,464 ETH and 63 tokens swept to the attacker.",
         "TRM Labs analysis", "c5_outflows"),
        ("CASE-005", "2026-10-29 21:01:00", "Tether freeze", "Tether freezes 971.1M USDT in the main receiving wallet.",
         "TRM Labs analysis", "c5_freezes"),
        ("CASE-005", "2026-10-29 22:27:00", "Binance confirms suspension", "Binance confirms withdrawals suspended on multiple networks.",
         "TechCrunch", "c5_statements"),
        ("CASE-005", "2026-10-30 00:10:00", "Attacker permissions removed", "Binance removes the attacker's permissions from the hot wallet.",
         "Wikipedia summary of coverage", "c5_freezes"),
        # ------------------------------------------------ CASE-006
        ("CASE-006", "2026-01-12 12:00:00", "First incident reported",
         "First known victim identified; red smiley-face marking documented on the wall.", "Initial incident report; date only", "c6_smiley"),
        ("CASE-006", "2026-02-03 12:00:00", "Second incident reported",
         "Investigators compare similarities between two scenes.", "Case chronology; time to be confirmed", "c6_trace"),
        ("CASE-006", "2026-03-18 12:00:00", "Third incident reported",
         "Another scene prompts comparison of a recovered handwritten note.", "Case chronology; time to be confirmed", "c6_note"),
        ("CASE-006", "2026-04-02 12:00:00", "Anonymous communication",
         "Administrator receives an anonymous message referencing family.", "Case chronology; time to be confirmed", "c6_mail"),
        ("CASE-006", "2026-04-17 12:00:00", "Family incident reported",
         "Administrator's wife and daughter identified among victims; independent command needed.", "Case chronology; time to be confirmed", None),
        ("CASE-006", "2026-04-18 12:00:00", "Crimson Task Force formed",
         "Warisha leads the investigation; Administrator recused from operational decisions.", "Case chronology; time to be confirmed", None),
        ("CASE-006", "2026-04-20 12:00:00", "Evidence review",
         "CCTV, physical exhibits and witness statements registered for review.", "Forensic exhibit register; time to be confirmed", "c6_trace"),
        ("CASE-006", "2026-05-05 12:00:00", "Suspect leads identified",
         "Three persons of interest (Red John, Gale Bertram, Bret Stiles) entered for background and alibi checks.", "Investigator notes; time to be confirmed", None),
        ("CASE-006", "2026-05-19 12:00:00", "Investigation-unit message",
         "Anonymous communication claims knowledge of the detective team.", "Communications report; time to be confirmed", "c6_sms"),
        ("CASE-006", "2026-10-01 09:00:00", "Blake Association list recovered",
         "Partial membership list names Gale Bertram; members greet each other with 'Tyger Tyger'.", "Restricted exhibit", "c6_blake"),
        ("CASE-006", "2026-10-14 16:00:00", "Visualize intake card obtained",
         "1994 card interviewed by Bret Stiles: member 'T.M.' with three dots tattooed on the left hand.", "Visualize archive", "c6_visualize"),
        ("CASE-006", "2026-11-01 12:00:00", "Investigation remains open",
         "Offender's identity and possible information leak remain unresolved.", "Case status review; time to be confirmed", "c6_secret"),
        # ------------------------------------------------ CASE-007
        ("CASE-007", "2026-11-07 12:00:00", "Classroom video registered",
         "Complainant-supplied original video registered; incident date and recording time remain unknown.", "Evidence intake date, NOT incident date", "c7_video"),
        ("CASE-007", "2026-11-07 12:30:00", "Witness account",
         "Darishna's report recorded separately from camera observations.", "Witness summary, not authenticated interview", "c7_video"),
        ("CASE-007", "2026-11-07 12:15:00", "Missing items reported",
         "Phone, pencil pouch and power bank reported missing from the window-row chairs.", "Missing property report", "c7_report"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", "2026-11-07 12:20:00", "Ledger reference logged",
         "Anonymous account of missing port ledger registered; original provenance unverified.", "Intake entry; not an incident timestamp", "c8_ledger"),
        ("CASE-008", "2026-11-07 12:25:00", "Anonymous tip received",
         "Rehman Dakait and Pablo named by unverified caller.", "Tip-line entry; not an incident timestamp", "c8_tip"),
        ("CASE-008", "2026-11-07 12:40:00", "Witness review opened",
         "Abdul Wahid and Ali Ahmed nominated for formal interviews.", "Investigator note", "c8_cam"),
        ("CASE-008", "2026-11-04 21:52:40", "Visitor enters records room",
         "Visitor badge V-117 ('P. Rodrigues') enters the records room while clerk Abdul Wahid is inside.", "Records-room badge log", "c8_access"),
        ("CASE-008", "2026-11-04 22:10:05", "Ledger goes missing",
         "Visitor V-117 leaves the records room; the ledger is missing from this time.", "Records-room badge log", "c8_access"),
        ("CASE-008", "2026-11-04 23:10:44", "Container released by override",
         "Container MSKU-48213 (4,200 kg overweight) released with the records clerk's override.", "Shipping manifest", "c8_manifest"),
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
        """'suspect:12' style graph key. Returns None if the suspect/evidence/witness/event does not exist,
        so a link to something missing is skipped instead of crashing the seed."""
        table = {"suspect": suspects, "evidence": evidence, "witness": witnesses}
        if kind in table:
            return f"{kind}:{table[kind][key]}" if key in table[kind] else None
        if kind == "event":
            return f"event:{key}" if key else None
        return f"{kind}:{key}"                    # device / location: free text

    rel_rows = [
        # (case, from, to, relationship, recorded basis, recorded_by)
        # ------------------------------------------------ CASE-001
        ("CASE-001", node("device", "Access card C-1001"), node("suspect", "wahid"), "registered holder",
         "Library security system records C-1001 as issued to Abdul Wahid.", "hiba"),
        ("CASE-001", node("device", "Access card C-1001"), node("evidence", "access"), "appears in",
         "C-1001 is logged at the side entrance at 22:47 and the Rare Books Room at 22:51.", "hiba"),
        ("CASE-001", node("evidence", "c1_chat"), node("suspect", "wahid"), "recovered from phone of",
         "Deleted chat recovered from Abdul Wahid's phone on 16 March.", "warisha"),
        ("CASE-001", node("evidence", "c1_chat"), node("suspect", "hasnain"), "messages from",
         "Sender 'S. Hasnain' asks for the card under the side-door mat and writes 'Done' at 23:31.", "warisha"),
        ("CASE-001", node("evidence", "c1_taxi"), node("location", "Side Entrance"), "drop-off at",
         "Booking BK-58812 from Hasnain Antiques ends at the library side gate at 22:40.", "hiba"),
        ("CASE-001", node("witness", "aslam"), node("suspect", "hasnain"), "drove passenger from shop of",
         "Pickup at Hasnain Antiques, Saddar; booked from a number ending 4471.", "hiba"),
        ("CASE-001", node("evidence", "c1_cctv"), node("location", "Side Entrance"), "recorded at",
         "CAM-05 covers the side-entrance card reader.", "hiba"),
        ("CASE-001", node("suspect", "hasnain"), node("evidence", "email"), "author of",
         "Sender address belongs to Hasnain Antiques.", "hiba"),
        ("CASE-001", node("witness", "rubina"), node("suspect", "daniyal"), "confirms whereabouts of",
         "Cafe owner: Daniyal paid and left at 21:58.", "hiba"),
        ("CASE-001", node("evidence", "c1_receipt"), node("suspect", "daniyal"), "supports alibi of",
         "Till receipt time 21:58:37, table 6.", "hiba"),
        ("CASE-001", node("evidence", "scene"), node("location", "Rare Books Room"), "taken at",
         "Scene photograph 07 of the Rare Books Room.", "warisha"),
        ("CASE-001", node("evidence", "autopsy"), node("location", "Rare Books Room"), "victim recovered from",
         "Pathology summary refers to the body recovered from the Rare Books Room.", "warisha"),
        ("CASE-001", node("witness", "ghufran"), node("evidence", "transcript"), "interview recorded in",
         "Transcript of the guard's interview on 14 March.", "warisha"),
        ("CASE-001", node("event", events.get(("CASE-001", "Raised voices heard"))), node("location", "Rare Books Room"),
         "heard near", "Guard places the voices on the second floor near the Rare Books Room.", "warisha"),
        # ------------------------------------------------ CASE-002
        ("CASE-002", node("evidence", "calls"), node("device", "SIM +92 321-***-0777"), "contact with",
         "SMS at 18:41 and a 212-second call at 19:12 with this number.", "maryam"),
        ("CASE-002", node("evidence", "c2_telco"), node("device", "SIM +92 321-***-0777"), "identifies owner of",
         "Operator reply: second SIM registered to Ruba Mazhar on 28 April.", "maryam"),
        ("CASE-002", node("suspect", "ruba"), node("device", "SIM +92 321-***-0777"), "owner of",
         "Biometric SIM registration in her name.", "maryam"),
        ("CASE-002", node("evidence", "c2_tickets"), node("suspect", "ruba"), "paid by",
         "Both Hyderabad tickets paid with the card ending 3390 (R. Mazhar).", "maryam"),
        ("CASE-002", node("evidence", "c2_cctv"), node("location", "Central Bus Terminal"), "recorded at",
         "CAM-07, bay 4, 20:06.", "amna"),
        ("CASE-002", node("witness", "shahid"), node("location", "Central Bus Terminal"), "observed activity at",
         "Conductor saw two young women board the 20:10 Hyderabad coach.", "amna"),
        ("CASE-002", node("witness", "shamim"), node("suspect", "ruba"), "contradicts statement of",
         "Register shows Ruba out at 19:05 (not 18:30) and back at 02:40.", "amna"),
        ("CASE-002", node("evidence", "c2_chat"), node("suspect", "mahzaib"), "messages from",
         "Threats to reveal Aira's 'secret' on 1 May.", "amna"),
        ("CASE-002", node("witness", "hira"), node("suspect", "mahzaib"), "mentions fear of",
         "Sister says Aira was scared of someone in her class.", "maryam"),
        # ------------------------------------------------ CASE-003
        ("CASE-003", node("evidence", "authlog"), node("device", "Service account svc.upgrade"), "records activity of",
         "Admin login and redirect rule at 23:41-23:44.", "amna"),
        ("CASE-003", node("suspect", "ali"), node("device", "Service account svc.upgrade"), "previously administered",
         "IAM ticket: svc.upgrade managed by Ali Ahmed's contract team; never disabled.", "amna"),
        ("CASE-003", node("evidence", "authlog"), node("device", "Workstation BR-TELLER-04"), "remote session on",
         "RDP login as teller.tayyab from 203.0.113.45 at 01:02.", "amna"),
        ("CASE-003", node("suspect", "tayyab"), node("device", "Workstation BR-TELLER-04"), "assigned user of",
         "Bank asset register lists BR-TELLER-04 as Muhammad Tayyab's workstation.", "amna"),
        ("CASE-003", node("witness", "imran"), node("suspect", "tayyab"), "confirms absence of",
         "Branch locked and alarmed from 18:00; no entry at night.", "amna"),
        ("CASE-003", node("evidence", "c3_whois"), node("device", "VPS 203.0.113.45"), "hosted on",
         "Phishing domain hosted on the same IP as the admin login and RDP session.", "maryam"),
        ("CASE-003", node("evidence", "c3_bank"), node("device", "VPS 203.0.113.45"), "paid for",
         "Card 8823 pays 'VPS-HOST*203.0.113.45' on 10 June.", "amna"),
        ("CASE-003", node("evidence", "c3_bank"), node("suspect", "ali"), "statement of",
         "Bank statement of Ali Ahmed's account, card ending 8823.", "amna"),
        ("CASE-003", node("evidence", "c3_forum"), node("suspect", "shadow"), "posted by",
         "Forum post by 'shadowteller', 10 June 01:12.", "maryam"),
        ("CASE-003", node("evidence", "c3_whois"), node("suspect", "shadow"), "registrant email of",
         "Registrant email shadow.teller@... matches the forum seller.", "maryam"),
        ("CASE-003", node("evidence", "phish"), node("evidence", "screenshot"), "links to",
         "The email's link opens the page shown in the screenshot.", "amna"),
        ("CASE-003", node("witness", "nazia"), node("suspect", "ali"), "raised access-removal ticket for",
         "IAM-412 raised 31 May.", "maryam"),
        # ------------------------------------------------ CASE-004
        ("CASE-004", node("evidence", "c4_gps"), node("device", "Van LDR-4418"), "tracks",
         "GPS export of the Neon Wharf Lounge van.", "hiba"),
        ("CASE-004", node("witness", "karim"), node("device", "Van LDR-4418"), "observed",
         "White van with 'Neon Wharf' lettering at the rear gate at about 01:10.", "hiba"),
        ("CASE-004", node("evidence", "c4_cctv"), node("location", "Warehouse 03 rear gate"), "recorded at",
         "CAM-3 rear gate, 01:14.", "hiba"),
        ("CASE-004", node("suspect", "pinky"), node("evidence", "c4_lab"), "fingerprint on packet in",
         "Latent print on the inner wrapping of packet 7 matched to Anmol Pinky.", "warisha"),
        ("CASE-004", node("evidence", "c4_chat"), node("suspect", "pinky"), "contact 'P.' resembles",
         "'Audio gear on top' matches her statement that the bag held audio equipment. Unconfirmed.", "warisha"),
        ("CASE-004", node("evidence", "c4_chat"), node("suspect", "walter"), "contact 'Teacher' resembles",
         "'Measuring kit on top' matches his statement about measuring equipment. Unconfirmed.", "warisha"),
        ("CASE-004", node("witness", "faraz"), node("suspect", "pinky"), "saw take the van keys",
         "Sound technician: Pinky took the van keys at about 00:40.", "warisha"),
        ("CASE-004", node("evidence", "c4_er"), node("evidence", "c4_lab"), "same batch as",
         "Lab: hospital packet and warehouse packets share one impurity profile.", "warisha"),
        # ------------------------------------------------ CASE-005
        ("CASE-005", node("suspect", "c5_group"), node("suspect", "c5_wallet"), "attributed controller of",
         "TRM Labs and Chainalysis attribute the operator wallet's activity to TraderTraitor.", "maryam"),
        ("CASE-005", node("suspect", "c5_wallet"), node("device", "Binance ETH hot wallet"), "submitted 50 authorizations to",
         "One transaction at 20:20 UTC with 50 pre-signed EIP-7702 authorizations.", "maryam"),
        ("CASE-005", node("evidence", "c5_outflows"), node("device", "Binance ETH hot wallet"), "records outflows from",
         "167,464 ETH and 63 tokens swept at 20:23:24 UTC.", "maryam"),
        ("CASE-005", node("evidence", "c5_technique"), node("device", "Binance ETH hot wallet"), "explains attack on",
         "Analyst note on the EIP-7702 delegation.", "warisha"),
        ("CASE-005", node("evidence", "c5_outflows"), node("device", "Attacker main receiving wallet"), "records transfers to",
         "Main sweep and six repeat sweeps.", "maryam"),
        ("CASE-005", node("evidence", "c5_freezes"), node("device", "Attacker main receiving wallet"), "records freezes in",
         "Tether 971.1M USDT (21:01), Circle 823M USDC (21:04).", "maryam"),
        ("CASE-005", node("witness", "ari"), node("suspect", "c5_group"), "attributes theft to",
         "TRM Labs attribution, high confidence.", "maryam"),
        ("CASE-005", node("witness", "jonathan"), node("suspect", "c5_group"), "attributes theft to",
         "Chainalysis: 'high confidence' North Korea was responsible.", "warisha"),
        # ------------------------------------------------ CASE-006
        ("CASE-006", node("evidence", "c6_smiley"), node("location", "Multiple scenes"), "same signature at",
         "Same stroke order and height at four scenes; details never released to the press.", "hiba"),
        ("CASE-006", node("witness", "david"), node("evidence", "c6_cam2"), "can clarify provenance of",
         "CCTV operator can explain camera export and coverage limits.", "hiba"),
        ("CASE-006", node("suspect", "redjohn"), node("evidence", "c6_cam1"), "resembles person in",
         "An unidentified hooded figure appears in the alley camera; identity not established.", "maryam"),
        ("CASE-006", node("evidence", "c6_blake"), node("suspect", "gale"), "lists as member",
         "Gale Bertram appears as a sponsor on the partial Blake Association list.", "warisha"),
        ("CASE-006", node("evidence", "c6_visualize"), node("suspect", "bret"), "signed by",
         "Bret Stiles personally interviewed member 'T.M.' in 1994.", "amna"),
        ("CASE-006", node("evidence", "c6_visualize"), node("suspect", "redjohn"), "possible early record of",
         "Three-dot tattoo on the left hand matches a survivor's description of Red John. Unconfirmed.", "amna"),
        ("CASE-006", node("evidence", "c6_note"), node("evidence", "c6_mail"), "same Blake quote as",
         "Both quote 'Tyger Tyger, burning bright', the Blake Association greeting.", "hiba"),
        ("CASE-006", node("evidence", "c6_blake"), node("evidence", "c6_mail"), "greeting phrase matches",
         "Association members identify themselves with 'Tyger Tyger'.", "warisha"),
        # ------------------------------------------------ CASE-007
        ("CASE-007", node("witness", "darishna"), node("location", "DUET Gulberg classroom corridor"), "reports activity near",
         "Witness account; no separate corridor footage.", "admin"),
        ("CASE-007", node("evidence", "c7_video"), node("location", "DUET Gulberg classroom"), "recorded in",
         "Supplied classroom video (camera view of the window-row chairs).", "admin"),
        ("CASE-007", node("evidence", "c7_chat"), node("suspect", "c7_uswa"), "chat recovered from",
         "Chat exhibit recovered from the handset; authenticity under review.", "admin"),
        ("CASE-007", node("evidence", "c7_chat"), node("suspect", "c7_fatima"), "chat recovered from",
         "Chat exhibit recovered from the handset; authenticity under review.", "admin"),
        ("CASE-007", node("evidence", "c7_report"), node("location", "DUET Gulberg classroom"), "items missing from",
         "Property left on the window-row chairs.", "admin"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", node("witness", "abdul"), node("evidence", "c8_ledger"), "reports observation related to",
         "Ledger-transfer account; no authenticated original yet.", "admin"),
        ("CASE-008", node("witness", "ali"), node("location", "Old Port District"), "reports meeting near",
         "Witness account; participants unidentified.", "admin"),
        ("CASE-008", node("suspect", "c8_rehman"), node("evidence", "c8_tip"), "named in unverified allegation",
         "Anonymous tip alone does not establish involvement.", "admin"),
        ("CASE-008", node("suspect", "c8_pablo"), node("evidence", "c8_tip"), "named in unverified allegation",
         "Anonymous tip alone does not establish involvement.", "admin"),
        ("CASE-008", node("evidence", "c8_access"), node("device", "Visitor badge V-117 (P. Rodrigues)"), "records",
         "V-117 in at 21:52, out at 22:10 on 4 Nov.", "hiba"),
        ("CASE-008", node("evidence", "c8_registry"), node("device", "Visitor badge V-117 (P. Rodrigues)"), "same name as director",
         "Knight Holdings director 'P. Rodrigues' = name given at the gate for V-117.", "maryam"),
        ("CASE-008", node("suspect", "c8_pablo"), node("device", "Visitor badge V-117 (P. Rodrigues)"), "possibly used",
         "'P.' in the ledger and the tip; first name only. Unverified.", "maryam"),
        ("CASE-008", node("evidence", "c8_access"), node("witness", "abdul"), "records badge of",
         "Clerk E-2207 was inside during the visit and issued the release override at 23:10.", "hiba"),
        ("CASE-008", node("evidence", "c8_manifest"), node("device", "Container MSKU-48213"), "weight mismatch on",
         "Weighbridge 22,600 kg vs declared 18,400 kg.", "hiba"),
        ("CASE-008", node("evidence", "c8_tip"), node("device", "Container MSKU-48213"), "names",
         "Caller: 'MSKU-48213 isn't machinery. Check the weight.'", "admin"),
    ]
    rel_rows = [row for row in rel_rows if row[1] and row[2]]     # drop links to anything that was not created
    for case_number, source, target, kind, text, by in rel_rows:
        db.execute("INSERT INTO evidence_relationships (case_id, source_node, target_node, relationship_type, "
                   "description, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (cases[case_number]["id"], source, target, kind, text, users[by]["id"], stamp))

    # ---- notes (one with an earlier version so Undo / the Stack can be demonstrated)
    cursor = db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-001"]["id"], users["warisha"]["id"], "Access card discrepancy",
         "Card C-1001 (Abdul Wahid) is logged at the side entrance at 22:47, three hours after he says he went home. "
         "The recovered chat shows he left the card under the side-door mat for Syed Hasnain. Need: Wahid's bank account "
         "for the '2 lakh'; Hasnain's real dinner companion; search Hasnain Antiques for the missing ledger and brass bookend.",
         "2026-03-14 13:00:00", "2026-03-18 18:20:00"))
    db.execute("INSERT INTO note_history (note_id, title, content, saved_by, saved_at) VALUES (?, ?, ?, ?, ?)",
               (cursor.lastrowid, "Access card discrepancy",
                "Wahid's card appears in the log late at night. Check with security whether it can be cloned.",
                users["warisha"]["id"], "2026-03-14 13:00:00"))
    db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-001"]["id"], users["hiba"]["id"], "Taxi passenger",
         "Passenger picked up at Hasnain Antiques arrived at 22:40, seven minutes before C-1001 was used, and was collected "
         "again at 23:29 - two minutes before the 'Done' message. Phone ending 4471 to be checked against Hasnain's number.",
         "2026-03-17 18:00:00", "2026-03-17 18:00:00"))
    db.execute(
        "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cases["CASE-003"]["id"], users["amna"]["id"], "Service account",
         "svc.upgrade should have been disabled when the contract ended on 31 May (IAM-412 only half done). "
         "The same IP 203.0.113.45 hosts the phishing site, ran the admin login and the RDP session - and was paid "
         "for with Ali Ahmed's card.",
         "2026-06-20 10:00:00", "2026-06-22 15:00:00"))

    # ---- additional per-case notes
    additional_notes = [
        ("CASE-001", "Red herring: Daniyal", "Daniyal's plagiarism motive is real, but the receipt (21:58) and the cafe owner "
         "put him away from the library; nothing links him to the side entrance.", "hiba"),
        ("CASE-001", "Weapon", "Pathology matches the base of the missing brass bookend. Search the dealer's shop and car.", "warisha"),
        ("CASE-002", "Ruba lied twice", "She said she left at 18:30 and had 'no idea' where Aira went. The register says 19:05, "
         "her second SIM called Aira at 19:12 and her card bought both Hyderabad tickets.", "maryam"),
        ("CASE-002", "Mahzaib's leverage", "The 1 May messages threaten to reveal Aira's 'secret'. Find out what it is - it may "
         "be why Aira chose to leave.", "amna"),
        ("CASE-002", "Next step", "Coach company CCTV at the first stop; Ruba's phone towers after 20:31; Hyderabad relatives "
         "of either girl. Aira may be safe and hiding - or not.", "maryam"),
        ("CASE-003", "Tayyab is likely framed", "His session at 01:02 came from 203.0.113.45 over remote desktop while the "
         "branch was locked; Ali Ahmed set up those RDP profiles during the upgrade.", "amna"),
        ("CASE-003", "shadowteller = Ali Ahmed?", "Forum post says 'when my contract ended'; domain and VPS paid by card 8823 "
         "(Ali Ahmed). Ask the forum operator for login IPs.", "maryam"),
        ("CASE-004", "Pinky's alibi fails", "Van GPS shows the lounge van at Warehouse 03 01:09-01:27; the technician saw her "
         "take the keys; her print is on packet 7.", "hiba"),
        ("CASE-004", "Who is 'Teacher'?", "Purity 96% points to a trained chemist. 'Measuring kit' matches Walter White's "
         "statement, but there is no print or phone link to him yet.", "warisha"),
        ("CASE-005", "Source of facts", "All entries come from public reporting (TRM Labs, TechCrunch, CNBC, Wikipedia). "
         "Wallet names in the files are masked for confidentiality. No individual is named as a suspect.", "maryam"),
        ("CASE-005", "Open questions", "Binance has not published a root cause. How were 50 authorizations signed without "
         "an alert? Where will the remaining ETH and BTC be cashed out?", "warisha"),
        ("CASE-006", "Confidentiality risk", "Anonymous messages suggest possible knowledge of the team; audit access lawfully.", "maryam"),
        ("CASE-006", "Administrator recusal", "Administrator is personally connected to the victims and must not direct investigative operations.", "warisha"),
        ("CASE-006", "Signature pattern", "The red smiley-face signature uses the same stroke order and height at every scene; it was never made public.", "hiba"),
        ("CASE-006", "Victim link review", "Compare documented contacts, disputes and records without presuming a common offender.", "amna"),
        ("CASE-006", "Independent verification", "Review authenticity of CCTV, anonymous mail, prior complaints and witness claims.", "hiba"),
        ("CASE-006", "Look at hands", "The SMS says 'look at hands'. The 1994 Visualize card describes three dots tattooed on "
         "the left hand of member 'T.M.' - the same initials as the torn Blake list entry.", "warisha"),
        ("CASE-007", "Working theory", "Uswa and Fatima are persons of interest on the current working theory only; this is not a finding of responsibility.", "admin"),
        ("CASE-007", "Unknown incident time", "The supplied video provides playback offsets, not a confirmed filming date or clock time.", "admin"),
        ("CASE-007", "Source versus recovered material", "Keep original video and portraits separate from recovered messages and missing-property report.", "admin"),
        ("CASE-007", "Witness scope", "Darishna's corridor statement is not corroborated by separate corridor footage.", "admin"),
        ("CASE-007", "Identity caution", "Named portrait associations are supplied labels, not independent biometric identification.", "admin"),
        ("CASE-007", "Integrity and privacy", "Preserve original file hashes and confirm permission before making portraits/videos public.", "admin"),
        ("CASE-008", "Unverified association", "Anonymous tip names Rehman Dakait and Pablo; do not treat this as established involvement.", "admin"),
        ("CASE-008", "Witness follow-up", "Interview witnesses Abdul Wahid and Ali Ahmed; compare accounts with independently sourced records.", "admin"),
        ("CASE-008", "Ledger authenticity", "Confirm provenance and meaning of black chess-knight symbol before drawing conclusions.", "admin"),
        ("CASE-008", "Open case", "All entries are preliminary and remain editable; no culprit or confirmed allegation is established.", "admin"),
        ("CASE-008", "Is the witness involved?", "Abdul Wahid, called as a witness, was inside the records room during the visit "
         "and issued the release override for the overweight container at 23:10. Treat his account with care.", "hiba"),
    ]
    for case_number, title, content, by in additional_notes:
        db.execute(
            "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cases[case_number]["id"], users[by]["id"], title, content, stamp, stamp)
        )

    # ---- pending analysis tasks so the Queue has something to process (CSV logs -> timeline)
    for case_number, key, requested_by, when in (("CASE-001", "access", "hiba", "2026-03-14 12:35:00"),
                                                 ("CASE-004", "c4_gps", "hiba", "2026-03-17 13:15:00"),
                                                 ("CASE-008", "c8_access", "hiba", "2026-11-07 13:15:00")):
        if key in evidence:
            db.execute("INSERT INTO analysis_tasks (case_id, evidence_id, task_type, requested_by, created_at) "
                       "VALUES (?, ?, 'import_csv_timeline', ?, ?)",
                       (cases[case_number]["id"], evidence[key], users[requested_by]["id"], when))
    db.commit()

    # ---- extra custody history, then real SHA-256 verifications for some items
    for key, username, action, text, when in (
            ("scene", "hiba", "Evidence viewed", "Reviewed scene photograph", "2026-03-14 11:02:00"),
            ("access", "warisha", "Evidence viewed", "Reviewed access log", "2026-03-14 13:05:00"),
            ("c1_chat", "warisha", "Evidence viewed", "Compared recovered chat with the access log", "2026-03-18 16:10:00"),
            ("c4_chat", "hiba", "Evidence viewed", "Reviewed burner-phone chat", "2026-03-15 20:05:00")):
        if key in evidence:
            record_custody_event(evidence[key], users[username]["id"], action, text, timestamp=when)
    for key, username in (("scene", "warisha"), ("autopsy", "warisha"), ("transcript", "warisha"),
                          ("authlog", "amna"), ("phish", "amna"), ("report", "maryam"),
                          ("c4_lab", "hiba"), ("c6_smiley", "warisha"), ("c7_video", "amna")):
        if key in evidence:
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
    create_app()            # recreates folders, schema and case data
    print("TRACE X reset complete. Case archive loaded.")


if __name__ == "__main__":
    if "--reset" in sys.argv:
        reset()
    else:
        print(__doc__)
