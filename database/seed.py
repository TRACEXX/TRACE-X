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
        "case_number": "CASE-004",
        "title": "The Indigo Veil",
        "category": "Narcotics Offence",
        "status": "Open",
        "incident_date": "2026-03-13",
        "location": "West Wharf District, Karachi (fictional)",
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
        "team": [],  # Admin assigns detectives during the demo
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
        "case_number": "CASE-006", "title": "The Red Signature Murders", "category": "Homicide",
        "status": "Under Investigation", "incident_date": "2026-01-12",
        "location": "Multiple fictional crime scenes; Crimson Task Force jurisdiction",
        "created_at": "2026-04-18 09:00:00",
        "description": (
            "A series of suspected connected killings is attributed to an unidentified offender called "
            "the Red Phantom. Investigators have documented a recurring red spiral symbol and anonymous "
            "messages apparently directed toward the investigation team. The Administrator's wife and "
            "daughter are among the victims, creating a conflict requiring operational recusal. "
            "Incident type: serial homicide, targeted family killings, psychological intimidation "
            "and possible evidence manipulation. The offender's identity and links among victims remain unknown."
        ),
        "summary": (
            "Open serial-homicide investigation involving nine reported victims, a recurring red spiral "
            "mark and anonymous communications. The Crimson Task Force is investigating possible insider leaks."
        ),
        "team": [("warisha", "lead"), ("amna", "investigator"),
                 ("hiba", "investigator"), ("maryam", "investigator")],
    },
    # ------------------------------------------------ CASE-007: THE DUET CAMPUS THEFT
    {
        "case_number": "CASE-007", "title": "The DUET Campus Theft", "category": "Theft",
        "status": "Pending Review", "incident_date": None,
        "location": "DUET Gulberg Campus (fictional training scenario)",
        "created_at": "2026-11-07 12:00:00",
        "description": (
            "In a fictional classroom scenario, student belongings including a mobile phone were reportedly "
            "taken near chairs. Uswa and Fatima are the scripted suspects, and Darishna reports observing "
            "activity near the corridor. A user-supplied classroom video, seven extracted frames, two "
            "portraits and simulated messages are available for investigation training. The actual incident "
            "date is unknown, and the source footage alone does not establish criminal wrongdoing."
        ),
        "summary": (
            "Fictional DUET student-property theft: Uswa and Fatima are responsible in the scripted "
            "storyline only. Original video and supplied portraits are separate from simulated exhibits."
        ),
        "team": [],  # The admin assigns the case during the demo
    },
    # ------------------------------------------------ CASE-008: THE BLACK LEDGER
    {
        "case_number": "CASE-008", "title": "The Black Ledger", "category": "Criminal Conspiracy",
        "status": "Open", "incident_date": None,
        "location": "Fictional Old Port District, Karachi",
        "created_at": "2026-11-07 12:10:00",
        "description": (
            "A sealed ledger bearing a black chess-knight emblem appears after a fictional port firm's "
            "records disappear. Anonymous claims name two people of interest, Rehman Dakait and Pablo, "
            "but investigators cannot yet verify their involvement. Abdul Wahid and Ali Ahmed are "
            "potential witnesses to unusual meetings and records transfers. The suspected conspiracy "
            "and the source of the ledger remain unresolved. All characters and allegations are fictional."
        ),
        "summary": (
            "Open fictional organized-crime conspiracy involving a missing ledger, conflicting accounts "
            "and two persons of interest. Evidence is preliminary; no culprit has been identified."
        ),
        "team": [],  # Admin assignment later
    },
]

SUSPECTS = {
    "CASE-001": [
        {"key": "kamran", "name": "Kamran Khan", "relationship": "Head librarian; colleague of the victim",
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
            "notes": "Late-night visit and connection to Pinky remain unverified."
        }
    ],
    # ------------------------------------------------ CASE-006
    "CASE-006": [
        {"key": "c6_daniel", "name": "Daniel Cross", "relationship": "Former homicide investigator; prior links to a victim.",
         "background": "Former senior investigator with knowledge of police procedures.",
         "motive": "Unknown; former professional associations under review.",
         "alibi": "Not verified.", "statements": "Interview pending.",
         "notes": "Past case access and current whereabouts need verification."},
        {"key": "c6_victor", "name": "Victor Hale", "relationship": "Business and family associate of the Administrator.",
         "background": "Businessman with prior disagreements involving the family.",
         "motive": "Possible personal or financial dispute; unconfirmed.",
         "alibi": "Claims to have been travelling during one incident.",
         "statements": "Formal statement pending.", "notes": "Financial and travel records requested."},
        {"key": "c6_unknown", "name": "Unknown CCTV Individual", "relationship": "Unidentified figure in footage near two locations.",
         "background": "Identity and occupation unknown.", "motive": "Unknown.",
         "alibi": "Not established.", "statements": "No interview possible until identification.",
         "notes": "Do not assume repeated footage proves the same individual."},
        {"key": "c6_adrian", "name": "Dr. Adrian Moore", "relationship": "Former forensic pathologist with historic case access.",
         "background": "Previously worked with law enforcement; employment records under review.",
         "motive": "Unknown; possible link to confidential case records unverified.",
         "alibi": "Partially verified.", "statements": "Interview pending.",
         "notes": "Verify prior information access and remaining alibi gaps."},
    ],
    # ------------------------------------------------ CASE-007
    "CASE-007": [
        {"key": "c7_uswa", "name": "Uswa", "relationship": "Scripted participant in missing-belongings incident.",
         "background": "Student character; maroon outfit in supplied classroom video.",
         "motive": "Not established from source footage.",
         "alibi": "No authenticated alibi supplied.",
         "statements": "No verified interrogation; fictional storyline assigns joint responsibility.",
         "notes": "Portrait and video identification supplied by user; not independent proof.",
         "photo_path": "assets/suspects/uswa.jpeg"},
        {"key": "c7_fatima", "name": "Fatima", "relationship": "Scripted participant in missing-belongings incident.",
         "background": "Student character; lighter outfit and green headscarf in video.",
         "motive": "Not established from source footage.",
         "alibi": "No authenticated alibi supplied.",
         "statements": "No verified interrogation; fictional storyline assigns joint responsibility.",
         "notes": "Portrait and video identification supplied by user; not independent proof.",
         "photo_path": "assets/suspects/fatima.jpeg"},
    ],
    # ------------------------------------------------ CASE-008
    "CASE-008": [
        {"key": "c8_rehman", "name": "Rehman Dakait", "relationship": "Fictional character named in an anonymous conspiracy allegation.",
         "background": "Legendary underworld figure within the fictional scenario.",
         "motive": "Possible influence over disputed port records; unverified.",
         "alibi": "Not yet interviewed.", "statements": "No authenticated statement.",
         "notes": "Treat the role as fictional; verify claims independently."},
        {"key": "c8_pablo", "name": "Pablo", "relationship": "Fictional contact named alongside Rehman in an anonymous tip.",
         "background": "Mysterious business intermediary; identity details pending.",
         "motive": "Unknown possible interest in missing company ledger.",
         "alibi": "Not yet interviewed.", "statements": "No authenticated statement.",
         "notes": "No confirmed association with any offence."},
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

WAREHOUSE_INCIDENT_REPORT = """WAREHOUSE INCIDENT REPORT (FICTIONAL)
Case reference: CASE-004. Date: 14 March 2026.
Location: West Wharf District, Warehouse 03.
Findings: Unidentified packages marked with an indigo crescent symbol recovered.
CCTV footage indicates a duffel-bag exchange involving Anmol Pinky.
"""


# CASE-007: original project-provided source media; relative to this repository.
# Put the included case_assets directory beside database/ before first-time seeding.
from pathlib import Path



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
        
        ("CASE-004", "inventory", "warehouse_incident_report.txt", WAREHOUSE_INCIDENT_REPORT.encode(),
         "Initial incident report documenting suspicious warehouse activity and recovered evidence.",
         "admin", "2026-03-14 10:30:00"),
        # ------------------------------------------------ CASE-006: Red Signature case exhibits
        ("CASE-006", "c6_spiral", "red_spiral_scene_record.pdf", make_pdf(
            "Red Spiral Scene Record", ["CASE-006: Fictional recurring red spiral mark documented at multiple scenes.",
            "Meaning, maker and connection between scenes remain undetermined."]),
            "Fictional recurring-symbol examination record.", "hiba", "2026-04-20 10:00:00"),
        ("CASE-006", "c6_note", "handwritten_note_report.txt",
            b"CASE-006 | Fictional handwritten note found near an earlier scene. Authorship unknown; handwriting review pending.",
            "Scene note and handwriting comparison request.", "hiba", "2026-04-20 10:05:00"),
        ("CASE-006", "c6_trace", "physical_trace_register.pdf", make_pdf(
            "Physical Trace Register", ["CASE-006: Fictional partial fingerprint, fabric and hair exhibits documented.",
            "Laboratory and DNA comparisons have not been completed."]),
            "Preliminary forensic exhibit register.", "hiba", "2026-04-20 10:10:00"),
        ("CASE-006", "c6_cam1", "cctv_first_location.png", make_placeholder_png(800, 500, (120, 35, 48)),
            "Generated fictional CCTV placeholder for unidentified person; not actual footage.", "hiba", "2026-04-20 10:20:00"),
        ("CASE-006", "c6_cam2", "cctv_vehicle_location.png", make_placeholder_png(800, 500, (105, 45, 55)),
            "Generated fictional camera still placeholder; vehicle identification pending.", "hiba", "2026-04-20 10:25:00"),
        ("CASE-006", "c6_mail", "anonymous_email.txt",
            b"FICTIONAL ANONYMOUS EMAIL | Recipient: Administrator | Sender unverified. A message references the Administrator's family. Original headers requested.",
            "Anonymous email report; sender unknown.", "maryam", "2026-04-20 10:30:00"),
        ("CASE-006", "c6_sms", "investigation_unit_message.txt",
            b"FICTIONAL TEXT | Recipient: Investigation Unit | Sender unknown. Message claims knowledge of the four detectives. Source attribution pending.",
            "Anonymous message allegedly sent to investigators.", "maryam", "2026-05-19 11:00:00"),
        ("CASE-006", "c6_secret", "restricted_complaint_reference.txt",
            b"CASE-006 | RESTRICTED FICTIONAL LEAD | Old confidential complaint appears connected to an event in the Administrator's professional history. Possible coincidence; no names established.",
            "Restricted historic complaint reference; unverified.", "warisha", "2026-11-01 10:00:00"),
        # ------------------------------------------------ CASE-007: exact supplied media from DUET package
        
("CASE-007", "c7_video", "EV-001_classroom_video.mp4",
    (Path("evidence_storage/CASE-007") / "EV-001_classroom_video.mp4").read_bytes(),
    "Original user-supplied classroom video; recording date and clock time unknown.",
    "admin", "2026-11-07 12:05:00"),

("CASE-007", "c7_frame2", "EV-002_entry.png",
    (Path("evidence_storage/CASE-007") / "EV-002_entry.png").read_bytes(),
    "Extracted still at video offset 00:02.5: Classroom entry; offset is not a wall-clock time.",
    "admin", "2026-11-07 12:10:00"),

("CASE-007", "c7_uswa_photo", "EV-009_uswa_portrait.jpeg",
    (Path("evidence_storage/CASE-007") / "EV-009_uswa_portrait.jpeg").read_bytes(),
    "User-supplied portrait labeled Uswa; source identification not independently verified.",
    "admin", "2026-11-07 12:15:00"),

("CASE-007", "c7_fatima_photo", "EV-010_fatima_portrait.jpeg",
    (Path("evidence_storage/CASE-007") / "EV-010_fatima_portrait.jpeg").read_bytes(),
    "User-supplied portrait labeled Fatima; source identification not independently verified.",
    "admin", "2026-11-07 12:16:00"),

("CASE-007", "c7_sim_chat", "SIM-001_chat_transcript.csv",
    (Path("evidence_storage/CASE-007") / "SIM-001_chat_transcript.csv").read_bytes(),
    "SIMULATED conversation for fictional storyline; not recovered from a device.",
    "admin", "2026-11-07 12:20:00"),

("CASE-007", "c7_lost_report", "SIM-002_lost_property_report.txt",
    (Path("evidence_storage/CASE-007") / "SIM-002_lost_property_report.txt").read_bytes(),
    "SIMULATED student-property report; ownership and incident date not verified.",
    "admin", "2026-11-07 12:21:00"),

        # ------------------------------------------------ CASE-008: starter fictional exhibits; editable later
        ("CASE-008", "c8_ledger", "black_ledger_intake.txt",
            b"CASE-008 | FICTIONAL CASE FILE | Sealed black ledger reported missing from a port company. An anonymous copy contains a black chess-knight emblem. Provenance under review.",
            "Preliminary ledger intake note; authenticity not established.", "admin", "2026-11-07 12:20:00"),
        ("CASE-008", "c8_tip", "anonymous_port_tip.txt",
            b"CASE-008 | FICTIONAL ANONYMOUS TIP | Caller mentions Rehman Dakait and Pablo but provides no corroborated information. Do not treat allegations as verified.",
            "Anonymous allegation; identity and claims unverified.", "admin", "2026-11-07 12:25:00"),
        ("CASE-008", "c8_cam", "port_corridor_placeholder.png", make_placeholder_png(800, 500, (50, 70, 100)),
            "Generated fictional port-corridor still; replace with original staged evidence.", "admin", "2026-11-07 12:30:00"),
    ]


def seed_database():
    """Create the schema and load the sample data. Call inside an app context."""
    from routes.evidence import store_evidence_file   # imported here to avoid a circular import

    db = get_db()
    create_schema(db)
    config = current_app.config
    stamp = now_str()

    # ---- users: administrator and detectives with relative image paths for static assets
    users = {}
    cursor = db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, badge_id, specialization, profile_image, created_at) "
        "VALUES (?, ?, ?, 'admin', 'ADM-001', 'System administration', 'assets/detectives/admin.jpg', ?)",
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
            photo_path = s.get("photo_path")
            cursor = db.execute(
                "INSERT INTO suspects (case_id, name, photo_path, background, relationship, motive, alibi, statements, notes, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cases[case_number]["id"], s["name"], photo_path, s["background"], s["relationship"], s["motive"], s["alibi"],
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
        # ------------------------------------------------ CASE-006
        ("CASE-006", "Sarah Mitchell", "Neighbour of first victim",
         "Reported unfamiliar activity near the victim's home; person not identified.",
         "2026-04-20 13:00:00", "amna", None, "c6_cam1"),
        ("CASE-006", "James Carter", "Security guard",
         "Observed an unidentified visitor near a crime-scene approach; identification pending.",
         "2026-04-20 13:20:00", "amna", "c6_unknown", "c6_cam1"),
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
        ("CASE-007", "Darishna", "Fictional eyewitness; campus corridor",
         "In the scripted scenario, reports seeing Uswa and Fatima near belongings. No signed interview or verified clock time supplied.",
         "2026-11-07 12:30:00", "admin", "c7_uswa", "c7_video"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", "Abdul Wahid", "Fictional witness; port-records clerk",
         "Reports a ledger transfer and an unfamiliar visitor; has not identified either suspect.",
         "2026-11-07 12:35:00", "admin", None, "c8_ledger"),
        ("CASE-008", "Ali Ahmed", "Fictional witness; nearby café employee",
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
        # ------------------------------------------------ CASE-006
        ("CASE-006", "2026-01-12 12:00:00", "First incident reported",
         "First known victim identified; red spiral scene marking documented.", "Initial incident report; date only", "c6_spiral"),
        ("CASE-006", "2026-02-03 12:00:00", "Second incident reported",
         "Investigators compare similarities between two scenes.", "Case chronology; time placeholder", "c6_trace"),
        ("CASE-006", "2026-03-18 12:00:00", "Third incident reported",
         "Another scene prompts comparison of a recovered handwritten note.", "Case chronology; time placeholder", "c6_note"),
        ("CASE-006", "2026-04-02 12:00:00", "Anonymous communication",
         "Administrator receives an anonymous message referencing family.", "Case chronology; time placeholder", "c6_mail"),
        ("CASE-006", "2026-04-17 12:00:00", "Family incident reported",
         "Administrator's wife and daughter identified among victims; independent command needed.", "Case chronology; time placeholder", None),
        ("CASE-006", "2026-04-18 12:00:00", "Crimson Task Force formed",
         "Warisha leads the investigation; Administrator recused from operational decisions.", "Case chronology; time placeholder", None),
        ("CASE-006", "2026-04-20 12:00:00", "Evidence review",
         "CCTV, physical exhibits and witness statements registered for review.", "Forensic exhibit register; time placeholder", "c6_trace"),
        ("CASE-006", "2026-05-05 12:00:00", "Suspect leads identified",
         "Four persons of interest entered for independent background and alibi checks.", "Investigator notes; time placeholder", None),
        ("CASE-006", "2026-05-19 12:00:00", "Investigation-unit message",
         "Anonymous communication claims knowledge of the detective team.", "Communications report; time placeholder", "c6_sms"),
        ("CASE-006", "2026-11-01 12:00:00", "Investigation remains open",
         "Offender's identity and possible information leak remain unresolved.", "Case status review; time placeholder", "c6_secret"),
        # ------------------------------------------------ CASE-007 (video offsets only; clock times unknown)
        ("CASE-007", "2026-11-07 12:00:00", "Classroom video registered",
         "User-supplied original video registered; incident date and recording time remain unknown.", "Evidence intake date, NOT incident date", "c7_video"),
        ("CASE-007", "2026-11-07 12:12:00", "Video frame 02 review",
         "Video offset 00:02.5: Classroom entry. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame2"),
        ("CASE-007", "2026-11-07 12:13:00", "Video frame 03 review",
         "Video offset 00:04.5: Approach to chairs. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame3"),
        ("CASE-007", "2026-11-07 12:14:00", "Video frame 04 review",
         "Video offset 00:06.5: Near belongings. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame4"),
        ("CASE-007", "2026-11-07 12:15:00", "Video frame 05 review",
         "Video offset 00:08.5: Continued interaction. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame5"),
        ("CASE-007", "2026-11-07 12:16:00", "Video frame 06 review",
         "Video offset 00:10.5: Individuals separate. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame6"),
        ("CASE-007", "2026-11-07 12:17:00", "Video frame 07 review",
         "Video offset 00:15.5: Later chair-area activity. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame7"),
        ("CASE-007", "2026-11-07 12:18:00", "Video frame 08 review",
         "Video offset 00:17.0: Movement across classroom. Not a real-world timestamp.", "Playback offset from EV-001; review logged on import date", "c7_frame8"),
        ("CASE-007", "2026-11-07 12:30:00", "Fictional witness account",
         "Darishna's scenario report recorded separately from camera observations.", "Scenario witness summary, not authenticated interview", "c7_video"),
        ("CASE-007", "2026-11-07 12:35:00", "Narrative outcome noted",
         "Storyline assigns joint responsibility to Uswa and Fatima; media alone does not prove wrongdoing.", "Fictional scenario conclusion", "c7_lost_report"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", "2026-11-07 12:20:00", "Ledger reference logged",
         "Anonymous account of missing port ledger registered; original provenance unverified.", "Fictional intake entry; not an incident timestamp", "c8_ledger"),
        ("CASE-008", "2026-11-07 12:25:00", "Anonymous tip received",
         "Rehman Dakait and Pablo named by unverified caller.", "Fictional tip entry; not an incident timestamp", "c8_tip"),
        ("CASE-008", "2026-11-07 12:40:00", "Witness review opened",
         "Abdul Wahid and Ali Ahmed nominated for scenario-based interviews.", "Fictional investigator note", "c8_cam"),
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
        # ------------------------------------------------ CASE-006
        ("CASE-006", node("evidence", "c6_spiral"), node("location", "Multiple scenes"), "reported at",
         "A similar symbol is reported at several fictional scenes; origin unverified.", "hiba"),
        ("CASE-006", node("witness", "david"), node("evidence", "c6_cam2"), "can clarify provenance of",
         "CCTV operator can explain camera export and coverage limits.", "hiba"),
        ("CASE-006", node("suspect", "c6_unknown"), node("evidence", "c6_cam1"), "resembles person in",
         "An unidentified figure appears in the fictional CCTV reference.", "maryam"),
        # ------------------------------------------------ CASE-007
        ("CASE-007", node("witness", "darishna"), node("location", "DUET Gulberg classroom corridor"), "reports activity near",
         "Fictional witness account; no authenticated corridor video provided.", "admin"),
        ("CASE-007", node("evidence", "c7_frame2"), node("evidence", "c7_video"), "frame derived from",
         "Extracted image from user-supplied original classroom video at 00:02.5.", "admin"),
        ("CASE-007", node("suspect", "c7_uswa"), node("evidence", "c7_uswa_photo"), "portrait label associated with",
         "Identity label provided with the media; no independent verification.", "admin"),
        ("CASE-007", node("suspect", "c7_fatima"), node("evidence", "c7_fatima_photo"), "portrait label associated with",
         "Identity label provided with the media; no independent verification.", "admin"),
        # ------------------------------------------------ CASE-008
        ("CASE-008", node("witness", "abdul"), node("evidence", "c8_ledger"), "reports observation related to",
         "Fictional ledger-transfer account; no authenticated original yet.", "admin"),
        ("CASE-008", node("witness", "ali"), node("location", "Old Port District"), "reports meeting near",
         "Scenario-based account; participants unidentified.", "admin"),
        ("CASE-008", node("suspect", "c8_rehman"), node("evidence", "c8_tip"), "named in unverified allegation",
         "Anonymous tip alone does not establish involvement.", "admin"),
        ("CASE-008", node("suspect", "c8_pablo"), node("evidence", "c8_tip"), "named in unverified allegation",
         "Anonymous tip alone does not establish involvement.", "admin"),
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

    # ---- additional per-case notes (CASE-006 / CASE-007 / CASE-008)
    additional_notes = [
        ("CASE-006", "Confidentiality risk", "Anonymous messages suggest possible knowledge of the team; audit access lawfully.", "maryam"),
        ("CASE-006", "Administrator recusal", "Administrator is personally connected to the victims and must not direct investigative operations.", "warisha"),
        ("CASE-006", "Signature pattern", "A repeated red spiral marking may be significant or intentionally misleading.", "hiba"),
        ("CASE-006", "Victim link review", "Compare documented contacts, disputes and records without presuming a common offender.", "amna"),
        ("CASE-006", "Independent verification", "Review authenticity of CCTV, anonymous mail, prior complaints and witness claims.", "hiba"),
        ("CASE-007", "Fictional storyline", "Uswa and Fatima are responsible in the scripted scenario only; this is not a claim about real students.", "admin"),
        ("CASE-007", "Unknown incident time", "The supplied video provides playback offsets, not a confirmed filming date or clock time.", "admin"),
        ("CASE-007", "Source versus simulation", "Keep original video and portraits separate from created messages and missing-property report.", "admin"),
        ("CASE-007", "Witness scope", "Darishna's fictional corridor statement is not corroborated by separate corridor footage.", "admin"),
        ("CASE-007", "Identity caution", "Named portrait associations are supplied labels, not independent biometric identification.", "admin"),
        ("CASE-007", "Integrity and privacy", "Preserve original file hashes and confirm permission before making portraits/videos public.", "admin"),
        ("CASE-008", "Unverified association", "Anonymous tip names Rehman Dakait and Pablo; do not treat this as established involvement.", "admin"),
        ("CASE-008", "Witness follow-up", "Interview fictional witnesses Abdul Wahid and Ali Ahmed; compare accounts with independently sourced records.", "admin"),
        ("CASE-008", "Ledger authenticity", "Confirm provenance and meaning of black chess-knight symbol before drawing conclusions.", "admin"),
        ("CASE-008", "Open case", "All entries are fictional placeholders and remain editable; no culprit or real allegation is established.", "admin"),
    ]
    for case_number, title, content, by in additional_notes:
        db.execute(
            "INSERT INTO investigation_notes (case_id, user_id, title, content, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cases[case_number]["id"], users[by]["id"], title, content, stamp, stamp)
        )

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