
import os
import re
import uuid
import smtplib
import sqlite3

from io import BytesIO
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import urlsplit

from email.message import EmailMessage
from email.utils import parseaddr

from flask import Flask, request, send_from_directory, jsonify, send_file, session
from flask_cors import CORS

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

app.secret_key = os.environ.get(
    "DEEPSHIELD_SECRET_KEY",
    "LOCAL-ONLY-change-this-secret-before-deployment"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "DEEPSHIELD_HTTPS", "0"
    ) == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_REFRESH_EACH_REQUEST=True
)

DEV_ORIGINS = [
    f"http://{host}:{port}"
    for host in ("127.0.0.1", "localhost")
    for port in range(5500, 5511)
]

CORS(
    app,
    supports_credentials=True,
    resources={r"/api/*": {"origins": DEV_ORIGINS}}
)


# ==========================================
# PDF COLORS
# ==========================================

BG = colors.HexColor("#071018")
NAVY = colors.HexColor("#0B1B26")
CYAN = colors.HexColor("#00CFE3")
GREEN = colors.HexColor("#00C987")
AMBER = colors.HexColor("#F0B44D")
RED = colors.HexColor("#F05A75")
MUTED = colors.HexColor("#647985")
INK = colors.HexColor("#15232D")


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def safe(value, limit=1000):
    return str(
        value if value is not None else "Not provided"
    ).replace("\x00", "")[:limit]


def valid_email(value):

    email = safe(value, 254).strip()
    _, parsed = parseaddr(email)

    return (
        parsed == email
        and bool(
            re.fullmatch(
                r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
                email
            )
        )
    )


# ==========================================
# PDF TIMESTAMP FORMAT
# ==========================================


def format_scan_timestamp(value):
    """
    Format:
    DD/MM/YYYY, HH:MM:SS AM/PM IST
    """

    # India Standard Time (UTC + 5:30)
    IST = timezone(timedelta(hours=5, minutes=30))

    try:
        raw = str(value or "").strip()

        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"

        parsed = datetime.fromisoformat(raw)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        local_time = parsed.astimezone(IST)

        return local_time.strftime(
            "%d/%m/%Y, %I:%M:%S %p IST"
        )

    except (ValueError, TypeError, OverflowError):
        return datetime.now(IST).strftime(
            "%d/%m/%Y, %I:%M:%S %p IST"
        )


# ==========================================
# PDF GENERATION
# ==========================================

def build_pdf(data, report_id):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="DeepShield Cyber Intelligence Report",
        author="DeepShield"
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="BodyDS",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=13,
            textColor=colors.HexColor("#425762"),
            spaceAfter=4
        )
    )

    styles.add(
        ParagraphStyle(
            name="MutedDS",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7,
            leading=10,
            textColor=MUTED
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionDS",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=INK,
            spaceBefore=12,
            spaceAfter=7
        )
    )

    styles.add(
        ParagraphStyle(
            name="WhiteDS",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.white
        )
    )

    styles.add(
        ParagraphStyle(
            name="VerdictDS",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.white
        )
    )

    # Scan information

    score = max(
        0,
        min(100, int(data.get("risk_score", 0)))
    )

    verdict = safe(data.get("verdict", "Not classified"), 100)
    url = safe(data.get("url"), 1000)

    explanation = safe(
        data.get("explanation", "No explanation supplied."),
        1500
    )

    reasons = data.get("reasons", [])

    if isinstance(reasons, list):
        reasons = [
            safe(x, 250) for x in reasons[:20]
        ]
    else:
        reasons = []

    confidence = data.get("confidence")

    if isinstance(confidence, (int, float)):
        confidence_text = f"{float(confidence):.1f}%"
    else:
        confidence_text = "Not available"

    scanned = format_scan_timestamp(
        data.get("scanned_at")
        or datetime.now(timezone.utc).isoformat()
    )

    mode = safe(data.get("mode", "Backend analysis"), 60)

    accent = (
        RED if score >= 50
        else AMBER if score >= 25
        else GREEN
    )

    def esc(value):
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    story = []

    # PDF header

    header = Table(
        [[
            Paragraph(
                '<font color="#00CFE3"><b>DEEP</b></font>'
                '<font color="#FFFFFF"><b>SHIELD</b></font><br/>'
                '<font color="#AFC4CE" size="6">'
                'CYBER THREAT INTELLIGENCE</font>',
                styles["WhiteDS"]
            ),

            Paragraph(
                '<font color="#00CFE3">'
                'CYBER INTELLIGENCE REPORT</font><br/>'
                f'<font color="#AFC4CE" size="6">'
                f'REPORT ID: {report_id}</font>',
                styles["MutedDS"]
            )
        ]],
        colWidths=[90 * mm, 85 * mm]
    )

    header.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG),
            ("BOX", (0, 0), (-1, -1), 0.8,
             colors.HexColor("#1C4653")),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 13),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT")
        ])
    )

    story += [
        header,
        Spacer(1, 9 * mm),
        Paragraph("WEBSITE INVESTIGATION", styles["MutedDS"]),
        Spacer(1, 2 * mm)
    ]

    # Risk score panel

    verdict_box = Table(
        [[
            Paragraph(
                f"<font color='#FFFFFF'><b>"
                f"{esc(verdict.upper())}</b></font><br/>"
                f"<font color='#B6C8D0' size='8'>"
                f"Automated assessment · {esc(mode)}</font>",
                styles["VerdictDS"]
            ),

            Paragraph(
                f"<font color='#FFFFFF' size='25'>"
                f"<b>{score:02d}</b></font><br/>"
                f"<font color='#B6C8D0' size='7'>"
                f"RISK SCORE / 100</font>",
                styles["WhiteDS"]
            )
        ]],
        colWidths=[112 * mm, 63 * mm]
    )

    verdict_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), NAVY),
            ("BOX", (0, 0), (-1, -1), 1, accent),
            ("LINEBEFORE", (1, 0), (1, 0), 0.7,
             colors.HexColor("#31505C")),
            ("LEFTPADDING", (0, 0), (-1, -1), 13),
            ("RIGHTPADDING", (0, 0), (-1, -1), 13),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "CENTER")
        ])
    )

    story += [
        verdict_box,
        Spacer(1, 4 * mm),
        Paragraph("TARGET DETAILS", styles["SectionDS"])
    ]

    # Target details

    rows = [
        [
            Paragraph("<b>Scanned URL</b>", styles["BodyDS"]),
            Paragraph(esc(url), styles["BodyDS"])
        ],
        [
            Paragraph("<b>Scan timestamp</b>", styles["BodyDS"]),
            Paragraph(esc(scanned), styles["BodyDS"])
        ],
        [
            Paragraph("<b>Model confidence</b>", styles["BodyDS"]),
            Paragraph(confidence_text, styles["BodyDS"])
        ],
        [
            Paragraph("<b>Analysis mode</b>", styles["BodyDS"]),
            Paragraph(esc(mode), styles["BodyDS"])
        ]
    ]

    details_table = Table(
        rows,
        colWidths=[43 * mm, 132 * mm]
    )

    details_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1),
             colors.HexColor("#F1F5F7")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [
                colors.HexColor("#F1F5F7"),
                colors.white
            ]),
            ("BOX", (0, 0), (-1, -1), 0.5,
             colors.HexColor("#D5E0E5")),
            ("INNERGRID", (0, 0), (-1, -1), 0.35,
             colors.HexColor("#D5E0E5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(details_table)

    # Security indicators

    story.append(
        Paragraph("SECURITY INDICATORS", styles["SectionDS"])
    )

    if not reasons:
        reasons = [
            "No suspicious URL patterns were returned by the current analysis."
        ]

    indicator_rows = [
        [
            Paragraph(
                "<b>INDICATOR / EXPLANATION</b>",
                styles["BodyDS"]
            )
        ]
    ]

    for reason in reasons:
        indicator_rows.append([
            Paragraph(
                "• " + esc(reason),
                styles["BodyDS"]
            )
        ])

    indicator_table = Table(
        indicator_rows,
        colWidths=[175 * mm]
    )

    indicator_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#E4EEF2")),
            ("BOX", (0, 0), (-1, -1), 0.5,
             colors.HexColor("#D5E0E5")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3,
             colors.HexColor("#E0E8EC")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ])
    )

    story.append(indicator_table)

    # Explainable analysis

    story.append(
        Paragraph("EXPLAINABLE ANALYSIS", styles["SectionDS"])
    )

    explanation_table = Table(
        [[Paragraph(esc(explanation), styles["BodyDS"])]],
        colWidths=[175 * mm]
    )

    explanation_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1),
             colors.HexColor("#F1EFF8")),
            ("BOX", (0, 0), (-1, -1), 0.7,
             colors.HexColor("#C8B8E8")),
            ("LINEBEFORE", (0, 0), (0, 0), 3,
             colors.HexColor("#8766C5")),
            ("LEFTPADDING", (0, 0), (-1, -1), 11),
            ("RIGHTPADDING", (0, 0), (-1, -1), 11),
            ("TOPPADDING", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9)
        ])
    )

    story += [
        explanation_table,
        Spacer(1, 7 * mm),

        Paragraph(
            "<b>SAFETY NOTE</b> — This report is an automated "
            "assessment, not a guarantee. A low-risk result does "
            "not prove a website is safe. Verify important links "
            "through the organisation's official website.",
            styles["BodyDS"]
        ),

        Spacer(1, 5 * mm),

        HRFlowable(
            width="100%",
            thickness=0.7,
            color=colors.HexColor("#C8D6DC")
        ),

        Spacer(1, 3 * mm),

        Paragraph(
            "Generated by DeepShield · "
            "AI-Based Phishing Website Detection",
            styles["MutedDS"]
        )
    ]

    # Page decoration

    def decorate(canvas, doc):

        canvas.saveState()

        width, height = A4

        canvas.setFillColor(BG)
        canvas.rect(
            0, height - 5 * mm,
            width, 5 * mm,
            fill=1, stroke=0
        )

        canvas.setStrokeColor(
            colors.HexColor("#D9E3E7")
        )

        canvas.line(
            18 * mm, 12 * mm,
            width - 18 * mm, 12 * mm
        )

        canvas.setFont("Courier", 6)
        canvas.setFillColor(MUTED)

        canvas.drawString(
            18 * mm, 8 * mm,
            "DEEPSHIELD // SCAN REPORT"
        )

        canvas.drawRightString(
            width - 18 * mm, 8 * mm,
            f"PAGE {doc.page}"
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=decorate,
        onLaterPages=decorate
    )

    return buffer.getvalue()


# ==========================================
# EMAIL SENDING
# ==========================================

def send_email(to_email, pdf_bytes, report_id, data):

    sender = os.environ.get("SMTP_USER", "").strip()

    password = os.environ.get(
        "SMTP_APP_PASSWORD", ""
    ).replace(" ", "")

    host = os.environ.get(
        "SMTP_HOST", "smtp.gmail.com"
    ).strip()

    port = int(os.environ.get("SMTP_PORT", "465"))

    security = os.environ.get(
        "SMTP_SECURITY", "ssl"
    ).strip().lower()

    if not sender or not password:
        raise RuntimeError(
            "Email is not configured. Set SMTP_USER and "
            "SMTP_APP_PASSWORD."
        )

    if security not in ("ssl", "starttls", "none"):
        raise RuntimeError(
            "SMTP_SECURITY must be ssl, starttls or none."
        )

    message = EmailMessage()

    message["Subject"] = (
        "Your DeepShield Cyber Intelligence Report"
    )

    message["From"] = sender
    message["To"] = to_email
    message["Reply-To"] = sender

    message.set_content(
        "Hello,\n\n"
        "Your DeepShield cyber intelligence report "
        "is attached as a PDF.\n"
        f"Report ID: {report_id}\n"
        f"Website: {safe(data.get('url'))}\n"
        f"Assessment: {safe(data.get('verdict'))}\n\n"
        "A low-risk result is not a guarantee that "
        "a website is safe.\n\n"
        "DeepShield Security Team"
    )

    message.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename="DeepShield_Cyber_Intelligence_Report.pdf"
    )

    if security == "ssl":

        with smtplib.SMTP_SSL(
            host, port, timeout=25
        ) as server:

            server.login(sender, password)
            server.send_message(message)

    else:

        with smtplib.SMTP(
            host, port, timeout=25
        ) as server:

            server.ehlo()

            if security == "starttls":
                server.starttls()
                server.ehlo()

            server.login(sender, password)
            server.send_message(message)


# ==========================================
# DATABASE
# ==========================================

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "deepshield.db"
)


def db_connection():

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    with db_connection() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                country TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)


def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    with db_connection() as db:

        row = db.execute(
            "SELECT id, name, country, email "
            "FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    return dict(row) if row else None


# ==========================================
# SCAN VALIDATION
# ==========================================

def validate_scan(data):

    url = safe(data.get("url"), 1000).strip()

    try:

        parsed_url = urlsplit(url)

        valid_url = (
            parsed_url.scheme in ("http", "https")
            and bool(parsed_url.hostname)
            and not parsed_url.username
            and not parsed_url.password
        )

    except ValueError:
        valid_url = False

    if not valid_url:
        return None, "Enter a valid HTTP or HTTPS website URL."

    try:
        score = int(data.get("risk_score", -1))
    except (TypeError, ValueError):
        return None, "Invalid risk score."

    if not 0 <= score <= 100:
        return None, "Risk score must be between 0 and 100."

    return {
        "url": url,
        "risk_score": score,
        "verdict": safe(
            data.get("verdict", "Not classified"), 100
        ),
        "reasons": data.get("reasons", []),
        "explanation": safe(
            data.get("explanation", "No explanation supplied."),
            1500
        ),
        "confidence": data.get("confidence"),
        "mode": safe(
            data.get("mode", "Backend analysis"), 60
        ),
        "scanned_at": safe(
            data.get("scanned_at")
            or datetime.now(timezone.utc).isoformat(),
            80
        )
    }, None


# ==========================================
# HEALTH CHECK
# ==========================================
@app.get("/")
def home():
    return send_from_directory(".", "index.html")
@app.get("/style.css")
def css():
    return send_from_directory(".", "style.css")


@app.get("/script.js")
def javascript():
    return send_from_directory(".", "script.js")


@app.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory("assets", filename)

@app.get("/api/health")
def health():

    return jsonify(
        status="ok",
        service="DeepShield API"
    )


# ==========================================
# ACCOUNT REGISTRATION
# ==========================================

@app.post("/api/auth/register")
def register():

    data = request.get_json(silent=True) or {}

    name = safe(data.get("name"), 100).strip()
    country = safe(data.get("country"), 80).strip()
    email = safe(data.get("email"), 254).strip().lower()
    password = str(data.get("password") or "")

    if not name or not country or not valid_email(email):

        return jsonify(
            error="Enter your name, country and a valid email address."
        ), 400

    if len(password) < 8:

        return jsonify(
            error="Password must contain at least 8 characters."
        ), 400

    try:

        with db_connection() as db:

            cursor = db.execute(
                """
                INSERT INTO users
                (name, country, email, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    name,
                    country,
                    email,
                    generate_password_hash(password),
                    datetime.now(timezone.utc).isoformat()
                )
            )

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:

        return jsonify(
            error="An account with this email already exists. Please log in."
        ), 409

    session.clear()
    session["user_id"] = user_id
    session.permanent = True

    return jsonify(
        success=True,
        user=current_user()
    ), 201


# ==========================================
# ACCOUNT LOGIN
# ==========================================

@app.post("/api/auth/login")
def login():

    data = request.get_json(silent=True) or {}

    email = safe(data.get("email"), 254).strip().lower()
    password = str(data.get("password") or "")

    with db_connection() as db:

        user = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password
    ):

        return jsonify(
            error="Incorrect email or password."
        ), 401

    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True

    return jsonify(
        success=True,
        user=current_user()
    )


# ==========================================
# CHECK LOGIN SESSION
# ==========================================

@app.get("/api/auth/me")
def auth_me():

    return jsonify(user=current_user())


# ==========================================
# LOGOUT
# ==========================================

@app.post("/api/auth/logout")
def logout():

    session.clear()

    return jsonify(
        success=True,
        message="Logged out."
    )


# ==========================================
# SAVE SCAN HISTORY
# ==========================================

@app.post("/api/scans")
def save_scan():

    user = current_user()

    if not user:

        return jsonify(
            error="Log in to save scan history."
        ), 401

    data = request.get_json(silent=True) or {}

    scan, error = validate_scan(data)

    if error:
        return jsonify(error=error), 400

    created = datetime.now(timezone.utc).isoformat()

    with db_connection() as db:

        db.execute(
            """
            INSERT INTO scans
            (user_id, url, risk_score, verdict, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                scan["url"],
                scan["risk_score"],
                scan["verdict"],
                created
            )
        )

    return jsonify(
        success=True,
        message="Scan saved to account history."
    )


# ==========================================
# GET PREVIOUS SCAN HISTORY
# ==========================================

@app.get("/api/scans")
def scan_history():

    user = current_user()

    if not user:

        return jsonify(
            error="Please log in to view scan history."
        ), 401

    with db_connection() as db:

        rows = db.execute(
            """
            SELECT url, risk_score, verdict, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (user["id"],)
        ).fetchall()

    return jsonify(
        scans=[dict(row) for row in rows]
    )


# ==========================================
# DIRECT PDF DOWNLOAD
# ==========================================

@app.post("/api/report/pdf")
def direct_pdf_download():

    data = request.get_json(silent=True) or {}

    scan, error = validate_scan(data)

    if error:
        return jsonify(error=error), 400

    report_id = uuid.uuid4().hex[:12].upper()

    pdf_bytes = build_pdf(scan, report_id)

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="DeepShield_Cyber_Intelligence_Report.pdf"
    )


# ==========================================
# SEND PDF THROUGH EMAIL
# ==========================================

@app.post("/api/report/email")
def email_report():

    data = request.get_json(silent=True) or {}

    email = safe(data.get("email"), 254).strip()

    if not valid_email(email):

        return jsonify(
            error="Please provide a valid email address."
        ), 400

    scan, error = validate_scan(data)

    if error:
        return jsonify(error=error), 400

    report_id = uuid.uuid4().hex[:12].upper()

    pdf_bytes = build_pdf(scan, report_id)

    try:

        send_email(
            email,
            pdf_bytes,
            report_id,
            scan
        )

    except Exception as exc:

        app.logger.exception("Email delivery failed")

        message = (
            str(exc)
            if isinstance(exc, RuntimeError)
            else
            "Email delivery failed. Check SMTP host, port, "
            "security mode, sender credentials and internet connection."
        )

        return jsonify(error=message), 502

    return jsonify(
        success=True,
        report_id=report_id,
        message="Report emailed successfully."
    )


# ==========================================
# INITIALIZE DATABASE
# ==========================================

init_db()


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
