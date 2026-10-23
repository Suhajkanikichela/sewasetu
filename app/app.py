# -*- coding: utf-8 -*-
"""
Sewa Setu - Old Age Pension Portal
Government of Purvanchal, Department of Social Welfare

Developed by: Netlink Infosolutions Pvt Ltd (2023)
Maintenance contract ended 31/01/2026.
"""

import os
import io
import csv
import random
import hashlib
import configparser
from datetime import datetime, date, timedelta

import requests
import psycopg2
from flask import (Flask, request, session, redirect, url_for, render_template,
                   flash, send_file, abort, jsonify)
from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config", "app.ini"))

app = Flask(__name__)
app.secret_key = config.get("app", "secret_key")
app.config["PERMANENT_SESSION_LIFETIME"] = 300

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "sewasetu@123"

SMS_GATEWAY_URL = config.get("app", "sms_gateway_url")
OTP_VALIDITY_SECONDS = config.getint("app", "otp_validity_seconds")
UPLOAD_DIR = config.get("app", "upload_dir")
SCHEME_DEADLINE = datetime.strptime(config.get("pension", "scheme_deadline"),
                                    "%Y-%m-%d %H:%M")
MIN_AGE = config.getint("pension", "min_age")
SLA_DAYS = config.getint("pension", "sla_days")

BLOCKS = ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"]

import logging
_logdir = "/var/log/sewasetu"
try:
    os.makedirs(_logdir, exist_ok=True)
    _fh = logging.FileHandler(os.path.join(_logdir, "sewasetu-app.log"))
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s in app: %(message)s"))
    app.logger.addHandler(_fh)
    app.logger.setLevel(logging.INFO)
except Exception:
    pass


def get_db():
    return psycopg2.connect(
        host=config.get("database", "host"),
        port=config.get("database", "port"),
        dbname=config.get("database", "name"),
        user=config.get("database", "user"),
        password=config.get("database", "password"),
    )


def sanitize(value, maxlen=100):
    # Trim input to safe length. maxlen is in CHARACTERS (not bytes) so that
    # multi-byte scripts (Assamese, Devanagari, etc.) are never cut mid-codepoint.
    # NIC mandate 2019 fixed-width limit was 20 bytes, but that predates Unicode
    # name entry; column width is VARCHAR(100) so we use that as the ceiling.
    if value is None:
        return ""
    return value.strip()[:maxlen]


def hash_password(p):
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def send_sms(mobile, text):
    try:
        requests.post(SMS_GATEWAY_URL + "/api/send",
                      json={"to": mobile, "text": text}, timeout=5)
    except Exception as e:
        app.logger.error("sms gateway error: %s" % e)


def deadline_remaining():
    delta = SCHEME_DEADLINE - datetime.now()
    if delta.total_seconds() <= 0:
        return None
    return int(delta.total_seconds() // 3600)


def new_application_no():
    return "SSP" + datetime.now().strftime("%y") + str(random.randint(100000, 999999))


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", hours_left=deadline_remaining())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/__gateway/", defaults={"subpath": ""})
@app.route("/__gateway/<path:subpath>")
def gateway_proxy(subpath):
    # Convenience proxy to the internal SMS gateway console — admin-only.
    # Previously unauthenticated, which allowed any internet user to read all OTPs
    # and citizen mobile numbers via /api/messages. Restricted to admin session.
    if not session.get("admin"):
        abort(403)
    # Block the /api/messages and /api/send endpoints from the proxy — admin console
    # (the visual inbox at /) is safe to expose; raw API endpoints are not.
    if subpath.startswith("api/"):
        abort(403)
    try:
        r = requests.get(SMS_GATEWAY_URL + "/" + subpath,
                         params=request.args, timeout=5)
        return (r.content, r.status_code,
                {"Content-Type": r.headers.get("Content-Type", "text/html")})
    except Exception as e:
        return ("SMS gateway unreachable: %s" % e, 502)


# ---------------------------------------------------------------------------
# Application flow: mobile -> OTP -> form steps -> upload -> declaration
# ---------------------------------------------------------------------------

@app.route("/apply", methods=["GET", "POST"])
def apply():
    if deadline_remaining() is None:
        flash("The application window for this scheme has closed.")
        return redirect(url_for("index"))
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        captcha = request.form.get("captcha", "")
        if len(mobile) != 10 or not mobile.isdigit():
            flash("Something went wrong. Please try again.")
            return render_template("apply.html", captcha_q=make_captcha())
        code = str(random.randint(100000, 999999))
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO otps (mobile, code, created_at) VALUES (%s, %s, %s)",
                    (mobile, code, datetime.now()))
        conn.commit()
        cur.close(); conn.close()
        send_sms(mobile, "Your Sewa Setu OTP is %s. Valid for 5 minutes." % code)
        session.permanent = True
        session["apply_mobile"] = mobile
        return redirect(url_for("verify"))
    return render_template("apply.html", captcha_q=make_captcha())


def make_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    session["captcha_answer"] = a + b
    return "%d + %d" % (a, b)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    mobile = session.get("apply_mobile")
    if not mobile:
        return redirect(url_for("apply"))
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT code, created_at FROM otps WHERE mobile = %s "
                    "ORDER BY id DESC LIMIT 1", (mobile,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if row and row[0] == code:
            age = (datetime.now() - row[1]).total_seconds()
            if age > OTP_VALIDITY_SECONDS:
                app.logger.warning("otp expired mobile=%s age=%ds" % (mobile, int(age)))
                flash("OTP expired. Please request a new OTP.")
                return redirect(url_for("apply"))
            session["verified_mobile"] = mobile
            return redirect(url_for("form_step", step=1))
        flash("Invalid OTP.")
    return render_template("verify.html", mobile=mobile)


@app.route("/form/<int:step>", methods=["GET", "POST"])
def form_step(step):
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if step not in (1, 2, 3):
        abort(404)
    if request.method == "POST":
        data = session.get("form_data", {})
        for k, v in request.form.items():
            data[k] = v
        session["form_data"] = data
        if step < 3:
            return redirect(url_for("form_step", step=step + 1))
        return redirect(url_for("upload"))
    return render_template("form_step%d.html" % step,
                           data=session.get("form_data", {}), blocks=BLOCKS)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        f = request.files.get("document")
        if f is None or f.filename == "":
            flash("ERR_VAL_47")
            return render_template("upload.html")
        filename = f.filename.lower()
        content = f.read()
        if not filename.endswith(".pdf"):
            flash("ERR_VAL_47")
            return render_template("upload.html")
        if len(content) > 102400:
            flash("ERR_VAL_47")
            return render_template("upload.html")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        path = os.path.join(UPLOAD_DIR, "%s_%s" % (session["verified_mobile"], filename))
        with open(path, "wb") as out:
            out.write(content)
        session["doc_path"] = path
        return redirect(url_for("declaration"))
    return render_template("upload.html")


@app.route("/declaration", methods=["GET", "POST"])
def declaration():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        return handle_submission()
    return render_template("declaration.html")


def handle_submission():
    # TODO: split this up some day. It grew. - RK, 09/2024
    mobile = session.get("verified_mobile")
    data = session.get("form_data", {})
    doc_path = session.get("doc_path", "")

    name = sanitize(data.get("applicant_name", ""))
    village = data.get("village", "").strip()
    block = data.get("block", "").strip()
    gender = data.get("gender", "")
    marital = data.get("marital_status", "")
    husband_name = data.get("husband_name", "")
    husband_employer = data.get("husband_employer", "")
    bank_account = data.get("bank_account", "").strip()
    ifsc = data.get("ifsc", "").strip().upper()
    dob_raw = data.get("dob", "").strip()

    if not name or not village or not block or not bank_account or not dob_raw:
        flash("Something went wrong. Please try again.")
        return redirect(url_for("form_step", step=1))

    if marital == "Widowed":
        if not husband_name or not husband_employer:
            flash("Something went wrong. Please try again.")
            return redirect(url_for("form_step", step=1))

    # Lenient date parsing (CR-2024-117). DD/MM/YYYY is the Indian standard and
    # must be tried FIRST; trying MM/DD first misparses e.g. "05/12/1960" as May 12
    # instead of December 5 for any day ≤ 12.
    dob = None
    for fmt in ("%d/%m/%Y", "%m/%d/%Y"):
        try:
            dob = datetime.strptime(dob_raw, fmt).date()
            break
        except ValueError:
            continue
    if dob is None:
        flash("Something went wrong. Please try again.")
        return redirect(url_for("form_step", step=1))

    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if age < MIN_AGE:
        flash("Applicant must be above %d years of age to be eligible." % MIN_AGE)
        return redirect(url_for("form_step", step=1))

    if datetime.now() > SCHEME_DEADLINE:
        flash("The application deadline has passed.")
        return redirect(url_for("index"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
    if cur.fetchone()[0] > 0:
        cur.close(); conn.close()
        flash("An application already exists for this mobile number. "
              "Duplicate applications are not permitted.")
        return redirect(url_for("index"))

    app_no = new_application_no()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            husband_name, husband_employer, village, block, bank_account, ifsc,
            doc_path, status, submitted_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s)
           RETURNING id""",
        (app_no, name, mobile, dob, gender, marital, husband_name,
         husband_employer, village, block, bank_account, ifsc, doc_path,
         datetime.now()))
    new_id = cur.fetchone()[0]

    # status portal account; password is DOB as DDMMYYYY per dept. circular
    portal_pass = dob.strftime("%d%m%Y")
    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO portal_users (mobile, password_hash) VALUES (%s,%s)",
                    (mobile, hash_password(portal_pass)))
    conn.commit()

    app.logger.info("generating acknowledgment pdf application=%d" % new_id)
    pdf_bytes = generate_acknowledgment(cur, new_id)
    ack_dir = os.path.join(UPLOAD_DIR, "ack")
    os.makedirs(ack_dir, exist_ok=True)
    with open(os.path.join(ack_dir, "%d.pdf" % new_id), "wb") as out:
        out.write(pdf_bytes)

    cur.close(); conn.close()
    session.pop("form_data", None)
    session.pop("doc_path", None)
    session.pop("verified_mobile", None)
    send_sms(mobile, "Sewa Setu: application %s received. Track at the status portal "
                     "with mobile no. and password (DOB as DDMMYYYY)." % app_no)
    return render_template("confirmation.html", app_no=app_no, app_id=new_id)


def _pdf_font_path():
    for path in (
            "/usr/share/fonts/truetype/noto/NotoSansBengali-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansBengali[wght].ttf"):
        if os.path.exists(path):
            return path
    raise RuntimeError("Unicode PDF font is not installed")


def _pdf_latin_font_path():
    path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    if os.path.exists(path):
        return path
    raise RuntimeError("Latin PDF fallback font is not installed")


def generate_acknowledgment(cur, app_id):
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, submitted_at, status FROM applications WHERE id = %s",
                (app_id,))
    row = cur.fetchone()
    pdf = FPDF()
    font_path = _pdf_font_path()
    latin_font_path = _pdf_latin_font_path()
    pdf.add_font("NotoSans", fname=font_path)
    pdf.add_font("NotoSans", style="B", fname=font_path)
    pdf.add_font("NotoSans", style="I", fname=font_path)
    pdf.add_font("DejaVu", fname=latin_font_path)
    pdf.set_fallback_fonts(["DejaVu"])
    pdf.add_page()
    pdf.set_font("NotoSans", "B", 14)
    pdf.cell(0, 10, "GOVERNMENT OF PURVANCHAL", ln=1, align="C")
    pdf.set_font("NotoSans", "", 11)
    pdf.cell(0, 8, "Department of Social Welfare", ln=1, align="C")
    pdf.cell(0, 8, "Old Age Pension Scheme - Acknowledgment", ln=1, align="C")
    pdf.ln(4)
    # Decorative border — simplified from 2000-iteration loop to two rect calls
    pdf.rect(10, 12, 190, 270)
    labels = ["Application No", "Applicant Name", "Mobile", "Date of Birth",
              "Village", "Block", "Bank Account", "IFSC", "Submitted At", "Status"]
    pdf.set_font("NotoSans", "", 10)
    for label, val in zip(labels, row):
        pdf.cell(60, 8, str(label), border=1)
        pdf.cell(0, 8, "" if val is None else str(val), border=1, ln=1)
    pdf.ln(6)
    pdf.set_font("NotoSans", "I", 9)
    pdf.multi_cell(0, 5, "This is a computer generated acknowledgment. Processing SLA "
                         "as per the Purvanchal Right to Public Services Act applies.")
    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# Status portal (citizen login)
# ---------------------------------------------------------------------------

@app.route("/status", methods=["GET", "POST"])
def status_login():
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM portal_users WHERE mobile = %s", (mobile,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if row and row[0] == hash_password(password):
            session["logged_in"] = True
            session["portal_mobile"] = mobile
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM applications WHERE mobile = %s "
                        "ORDER BY submitted_at DESC LIMIT 1", (mobile,))
            r = cur.fetchone()
            cur.close(); conn.close()
            if r:
                return redirect(url_for("view_application", app_id=r[0]))
            flash("No application found for this mobile number.")
            return redirect(url_for("status_login"))
        flash("Something went wrong. Please try again.")
    return render_template("status_login.html")


@app.route("/application/<int:app_id>")
def view_application(app_id):
    if not session.get("logged_in"):
        flash("Please login to view application status.")
        return redirect(url_for("status_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, status, submitted_at, decided_at "
                "FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        abort(404)
    # IDOR fix: citizens must only see their own application.
    # Admin sessions (session["admin"]) may view any application.
    portal_mobile = session.get("portal_mobile")
    if not session.get("admin") and row[2] != portal_mobile:
        abort(403)
    # Compute edit eligibility (24-hour window from submission)
    edit_open = False
    if row[9] and not session.get("admin"):
        edit_open = (datetime.now() - row[9]).total_seconds() < 86400
    return render_template("application.html", a=row, app_id=app_id, edit_open=edit_open)


@app.route("/ack/<int:app_id>.pdf")
def ack_pdf(app_id):
    if not session.get("logged_in"):
        return redirect(url_for("status_login"))
    path = os.path.join(UPLOAD_DIR, "ack", "%d.pdf" % app_id)
    if not os.path.exists(path):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT mobile FROM applications WHERE id = %s", (app_id,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            abort(404)
        if not session.get("admin") and row[0] != session.get("portal_mobile"):
            cur.close(); conn.close()
            abort(403)
        data = generate_acknowledgment(cur, app_id)
        cur.close(); conn.close()
        return send_file(io.BytesIO(data), mimetype="application/pdf")
    if not session.get("admin"):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT mobile FROM applications WHERE id = %s", (app_id,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if not row:
            abort(404)
        if row[0] != session.get("portal_mobile"):
            abort(403)
    return send_file(path, mimetype="application/pdf")


@app.route("/status/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        conn = get_db()
        cur = conn.cursor()
        # SQL injection fix: use parameterized queries (previously used string interpolation)
        cur.execute("SELECT mobile FROM portal_users WHERE mobile = %s", (mobile,))
        row = cur.fetchone()
        if row:
            cur.execute("SELECT dob FROM applications WHERE mobile = %s LIMIT 1", (mobile,))
            r2 = cur.fetchone()
            if r2:
                newpass = r2[0].strftime("%d%m%Y")
                cur.execute("UPDATE portal_users SET password_hash = %s WHERE mobile = %s",
                            (hash_password(newpass), row[0]))
                conn.commit()
                send_sms(row[0], "Sewa Setu: your password has been reset to your "
                                 "date of birth (DDMMYYYY).")
        cur.close(); conn.close()
        flash("If the mobile number exists, the password has been reset and sent by SMS.")
    return render_template("reset.html")


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USERNAME and
                request.form.get("password") == ADMIN_PASSWORD):
            session["logged_in"] = True
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials.")
    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, count(*) FROM applications GROUP BY status")
    by_status = cur.fetchall()
    cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING' "
                "AND submitted_at < %s", (datetime.now() - timedelta(days=SLA_DAYS),))
    overdue = cur.fetchone()[0]
    cur.execute("SELECT block, count(*) FROM applications WHERE status = 'PENDING' "
                "GROUP BY block ORDER BY count(*) DESC")
    by_block = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_dashboard.html", by_status=by_status,
                           overdue=overdue, by_block=by_block, sla=SLA_DAYS)


@app.route("/admin/applications")
def admin_list():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    status = request.args.get("status", "PENDING")
    page = int(request.args.get("page", 1))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, application_no, applicant_name, mobile, block, status, "
                "submitted_at FROM applications WHERE status = %s "
                "ORDER BY submitted_at ASC LIMIT 50 OFFSET %s",
                (status, (page - 1) * 50))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_list.html", rows=rows, status=status, page=page)


@app.route("/admin/application/<int:app_id>")
def admin_view(app_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, gender, "
                "marital_status, village, block, bank_account, ifsc, doc_path, "
                "status, submitted_at, decided_at, decided_by "
                "FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        abort(404)
    return render_template("admin_view.html", a=row, app_id=app_id)


@app.route("/admin/approve/<int:app_id>", methods=["POST"])
def admin_approve(app_id):
    # Session confusion fix: previously checked session["logged_in"] which is also
    # set for citizen portal logins. Now requires session["admin"] explicitly.
    if not session.get("admin"):
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = 'APPROVED', decided_at = %s, "
                "decided_by = %s WHERE id = %s",
                (datetime.now(), session.get("portal_mobile", "admin"), app_id))
    conn.commit()
    cur.close(); conn.close()
    flash("Application approved.")
    return redirect(url_for("admin_list"))


@app.route("/admin/reject/<int:app_id>", methods=["POST"])
def admin_reject(app_id):
    # Session confusion fix: same as admin_approve above.
    if not session.get("admin"):
        abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = 'REJECTED', decided_at = %s, "
                "decided_by = %s WHERE id = %s",
                (datetime.now(), session.get("portal_mobile", "admin"), app_id))
    conn.commit()
    cur.close(); conn.close()
    flash("Application rejected.")
    return redirect(url_for("admin_list"))


@app.route("/application/<int:app_id>/edit", methods=["GET", "POST"])
def edit_application(app_id):
    """24-hour post-submission edit window for minor corrections.
    Allows citizens to fix name, village, bank account, IFSC typos.
    Locked after 24 hours or once status moves beyond PENDING.
    """
    if not session.get("logged_in"):
        flash("Please login to edit your application.")
        return redirect(url_for("status_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT applicant_name, village, bank_account, ifsc, mobile, "
                "status, submitted_at FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        abort(404)
    # IDOR check: only the owning citizen (or admin) may edit
    if not session.get("admin") and row[4] != session.get("portal_mobile"):
        cur.close(); conn.close()
        abort(403)
    # Time-window check: edits only allowed within 24 hours of submission
    submitted_at = row[6]
    age_seconds = (datetime.now() - submitted_at).total_seconds() if submitted_at else 99999
    if age_seconds >= 86400 or row[5] != "PENDING":
        cur.close(); conn.close()
        flash("The edit window has closed. Please contact your Block Development Office.")
        return redirect(url_for("view_application", app_id=app_id))
    if request.method == "POST":
        new_name = sanitize(request.form.get("applicant_name", "").strip())
        new_village = request.form.get("village", "").strip()[:100]
        new_account = request.form.get("bank_account", "").strip()[:30]
        new_ifsc = request.form.get("ifsc", "").strip().upper()[:15]
        if not new_name or not new_village or not new_account:
            flash("All fields are required.")
        else:
            cur.execute(
                "UPDATE applications SET applicant_name=%s, village=%s, "
                "bank_account=%s, ifsc=%s WHERE id=%s",
                (new_name, new_village, new_account, new_ifsc, app_id))
            conn.commit()
            app.logger.info("application_edit app_id=%d by mobile=%s" %
                            (app_id, session.get("portal_mobile")))
            flash("Your application has been updated.")
            cur.close(); conn.close()
            return redirect(url_for("view_application", app_id=app_id))
    cur.close(); conn.close()
    return render_template("edit_application.html",
                           app_id=app_id,
                           applicant_name=row[0], village=row[1],
                           bank_account=row[2], ifsc=row[3],
                           seconds_remaining=int(86400 - age_seconds))


# ---------------------------------------------------------------------------
# Unused / legacy
# ---------------------------------------------------------------------------

def export_to_excel(rows):
    # Was used for the monthly disbursement report before eKosh integration.
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["application_no", "name", "account", "ifsc", "amount"])
    for r in rows:
        writer.writerow(list(r) + ["250"])
    return out.getvalue()


def old_payment_gateway_callback(txn):
    # retained for reference; eChallan integration was descoped in Phase 2
    status = txn.get("STATUS")
    if status == "0300":
        return "SUCCESS"
    elif status == "0399":
        return "FAILED"
    return "PENDING"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
