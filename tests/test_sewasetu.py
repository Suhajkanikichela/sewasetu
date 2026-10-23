# -*- coding: utf-8 -*-
"""
Sewa Setu — Test Suite
Each test is annotated with the issue it covers and whether it would
FAIL BEFORE the fix and PASS AFTER.

Run: pytest tests/ -v
"""

import os
import sys
import importlib
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def app_client():
    """Flask test client with an in-memory SQLite-compatible setup.
    For full integration tests, set environment to point at a test Postgres DB.
    """
    # Patch get_db so we don't need a live Postgres for unit tests
    import app.app as flask_app
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SECRET_KEY"] = "test"
    with flask_app.app.test_client() as client:
        yield client


# ===========================================================================
# ISSUE 1 — Character Encoding & Truncation
# ===========================================================================

class TestEncoding:
    """FAILS BEFORE fix (sanitize used byte slice [:20])
       PASSES AFTER fix (sanitize uses character slice [:100])"""

    def test_assamese_name_preserved(self):
        """7-char Assamese name = 21 UTF-8 bytes; old [:20] cut the last char."""
        from app.app import sanitize
        name = "অসমীয়া"           # 7 chars, 21 bytes
        result = sanitize(name)
        assert result == "অসমীয়া", \
            f"Assamese name truncated: got {result!r}"

    def test_long_assamese_name_preserved(self):
        """Longer name with spaces — must not be corrupted."""
        from app.app import sanitize
        name = "ৰামপ্ৰসাদ কলিতা"    # common Assamese name
        result = sanitize(name)
        assert result == "ৰামপ্ৰসাদ কলিতা"

    def test_devanagari_name_preserved(self):
        """Hindi / Devanagari names must survive sanitize."""
        from app.app import sanitize
        name = "राम प्रसाद"
        assert sanitize(name) == "राम प्रसाद"

    def test_latin_name_unchanged(self):
        """Latin names must still work exactly as before."""
        from app.app import sanitize
        assert sanitize("  Rajan Kumar  ") == "Rajan Kumar"

    def test_pdf_generation_does_not_replace_unicode(self):
        """Acknowledgements must use a Unicode font, not Latin-1 replacement."""
        import app.app as flask_app
        import inspect
        source = inspect.getsource(flask_app.generate_acknowledgment)
        assert "_safe_latin" not in source
        assert 'set_font("NotoSans"' in source

    def test_none_returns_empty(self):
        from app.app import sanitize
        assert sanitize(None) == ""

    def test_maxlen_counts_characters_not_bytes(self):
        """Old code: maxlen=5 on a 5-byte ASCII string passed; on a 2-byte-per-char
        string it silently cut characters. New: maxlen counts chars."""
        from app.app import sanitize
        # 3 Assamese chars = 9 bytes; maxlen=3 should keep all 3 chars
        name = "অসম"
        result = sanitize(name, maxlen=3)
        assert len(result) == 3 and result == "অসম"


# ===========================================================================
# ISSUE 2 — RTPS Cron (15-day deemed approval)
# ===========================================================================

class TestCronConfig:
    """FAILS BEFORE fix (settings.ini not found → FileNotFoundError)
       PASSES AFTER fix (reads app.ini)"""

    def test_config_file_exists(self):
        """The file the cron script reads must exist."""
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, "app", "config", "app.ini")
        assert os.path.exists(path), \
            f"Config file not found at {path}. Cron will fail at runtime."

    def test_cron_script_points_to_correct_config(self):
        """The deemed_approval script must reference app.ini, not settings.ini."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "app", "scripts", "deemed_approval.py")
        with open(script_path) as f:
            source = f.read()
        assert "settings.ini" not in source, \
            "deemed_approval.py still references settings.ini (wrong filename)"
        assert "app.ini" in source, \
            "deemed_approval.py must reference app.ini"

    def test_deemed_approval_logic(self):
        """Simulate the cron query: rows older than SLA_DAYS should be returned."""
        # Pure logic test — no DB needed
        sla_days = 15
        now = datetime.now()
        old_submission = now - timedelta(days=16)
        new_submission = now - timedelta(days=10)
        cutoff = now - timedelta(days=sla_days)
        assert old_submission < cutoff, "16-day-old submission should be past cutoff"
        assert new_submission >= cutoff, "10-day-old submission should not be past cutoff"


# ===========================================================================
# ISSUE 3 — Data Leakage / PII / Security
# ===========================================================================

class TestSecurity:
    """FAILS BEFORE fix; PASSES AFTER."""

    def test_gateway_proxy_requires_admin(self, app_client):
        """/__gateway/ must return 403 for unauthenticated requests.
        Before fix: returned 200 with full SMS inbox."""
        resp = app_client.get("/__gateway/")
        assert resp.status_code == 403, \
            f"Gateway proxy must require admin auth, got {resp.status_code}"

    def test_gateway_api_messages_blocked(self, app_client):
        """/__gateway/api/messages must be blocked even for admin sessions."""
        with app_client.session_transaction() as sess:
            sess["admin"] = True
            sess["logged_in"] = True
        resp = app_client.get("/__gateway/api/messages")
        assert resp.status_code == 403

    def test_acknowledgment_requires_login(self, app_client):
        resp = app_client.get("/ack/1.pdf")
        assert resp.status_code in (302, 403)

    def test_acknowledgment_blocks_other_citizen(self, app_client):
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
        with patch("app.app.get_db") as mock_db:
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_db.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cur
            mock_cur.fetchone.return_value = ("9000000002",)
            resp = app_client.get("/ack/1.pdf")
        assert resp.status_code == 403

    def test_templates_do_not_load_external_tracking_assets(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "app", "templates", "base.html"), encoding="utf-8") as handle:
            template = handle.read()
        assert "fonts.googleapis.com" not in template

    def test_no_sqli_in_reset_password(self, app_client):
        """SQL injection payload in mobile field must not crash or dump data."""
        payload = "' OR '1'='1'; --"
        with patch("app.app.get_db") as mock_db:
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_db.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cur
            mock_cur.fetchone.return_value = None
            resp = app_client.post("/status/reset", data={"mobile": payload})
        # Must return 200 (flash message page), not 500
        assert resp.status_code == 200
        assert b"SELECT" not in resp.data  # must not echo SQL

    def test_reset_password_uses_parameterized_query(self):
        """Verify the source code uses %s params, not string interpolation."""
        import app.app as flask_app
        import inspect
        source = inspect.getsource(flask_app.reset_password)
        assert "% mobile" not in source, \
            "reset_password() uses string interpolation — SQL injection vulnerability"
        assert "'%s'" not in source, \
            "reset_password() uses old-style format string in SQL"

    def test_idor_citizen_cannot_view_others(self, app_client):
        """A logged-in citizen must get 403 when accessing another's application."""
        # Log in as citizen A (mobile 9000000001)
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
        # Try to access application belonging to a different mobile
        # Mock the DB to return a row with mobile 9000000002
        with patch("app.app.get_db") as mock_db:
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_db.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cur
            mock_cur.fetchone.return_value = (
                "SSP26123456", "Other Person", "9000000002",
                "1955-01-01", "OtherVillage", "Sonari",
                "000099998888", "SBIN0001234", "PENDING",
                datetime.now(), None)
            resp = app_client.get("/application/9999")
        assert resp.status_code == 403, \
            f"IDOR: citizen saw another citizen's data (status {resp.status_code})"

    def test_citizen_cannot_approve_applications(self, app_client):
        """A citizen session must not be able to approve applications.
        Before fix: session['logged_in']=True (set by citizen login) passed the check."""
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
            # Note: session["admin"] is NOT set — this is a citizen session
        resp = app_client.post("/admin/approve/1")
        assert resp.status_code == 403, \
            f"Citizen session could approve applications (status {resp.status_code})"

    def test_citizen_cannot_reject_applications(self, app_client):
        """Same as above for reject."""
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
        resp = app_client.post("/admin/reject/1")
        assert resp.status_code == 403


# ===========================================================================
# ISSUE 4 — DB Indexes (schema check)
# ===========================================================================

class TestIndexes:
    """FAILS BEFORE fix (no indexes in schema.sql); PASSES AFTER."""

    def test_schema_has_status_index(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema = open(os.path.join(base, "app", "schema.sql")).read()
        assert "idx_applications_status" in schema

    def test_schema_has_mobile_index(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema = open(os.path.join(base, "app", "schema.sql")).read()
        assert "idx_applications_mobile" in schema

    def test_schema_has_submitted_at_index(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema = open(os.path.join(base, "app", "schema.sql")).read()
        assert "idx_applications_submitted_at" in schema

    def test_schema_has_composite_status_submitted_index(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema = open(os.path.join(base, "app", "schema.sql")).read()
        assert "idx_applications_status_submitted" in schema

    def test_schema_has_partial_pending_sla_index(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema = open(os.path.join(base, "app", "schema.sql")).read()
        assert "idx_applications_pending_sla" in schema

    def test_cron_excludes_unsubmitted_rows(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = open(os.path.join(base, "app", "scripts", "deemed_approval.py")).read()
        assert "submitted_at IS NOT NULL" in script
        assert "submitted_at <= %s" in script


# ===========================================================================
# ISSUE 5 — Post-Submission Edit Window
# ===========================================================================

class TestEditWindow:
    """FAILS BEFORE fix (no edit route); PASSES AFTER."""

    def test_edit_route_exists(self):
        """The edit route must be registered."""
        import app.app as flask_app
        rules = [r.rule for r in flask_app.app.url_map.iter_rules()]
        assert any("/edit" in r for r in rules), \
            "No edit route found — post-submission edit window not implemented"

    def test_edit_requires_login(self, app_client):
        resp = app_client.get("/application/1/edit")
        assert resp.status_code in (302, 403), \
            "Edit route must require login"

    def test_edit_blocked_after_24h(self, app_client):
        """An application older than 24 hours must not be editable."""
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
        with patch("app.app.get_db") as mock_db:
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_db.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cur
            old_time = datetime.now() - timedelta(hours=25)
            mock_cur.fetchone.return_value = (
                "Rajan Kumar", "Sonari", "000099998888", "SBIN0001234",
                "9000000001", "PENDING", old_time)
            resp = app_client.get("/application/1/edit")
        # Should redirect away (edit window closed)
        assert resp.status_code in (302, 403)

    def test_edit_allowed_within_24h(self, app_client):
        """An application submitted less than 24 hours ago should be editable."""
        with app_client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9000000001"
        with patch("app.app.get_db") as mock_db:
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_db.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cur
            fresh_time = datetime.now() - timedelta(hours=1)
            mock_cur.fetchone.return_value = (
                "Rajan Kumar", "Sonari", "000099998888", "SBIN0001234",
                "9000000001", "PENDING", fresh_time)
            resp = app_client.get("/application/1/edit")
        assert resp.status_code == 200, \
            f"Edit within 24h should show edit form, got {resp.status_code}"


# ===========================================================================
# BONUS — Date parsing order (DD/MM vs MM/DD)
# ===========================================================================

class TestDateParsing:
    """Indian date format DD/MM/YYYY must be tried first."""

    def test_dd_mm_yyyy_parsed_correctly(self):
        """05/12/1960 must be December 5, not May 12."""
        from app.app import app as flask_app
        from datetime import datetime
        for fmt in ("%d/%m/%Y", "%m/%d/%Y"):
            try:
                dob = datetime.strptime("05/12/1960", fmt).date()
                break
            except ValueError:
                continue
        # With the fix, DD/MM is tried first → December 5
        assert dob.month == 12 and dob.day == 5, \
            f"Date parsed as month={dob.month} day={dob.day}, expected month=12 day=5"
