-- Sewa Setu Old Age Pension Portal - schema
-- NOTE: seed.sql (shipped separately) loads after this and contains the
-- production data. Do not re-run against a live database.

CREATE TABLE IF NOT EXISTS applications (
    id              SERIAL PRIMARY KEY,
    application_no  VARCHAR(20),
    applicant_name  VARCHAR(100),
    mobile          VARCHAR(15),
    dob             DATE,
    gender          VARCHAR(10),
    marital_status  VARCHAR(20),
    husband_name    VARCHAR(100),
    husband_employer VARCHAR(100),
    village         VARCHAR(100),
    block           VARCHAR(50),
    bank_account    VARCHAR(30),
    ifsc            VARCHAR(15),
    doc_path        VARCHAR(200),
    status          VARCHAR(20) DEFAULT 'PENDING',
    submitted_at    TIMESTAMP,
    decided_at      TIMESTAMP,
    decided_by      VARCHAR(50)
);

-- Status portal accounts (created at submission time)
CREATE TABLE IF NOT EXISTS portal_users (
    mobile        VARCHAR(15) PRIMARY KEY,
    password_hash VARCHAR(80)
);

CREATE TABLE IF NOT EXISTS otps (
    id         SERIAL PRIMARY KEY,
    mobile     VARCHAR(15),
    code       VARCHAR(6),
    created_at TIMESTAMP
);

-- Performance indexes (Issue #4 fix)
-- These are safe to run on a live database using CREATE INDEX CONCURRENTLY
-- (remove CONCURRENTLY if running during initial setup / docker-entrypoint-initdb.d).

-- Admin dashboard GROUP BY status, overdue count filter
CREATE INDEX IF NOT EXISTS idx_applications_status
    ON applications (status);

-- Admin list page: WHERE status + ORDER BY submitted_at (covers pagination too)
CREATE INDEX IF NOT EXISTS idx_applications_status_submitted
    ON applications (status, submitted_at);

-- Citizen portal and duplicate-check: WHERE mobile
CREATE INDEX IF NOT EXISTS idx_applications_mobile
    ON applications (mobile);

-- RTPS cron job: WHERE status='PENDING' AND submitted_at < cutoff
CREATE INDEX IF NOT EXISTS idx_applications_submitted_at
    ON applications (submitted_at);

-- OTP lookup: WHERE mobile ORDER BY id DESC
CREATE INDEX IF NOT EXISTS idx_otps_mobile
    ON otps (mobile);

