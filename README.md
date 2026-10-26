# APAAR Verify: Student Data Management and Verification Platform for AICTE

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![SQLModel](https://img.shields.io/badge/SQLModel-0.0.16%2B-indigo.svg)](https://sqlmodel.tiangolo.com)
[![Cryptography](https://img.shields.io/badge/Ed25519-RFC%208032-emerald.svg)](https://cryptography.io)
[![License](https://img.shields.io/badge/SIH-PS%2026263-orange.svg)](#)

> **Smart India Hackathon (SIH) — Problem Statement 26263**  
> An automated, privacy-first APAAR ID-based student verification and data management gateway enabling AICTE to monitor approved intake compliance, detect fraudulent or concurrent multi-institution enrollments, and provide verifiable cryptographic credentials with student-controlled DigiLocker consent.

---

## 1. Executive Summary & Problem Addressed

Currently, central regulators such as AICTE capture student-level records primarily for PGDM programs, while relying on aggregated aggregate numbers for broad technical courses. This regulatory visibility gap creates significant operational risks:
- **Intake Violations:** Institutions exceeding approved program seats without detection.
- **Ghost & Concurrent Enrollments:** The same student simultaneously enrolled full-time at multiple institutions to claim duplicate subsidies or seats.
- **Unverifiable Paper Credentials:** Certificates prone to forging with no cryptographic link to national student registries.
- **Privacy Gaps:** Lack of granular student consent during employer and third-party credential background checks.

**APAAR Verify** resolves these challenges by introducing an end-to-end digital pipeline anchored on the 12-digit **Automated Permanent Academic Account Registry (APAAR) ID**, featuring real-time quota guardrails, explainable anomaly detection, hash-chained audit trails, and Ed25519 cryptographic verifiability.

---

## 2. Requirements & Differentiators Matrix

### 2.1 Core Problem Statement Requirements (R1 – R10)
| ID | Requirement | Implementation in APAAR Verify |
|---|---|---|
| **R1** | 12-digit APAAR Format | Strict ASCII numeric format and checksum validation in `app/validation.py`. |
| **R2** | Student Master Data | Structured records capturing demographics, admission category, mode, year, and quota type. |
| **R3** | Registry Validation | National registry lookup validating existence and active identity status (`app/apaar_registry.py`). |
| **R4** | Intra-Institution Duplicates | Real-time rejection of duplicate APAAR IDs within the same institutional campus. |
| **R5** | Inter-Institution Concurrent Enrollments | Cross-institution detection identifying concurrent full-time admissions across institutions. |
| **R6** | Intake Guard & Seat Meters | 3-state quota engine: **ALLOW** (<90%), **WARN** (90–99%), and **BLOCK** (100% full, requiring formal justification). |
| **R7** | Supernumerary Quota Tracking | AICTE handbook cap enforcement for TFW, EWS, J&K, PMSSS, and NRI allocations. |
| **R8** | Identity Discrepancy Matching | Fuzzy similarity matching on student Name and DOB using Levenshtein distance metrics. |
| **R9** | Central Anomaly Engine | Automated identification of YoY intake surges, NRI outliers, and suspicious DOB clustering. |
| **R10** | Verifiable Credentials & Consent | Digital signing with AICTE Ed25519 root key, QR codes, and 3-tier DigiLocker consent masking. |

### 2.2 Architectural Differentiators (D1 – D7)
1. **D1: Real-Time Intake Guard:** Interactive visual seat meter preventing over-enrollment at upload time.
2. **D2: Hash-Chained Audit Trail:** Tamper-evident SHA-256 chained audit ledger with automated mathematical verification (`verify_chain`).
3. **D3: Ed25519 Verifiable Credentials:** Asymmetric public-key digital signatures (RFC 8032) verifiable offline against published AICTE root public key (`/.well-known/aicte-public-key.pem`).
4. **D4: 3-Tier Consent Privacy Gateway:** Granular disclosure adhering to DPDP Act data minimization principles:
   - **Tier 0:** Valid status confirmed; all personal and directory details withheld.
   - **Tier 1 (Directory):** Institutional roll ID, affiliated college, program, and status disclosed; personal identity hidden.
   - **Tier 2 (Full):** Full academic credential disclosed with authentic verification badge.
5. **D5: Explainable Anomaly Detection:** Rule-based heuristics providing clear, plain-English reasons for every flagged risk.
6. **D6: Multi-Tenant RBAC & Rate Limiting:** Role-based route enforcement for 4 distinct actors with a 30 lookups/min sliding-window rate limiter for third-party verifiers.
7. **D7: Dynamic Policy Engine:** AICTE regulators can adjust intake warning, block, NRI, and YoY surge thresholds dynamically via UI/API without redeployment.

---

## 3. Technology Stack

- **Backend:** Python 3.11+, FastAPI (high-concurrency async ASGI framework)
- **Database Layer:** SQLModel (combining SQLAlchemy Core/ORM with Pydantic schemas)
  - *Default Local Demo:* File-backed SQLite (`apaar.db`)
  - *Automated Test Isolation:* Disposable SQLite test database (`test_apaar.db`)
  - *Remote Capability:* PostgreSQL / Supabase supported via `DATABASE_URL` with connection pool pre-pinging and recycle handling
- **Frontend / UI:** Jinja2 Server-Side Rendered Templates, Tailwind CSS (via CDN), Chart.js (via CDN)
- **Cryptography & Security:** `cryptography` (Ed25519 signing/verification), `hashlib` (SHA-256 audit chaining), `python-jose` / `passlib` (JWT and bcrypt password hashing)
- **Data & QR Utilities:** `pandas` (CSV upload parsing), `rapidfuzz` (fuzzy string matching), `qrcode` (PNG generation)

---

## 4. Setup and Installation

### 4.1 Prerequisites
- Python 3.11, 3.12, or 3.13 installed
- Git installed
- Windows PowerShell, macOS Terminal, or Linux Bash

### 4.2 Step-by-Step Local Deployment
```bash
# 1. Clone repository
git clone https://github.com/KBALAJI-hub/apaar-sih.git
cd apaar-sih

# 2. Create and activate a clean virtual environment
python -m venv venv

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
# source venv/bin/activate

# 3. Install required dependencies
pip install -r requirements.txt

# 4. Install the canonical database snapshot (Offline, 2 seconds)
python scripts/setup_dev_database.py

# 5. Launch the local development server
uvicorn app.main:app --reload
```
Once started, the application will be live at: **http://127.0.0.1:8000**

---

## 5. Demo Credentials

The canonical database (`apaar.db`) is derived directly from the authoritative national AICTE dataset (13,089 institutions, 58,297 programs, 120 signed students):

| Role | Username | Password | Purpose / Organization |
|---|---|---|---|
| **AICTE_ADMIN** | `aicte_admin` | `Admin@123` | Central Regulator Dashboard, Duplicates Panel, Anomaly Alerts |
| **INSTITUTION** | `inst1` *(or `registrar_poly`)* | `Inst@123` | Government Polytechnic Diglipur (A&N Islands — Intake: 120) |
| **INSTITUTION** | `registrar_ambr` | `Inst@123` | Dr. B.R. Ambedkar Institute of Technology |
| **INSTITUTION** | `registrar_ancol`| `Inst@123` | Andaman Nicobar College (ANCOL) |
| **INSTITUTION** | `registrar_jnrm` | `Inst@123` | Jawaharlal Nehru Rajkeeya Mahavidyalaya |
| **INSTITUTION** | `registrar_cipet`| `Inst@123` | Central Institute of Petrochemicals Engineering |
| **VERIFIER** | `employer1` *(or `recruiter_tcs`)* | `Verify@123` | TCS Campus Recruiter / Third-Party Background Verification |
| **STUDENT** | `student1` *(or `student_demo1`)* | `Student@123` | Student Consent Portal (or simulated OTP: `123456`) |

*Maintainer Snapshot Refresh:* Maintainers with Supabase access can refresh the canonical snapshot via `python scripts/sync_supabase_to_sqlite.py`.

---

## 6. 3-Step Guided Demo Walkthrough

### Step 1: Institution Seat Meter & CSV Validation
1. Open **http://127.0.0.1:8000/login** and sign in as `inst1` / `Inst@123`.
2. Observe the real-time **Program Seat Meter** showing current enrollment vs. approved intake.
3. Click **Upload Students (CSV)** and upload `sample_data/bad_upload.csv`.
4. Observe the batch validation summary: clean rows accepted, warnings flagged, fatal errors rejected.
5. Click **Download Error Report CSV** to review row-by-row rule violations (e.g., duplicate APAAR R4, cross-institution concurrent enrollment R5).

### Step 2: Central AICTE Regulator Monitoring
1. Log out and sign in as `aicte_admin` / `Admin@123`.
2. Inspect the **National Compliance Score**, institutional ranking, and live flag tallies.
3. Navigate to **Concurrent Enrollments** (`/aicte/duplicates`) to examine dual-enrollment evidence across multiple institutions.
4. Open **Anomaly Alerts** (`/aicte/anomalies`) to inspect plain-English explanations for YoY enrollment surges and NRI quota outliers.
5. Open **Audit Ledger** (`/aicte/audit`) and click **Verify Chain Integrity** to validate cryptographic SHA-256 hash chaining.

### Step 3: Consent-Aware Verification & Tamper Detection
1. Log in as `employer1` / `Verify@123` at `/verify`.
2. Query student APAAR `100000000008` (Tier 0 Consent) &rarr; notice valid status is confirmed, but personal details are withheld.
3. Open a separate private window, navigate to `/student/consent`, log in as APAAR `100000000008` with OTP `123456`, and change consent to **Tier 2**.
4. Re-query the student in the verifier portal &rarr; full verified credential with authentic badge appears.
5. Click **View Digital Certificate** to inspect the degree credential with embedded Ed25519 signature and live verification QR code.
6. Verify that tampering with any canonical database field immediately flips the public status to **TAMPERED or not found**.

---

## 7. Prototype Boundaries & Transparency Disclosures

To provide honest, transparent prototype boundaries for hackathon evaluation:

1. **Simulated APAAR National Registry:**
   The central APAAR student registry is currently simulated using 850 pre-seeded mock records in the local database. The codebase implements an isolated adapter pattern in `app/apaar_registry.py` (`lookup_apaar`), allowing trivial drop-in replacement with the official Ministry of Education / DigiLocker API when production gateway access is granted.
2. **Simulated DigiLocker OTP Authentication:**
   The student login flow demonstrates consent management using a deterministic OTP (`123456`) to simulate Aadhaar-linked OTP verification without incurring external SMS gateway dependencies during evaluation.
3. **Database Dialect Scope:**
   The prototype is fully stabilized and validated using file-backed SQLite (`apaar.db`) for zero-friction local and offline demonstration. While `app/database.py` includes production connection pooling configurations for Supabase / PostgreSQL, the local demo relies exclusively on SQLite to ensure complete independence from remote network stability.

---

## 8. Automated Test Suites

The repository includes 3 distinct automated test suites with total test isolation (automated tests run against a disposable SQLite database and never modify the primary demo database `apaar.db`):

```bash
# 1. Database selection, connection resilience, and credential redaction tests (8 tests)
python test_db_selection_persistence.py

# 2. Security edge cases, RBAC, consent tiers, and audit-chain integrity (8 tests)
python test_security_edge_cases.py

# 3. Complete Phase 4 integration test checklist covering all 16 end-to-end workflows (16 tests)
python test_phase4_checklist.py
```

All 32 tests pass completely and can be executed multiple times without altering demo records.
