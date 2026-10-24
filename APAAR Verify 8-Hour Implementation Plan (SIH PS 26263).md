# APAAR Verify: 8-Hour Implementation Plan

SIH PS 26263 | APAAR ID-Based Student Data Management and Verification Platform for AICTE | Team of 3-4 | 8 hours

## 1. Strategy in One Minute

1. **Build one complete vertical slice, not a half-built everything.** The pipeline from the problem statement must work end to end: Institution → Student Data Upload → APAAR Validation → Data Verification → AICTE Central Repository → Analytics and Monitoring → Authorized Verification.
2. **Mock APAAR registry behind an adapter.** The real APAAR/DigiLocker registry is not publicly accessible. Build a table of fake APAAR IDs behind `apaar_registry.py` and say on the slides: plug-in point for the real API. Judges respect honest boundaries.
3. **Detect AND prevent.** Most teams will only flag problems after upload. We add preventive controls (Intake Guard) and tamper-evident trust features.
4. **Hard feature freeze at Hour 5:30.** The last 2.5 hours are for testing, PPT, video and submission. No exceptions.
5. **Write down the real clock times now.** Note the current time as T0 and the 12 PM deadline. If you have less or more than 8 hours, scale every hour mark proportionally (freeze at about 70% of the time).

## 2. How We Stand Out (Differentiators)

Every item below is cheap to build and easy to show in a demo. Each maps to the Innovation Expected paragraph of the problem statement.

| # | Differentiator | What it is | Build cost |
| --- | --- | --- | --- |
| D1 | **Intake Guard (preventive)** | Live seat meter per program. A pre-admission check endpoint returns ALLOW / WARN / BLOCK before an institution exceeds approved intake. Others only detect after the fact. | 45 min |
| D2 | **Cross-institution duplicate evidence panel** | Same APAAR ID active at two institutions: show both enrolments side by side with dates, and let AICTE mark one as confirmed or resolved. | 30 min |
| D3 | **Signed Verifiable Student Record** | Ed25519 digital signature over a canonical record. QR links to a public verify page. Public key published at `/.well-known/aicte-public-key.pem`, so anyone can verify independently. Tamper demo: edit the DB, QR shows TAMPERED. | 60 min |
| D4 | **Consent-aware tiered disclosure** | Student grants consent via a simulated OTP flow. Verifier sees Tier 0 (valid or not), Tier 1 (institution, program, year, status) or Tier 2 (full record) depending on consent and verifier role. Student sees a Who looked me up log. Verifier lookups are rate-limited. | 60 min |
| D5 | **Hash-chained audit log** | Each audit row stores the hash of the previous row. An Verify integrity button on the admin audit page proves no row was altered or deleted. | 20 min |
| D6 | **Explainable anomaly engine plus Compliance Score** | Rules plus z-score plus IsolationForest. Every alert has a plain-English reason and a recommended action. Each institution gets a 0-100 compliance score and a risk rank. | 75 min |
| D7 | **Config-driven rules** | Admin settings page for thresholds (supernumerary %, NRI share limit, surge %, fill-ratio limit). Policy changes need no code change. | 20 min |

**Stretch only if time remains after freeze-ready state:** webhook callback on HIGH flags, upload data-quality score, templated Ask the data queries.

## 3. Requirement Traceability (judges will check this)

| Req | Requirement | Where it is satisfied |
| --- | --- | --- |
| 1 | Secure platform/API for student-level upload and update using APAAR ID | Institution portal (form and CSV), REST API `POST /api/v1/students/bulk`, edit and update flows |
| 2 | Fields: Approved Intake, Actual Enrolment, Supernumerary, NRI, OCI, FN, other | `Program.approved_intake`, `supernumerary_cap`; `Student` fields `admission_type`, `is_nri`, `oci_status`, `is_foreign_national`, nationality, category, etc.; actual enrolment computed live |
| 3 | Automated validation: duplicates, invalid/missing APAAR, intake exceeded, inconsistencies, cross-institution duplicates | Validation engine rules R1-R12 plus Intake Guard |
| 4 | Dashboards for AICTE and institutions, real time | Two dashboards with 10-second auto-refresh |
| 5 | Secure verification for AICTE, institutions, employers, regulators | Verification portal with roles, tiers, consent, rate limiting |
| 6 | Verifiable student records linked to academic identity | Ed25519-signed record, QR, public verify page, public key |
| 7 | Integration/API with institutional and AICTE systems | Versioned REST API, per-institution API keys, Swagger at `/docs`, registry adapter |
| 8 | Security, privacy, authentication, RBAC, audit, consent | JWT cookie auth, bcrypt, 4 roles, hash-chained audit log, simulated OTP consent, rate limits |
| 9 | Reports for policy, accreditation, monitoring, regulatory use | CSV exports plus printable Compliance Summary and State-wise Summary |
| 10 | Print APAAR ID with student ID on certificates | Printable certificate template with Student ID, APAAR ID, QR and signature |
| Innovation | Automated validation, anomaly detection, real-time monitoring, secure verification, analytics | D1-D7 |

## 4. Tech Stack and Architecture

| Layer | Choice | Reason |
| --- | --- | --- |
| Backend | Python 3.11, FastAPI | Swagger docs for free (Req 7), LLMs write it well |
| ORM and DB | SQLModel. `DATABASE_URL` env var: **defaults to local SQLite**, set to Supabase PostgreSQL (Session Pooler string, Mumbai region) for the shared demo | Zero-setup local dev, shared Postgres for final demo, same code on both |
| Frontend | Jinja2 templates, Tailwind CSS (CDN), Chart.js (CDN) | No build step |
| Auth | JWT in HttpOnly SameSite=Lax cookie, bcrypt (pin `bcrypt==4.0.1`) | Simple RBAC dependency |
| Data | pandas | CSV parsing |
| Signing | `cryptography` (Ed25519) | Independent verifiability |
| QR | `qrcode[pil]` | Verify links on records and certificates |
| ML | scikit-learn IsolationForest | Anomaly score |
| Fake data | Faker (en\_IN) | Seeding |

**Do not use:** React, Docker, microservices, Redis, Celery, blockchain, real OTP/SMS. They cost time and add nothing to the score.

**Database notes:** Supabase direct connections are IPv6-only on the free tier and often fail on Indian networks, so use the Session Pooler connection string. Enable Row Level Security on all tables (no policies) so Supabase's auto-generated API cannot expose data; FastAPI connects as the postgres role and is unaffected. Load registry and existing APAAR IDs into in-memory sets during bulk validation to avoid hundreds of network round trips.

### Architecture

```
[Institution Portal: form/CSV]   [Institution ERP: REST + API key]
              \                      /
               v                    v
        +-------------------------------------+
        |        FastAPI Application          |
        |  Auth + RBAC + Rate limit + Audit   |
        |  Intake Guard | Validation Engine   |
        |  Anomaly Engine | Signing + QR      |
        +------+------------------+-----------+
               |                  |
    APAAR Registry Adapter   AICTE Central Repository (DB)
    (Mock now / real API)       |             |
                         Analytics &     Verification Portal/API
                         Dashboards      (consent-aware tiers)
                         Reports         Employers, Regulators, Students
```

## 5. Data Model

| Table | Key fields |
| --- | --- |
| `User` | id, username, password\_hash, role (AICTE\_ADMIN, INSTITUTION, VERIFIER, STUDENT), institution\_id, apaar\_id (students only), full\_name |
| `Institution` | id, aicte\_id, name, state, type, api\_key |
| `Program` | id, institution\_id, name, level, academic\_year, approved\_intake, supernumerary\_cap |
| `ApaarRegistry` (mock) | apaar\_id (12 digits, unique), full\_name, dob, gender |
| `Student` | id, apaar\_id, institution\_id, program\_id, student\_id (roll no.), full\_name, dob, gender, category, admission\_type (REGULAR/SUPERNUMERARY), is\_nri, oci\_status, is\_foreign\_national, nationality, admission\_year, mode (FULL\_TIME/PART\_TIME), status (ACTIVE/WITHDRAWN/GRADUATED), consent\_level (0/1/2), consent\_timestamp, record\_signature, created\_at, updated\_at |
| `ValidationFlag` | id, institution\_id, program\_id, student\_id, rule\_code, severity, message, recommended\_action, status (OPEN/RESOLVED), created\_at |
| `AnomalyAlert` | id, institution\_id, code, score, reason, created\_at |
| `AuditLog` | id, user\_id, username, action, entity, entity\_id, details, timestamp, prev\_hash, row\_hash |
| `VerificationLog` | id, verifier\_id, apaar\_id, tier\_shown, result, timestamp |
| `Setting` | key, value (thresholds for D7) |

## 6. Validation and Anomaly Rules

### Validation rules (all produce a flag with severity, message and recommended action)

| Code | Rule | Severity | Level |
| --- | --- | --- | --- |
| R1 | APAAR missing or not exactly 12 digits | HIGH (reject row) | Row |
| R2 | APAAR not found in registry | HIGH (reject row) | Row |
| R3 | Name fuzzy mismatch or DOB mismatch vs registry | MEDIUM | Row |
| R4 | Duplicate APAAR within the same institution | HIGH | Row |
| R5 | Same APAAR actively enrolled full-time at another institution | HIGH | Cross |
| R6 | Regular admissions exceed approved intake | HIGH | Program |
| R7 | Supernumerary admissions exceed cap | MEDIUM | Program |
| R8 | Inconsistency: NRI and FN both true; FN with nationality India; OCI with nationality India; implausible age; future admission year | MEDIUM | Row |
| R9 | Mandatory fields missing (name, DOB, program, admission year) | HIGH (reject row) | Row |
| R10 | Consent not captured | LOW | Row |
| R11 | Program not found for this institution and year | HIGH (reject row) | Row |
| R12 | Duplicate student\_id (roll no.) within institution | MEDIUM | Row |

Rows with R1, R2, R9 or R11 are rejected and listed in a downloadable error CSV. All other rows are accepted with flags. Supernumerary cap default is configurable. **Check the current AICTE Approval Process Handbook for actual quota categories and percentages** and quote it on the slide.

### Intake Guard (D1)

`GET /api/v1/programs/{id}/intake-check` returns remaining seats and a decision: ALLOW (under 90%), WARN (90-100%), BLOCK (would exceed). The institution form shows a live seat meter and requires a justification text to override a BLOCK, which is itself logged and flagged HIGH.

### Anomaly engine

| Code | Check | Method |
| --- | --- | --- |
| A1 | Fill ratio outlier vs peers | z-score above 2 or ratio above 1.0 |
| A2 | Year-on-year surge | growth above configured % |
| A3 | Abnormal NRI/FN/OCI share | above threshold or z-score above 2 vs same institution type |
| A4 | Suspicious cluster | many students sharing one DOB in one program |
| A5 | IsolationForest | on fill\_ratio, nri\_share, fn\_share, yoy\_growth, flag\_rate per institution |

**Compliance Score** = 100 minus weighted penalties (HIGH 5, MEDIUM 2, LOW 0.5 per open flag, capped) minus anomaly penalties. Show rank and trend.

## 7. Pages and API Surface

**Institution:** dashboard, students list (search, filters, flag badges), add/edit student with seat meter, CSV upload with result summary and error CSV, flags with Resolve, reports.

**AICTE admin:** dashboard (KPIs, charts, ranked institutions, alerts panel, auto-refresh), institution drill-down, duplicate evidence panel, anomaly alerts, audit log with integrity check, settings (thresholds), reports, state-wise summary.

**Verifier:** lookup by APAAR ID, tiered result, authenticity badge, verification history.

**Student (simulated):** login with APAAR ID plus demo OTP 123456, consent toggle (Tier 0/1/2), Who looked me up log.

**Public:** `/verify/record/{id}?sig=...` authenticity page, `/.well-known/aicte-public-key.pem`, certificate print page.

**REST API (Swagger at /docs):**

- `POST /api/v1/students/bulk` (X-API-Key)
- `PUT /api/v1/students/{apaar_id}` (X-API-Key)
- `GET /api/v1/programs/{id}/intake-check`
- `GET /api/v1/students/{apaar_id}/verify` (verifier token)
- `GET /api/v1/institutions/{aicte_id}/summary`
- `GET /api/aicte/summary` (dashboard JSON)

## 8. Team Roles and File Ownership

### Team of 4

| Person | Role | Owns |
| --- | --- | --- |
| P1 | Backend and security lead | `models.py`, `database.py`, `auth.py`, `audit.py`, `security.py` (signing, rate limit), `routers/api.py`, `routers/verify.py` |
| P2 | Data and intelligence lead | `apaar_registry.py`, `validation.py`, `anomaly.py`, `seed.py`, reports logic |
| P3 | Frontend lead | `templates/`, `static/`, dashboards, certificate, verify pages |
| P4 | Product and demo lead | PPT, demo script, sample CSVs, test checklist, README, video, submission. Also reviews every merge and files bugs |

### Team of 3

Merge P4 into P3 and P1 as follows: P3 owns frontend plus PPT and video; P1 owns test checklist and README; P2 owns sample CSVs. Drop stretch items and D7 (settings page) first.

**Git:** one repo, one branch per person, merge to `main` on every checkpoint. Commit before every risky LLM prompt. Never let the LLM rewrite the whole project.

## 9. Hour-by-Hour Timeline

| Time | Block | P1 | P2 | P3 | P4 | Checkpoint |
| --- | --- | --- | --- | --- | --- | --- |
| 0:00-0:30 | Setup | Repo, venv, requirements, `.env.example`, skeleton | Fake APAAR ID generator | `base.html` with Tailwind, navbar | Context prompt file, PPT skeleton from SIH template | Everyone sees `/` and `/docs` |
| 0:30-1:45 | Foundations | Models, DB switch, JWT auth, RBAC, hash-chained audit | Registry adapter, `seed.py` with planted problems | Login page, role-based navbar, institution dashboard shell | Sample CSVs (good, bad, cross-duplicate), demo script draft | Login works for all 4 roles, seed runs |
| 1:45-3:30 | Core pipeline | Student CRUD, CSV upload, bulk API with API key | Validation engine R1-R12, Intake Guard | Student list, form with seat meter, upload result page, flag badges | Test upload flow, log bugs | bad\_upload.csv gives correct rejects and flags |
| 3:30-5:30 | Intelligence and trust | Ed25519 signing, public key, verify page, consent flow, verifier portal with tiers, rate limit | Anomaly engine, compliance score, reports (CSV and summary) | AICTE dashboard with auto-refresh, alerts panel, duplicate evidence panel, certificate | Screenshots, architecture diagram, PPT content | Dashboards show planted anomalies |
| **5:30** | **FEATURE FREEZE** | `git tag v1-demo`, backup zip |  |  |  |  |
| 5:30-6:15 | Integration test | Fix bugs from test list | Fix data bugs | Polish only visible screens | Run the test checklist twice from fresh seed | All checklist items pass |
| 6:15-7:15 | Deliverables | Support, README | Reset-demo button, seed stability | PPT visuals | Final PPT, record video scene by scene | Video exported |
| 7:15-8:00 | Submit and buffer | Verify repo | Verify links | Verify video plays | Submit to portal, screenshot confirmation | **Submitted with 30 minutes to spare** |

## 10. Seed Data Specification

Use fixed seeds (`random.seed(42)`, `Faker.seed(42)`) so every reset gives identical data.

- 1 AICTE admin, 5 institutions (Engineering, PGDM, Pharmacy, Management, Polytechnic) across different states, one institution user each, API keys
- 2-4 programs per institution, approved intake 60/120/180, two academic years
- 1 verifier (employer), a few student users linked to APAAR IDs
- About 800 mock registry entries and about 500 students, mostly clean
- **Planted problems:**
  - Institution 3, one program at 135% of intake
  - 3 duplicate APAAR IDs inside one institution
  - 4 APAAR IDs enrolled at two institutions at once
  - 5 APAAR IDs not in the registry, 5 name/DOB mismatches
  - Institution 4 with about 40% NRI share
  - Institution 2 with a 3x year-on-year jump
  - FN with nationality India, a cluster of students sharing one DOB
- Consent level: about 40% Tier 2, 30% Tier 1, 30% Tier 0

**Demo credentials** (put in README): `aicte_admin / Admin@123`, `inst1`..`inst5 / Inst@123`, `employer1 / Verify@123`, student demo OTP `123456`.

## 11. LLM Prompting Rules

1. Paste the master context prompt (stack, roles, tables, APAAR is 12 digits, rules for the LLM) at the start of every new chat.
2. One small task per prompt. Run after each one.
3. For errors, give the full traceback plus the one relevant file.
4. If the LLM loops three times, `git checkout`, restate the requirement, ask for the simplest version.
5. Do not let it change the stack.
6. Use the LLM for non-code work too: seed CSVs, PPT text, demo script, README, test cases.
7. Keep SQL dialect-neutral so the same code runs on SQLite and PostgreSQL.

## 12. Test Checklist (run twice from fresh seed)

| # | Action | Expected |
| --- | --- | --- |
| 1 | Login as `inst3` | Dashboard shows intake exceeded in red |
| 2 | Upload `bad_upload.csv` | Rejected and flagged rows reported, error CSV downloads |
| 3 | Add a student near full intake | Seat meter WARN; at full, BLOCK needs justification |
| 4 | Add same APAAR again | R4 flag |
| 5 | Add APAAR active at another institution | R5 flag and evidence panel entry |
| 6 | Login as `aicte_admin` | New flags appear without manual refresh |
| 7 | Open anomaly alerts | NRI-share and surge alerts with reasons |
| 8 | Verifier looks up Tier 2 APAAR | Full details and authentic badge |
| 9 | Verifier looks up Tier 0 APAAR | Valid only, no details |
| 10 | Student logs in with OTP, changes consent, views lookup log | Change reflected, verifier lookup appears |
| 11 | Open a certificate QR | Authentic record |
| 12 | Edit a student field directly in the DB, reopen QR | TAMPERED |
| 13 | Call bulk API from `/docs` with API key | 200 OK, summary returned |
| 14 | Run audit integrity check | Chain valid; after manual DB edit, chain broken |
| 15 | Institution opens `/aicte/dashboard` | 403 or redirect |
| 16 | Verifier exceeds rate limit | 429 with message |

## 13. Demo Video Script (about 4:30)

| Time | Scene |
| --- | --- |
| 0:00-0:25 | Problem: only PGDM gives student-level data, others give totals. No verifiability, excess and duplicate enrolment risk |
| 0:25-0:50 | Architecture slide, one sentence per block, mock registry honesty line |
| 0:50-1:40 | Institution: seat meter, CSV upload, rejected rows, error report |
| 1:40-2:10 | Cross-institution duplicate caught live, evidence panel |
| 2:10-3:00 | AICTE dashboard updates live, anomaly reasons, compliance ranking, drill-down |
| 3:00-3:40 | Verifier: three consent tiers, student consent change, QR authentic then tampered |
| 3:40-4:10 | Certificate with Student ID and APAAR ID, report download, Swagger call |
| 4:10-4:30 | Audit integrity check, RBAC denial, closing impact line |

Record scene by scene, click Reset demo data before each take, 1080p, browser zoom 110-125%, check audio with headphones. Keep a backup take of every scene.

## 14. PPT Outline

1. Title, team, PS ID 26263
2. Problem and gaps
3. Solution and pipeline graphic
4. Features mapped to the 10 requirements
5. Architecture
6. Validation, Intake Guard and anomaly engine with compliance score
7. Signed verifiable records and consent-aware verification
8. Security and privacy: RBAC, hash-chained audit, rate limiting, data minimisation, alignment with DPDP Act principles
9. Innovation and USP (D1-D7)
10. Screenshots
11. Integration: REST API, adapter for real APAAR/DigiLocker, embedding in AICTE portal
12. Scalability roadmap: PostgreSQL, queued bulk jobs, caching, NIC/cloud, asymmetric key management in an HSM
13. Impact for AICTE, institutions, students, employers
14. Future scope and team

Check the official SIH template and slide limit first.

## 15. Risks and Cut Order

| Risk | Mitigation |
| --- | --- |
| LLM breaks working code | Small prompts, commit often, revert fast |
| Supabase unreachable | Local SQLite fallback through `DATABASE_URL`; record the final video on whichever works |
| Shared DB reset wipes teammates' data | Use SQLite locally; only one person touches Supabase at a time |
| Merge conflicts | File ownership by role |
| Running out of time | **Cut in this order:** stretch items → IsolationForest → settings page (D7) → filters → state-wise report → student Who looked me up log → rate limit demo. **Never cut:** upload and validation, AICTE dashboard, verification with consent, signed QR, certificate |
| Demo glitch | Deterministic seed, Reset demo data button, backup takes |
| Exhaustion | Two people always awake; P4 drafts PPT while others code |

## 16. Judge Q&A Prep and Honest Limitations

- **Is APAAR real here?** The registry is simulated; the adapter has a single `lookup_apaar` function to swap for the real API when access is granted.
- **Is the consent real?** Simulated OTP; production would use DigiLocker consent artefacts.
- **Why Ed25519, not blockchain?** Same tamper-evidence, no infrastructure, verifiable with a published public key, and keys can move to an HSM.
- **How does it scale?** Stateless FastAPI behind a load balancer, PostgreSQL with indexes on `apaar_id`, bulk uploads moved to a job queue.
- **How do you handle false positives?** Every flag has a reason and a Resolve action with an audit entry; thresholds are configurable.
- **Privacy?** Tiered disclosure, student-controlled consent, verification logs visible to the student, no Aadhaar stored, minimum fields on public pages.
- **Supernumerary rules?** Caps are configurable per program and derived from AICTE handbook categories.

## 17. Submission Checklist

- [ ] PPT in official template, exported in the required format
- [ ] Demo video within size and time limits, tested on another device
- [ ] GitHub repo with README (setup, credentials, screenshots, architecture) and no secrets committed
- [ ] Zip backup of code and database export
- [ ] Team details and PS ID entered correctly
- [ ] A teammate opens every submitted link from their own account
- [ ] Screenshot of submission confirmation
- [ ] Submitted at least 30 minutes before the deadline

## 18. Definition of Done

A stranger can log in as each role, run the 16-step test checklist without help, and every item in the traceability matrix is visible in the video. If that is true at Hour 5:30, freeze and move to deliverables.

## 19. Phase-by-Phase Build Guide (Installs, LLM Prompts, Owners)

Every phase below lists who does what, what to install, the exact prompts to paste into your LLM IDE, and a checkpoint that must pass before moving on. Start every new LLM chat by pasting the Master Context Prompt from Phase 0. Section numbers in brackets refer to sections above (for example \[5\] is the Data Model).

### 19.1 Person-wise division at a glance

| Person | Role | Files owned | Phase 1 | Phase 2 | Phase 3 | After freeze |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | Backend and security lead | `models.py`, `database.py`, `auth.py`, `audit.py`, `security.py`, `routers/api.py`, `routers/verify.py`, `routers/institution.py` | Models, DB switch, JWT auth, RBAC, hash-chained audit | Student CRUD, CSV upload route, bulk API with API key | Ed25519 signing, public key, verify page, student OTP consent, verifier tiers, rate limit | Bug fixes, Supabase switch test, README run steps |
| P2 | Data and intelligence lead | `apaar_registry.py`, `validation.py`, `anomaly.py`, `seed.py`, `routers/aicte.py` | Registry adapter, seed data with planted problems | Validation rules R1-R12, Intake Guard | Anomaly engine, compliance score, reports, settings | Reset-demo button, seed stability |
| P3 | Frontend lead | `templates/`, `static/` | Base layout, login, role navbar, error pages, dashboard shell | Students list, form with seat meter, upload and result pages, flags page | AICTE dashboard with auto-refresh, duplicate panel, certificate, verify pages, audit page | Visual polish, PPT visuals |
| P4 | Product and demo lead | `docs/`, `sample_data/`, `README.md` | Context prompt file, sample CSVs, demo script draft, PPT skeleton | Test every merged feature, log bugs | Screenshots, architecture diagram, PPT content, demo rehearsal | Test checklist x2, PPT final, video, submission |

Team of 3: P3 also takes P4's PPT and video work; P1 takes the test checklist and README; P2 takes the sample CSVs.

### 19.2 Install summary by phase

| Phase | Install | Who | Command or action |
| --- | --- | --- | --- |
| 0 | Python 3.11+, Git, VS Code (or an AI IDE) | Everyone | Download from the official sites; check with `python --version` and `git --version` |
| 0 | All Python packages | Everyone | One `pip install` line in Phase 0 below |
| 0 | GitHub repo | P1 | Create repo, invite the other three, add `.gitignore` with `venv/`, `.env`, `apaar.db`, `__pycache__/` |
| 1 | `rapidfuzz` (fuzzy name match) | P2 | `pip install rapidfuzz` then `pip freeze > requirements.txt` |
| 1 | Supabase account and project (optional, Mumbai region) | P1 | Create now, use the Session Pooler connection string later in Phase 4 |
| 2-3 | Nothing new |  | All libraries already installed in Phase 0 |
| 5 | OBS Studio (screen recording), CapCut or Clipchamp (editing), HandBrake (compression) | P4 | Install and test the microphone before Phase 5 starts |
| 5 | draw.io or Excalidraw (web, no install) | P4 | Architecture diagram |

### Phase 0: Setup and alignment (0:00-0:30)

**Goal:** the skeleton runs on every laptop and everyone can push to the repo.

**Install and run (everyone)**

```text
mkdir apaar-platform && cd apaar-platform
python -m venv venv
Windows: venv\Scripts\activate     Mac/Linux: source venv/bin/activate
pip install fastapi "uvicorn[standard]" sqlmodel "psycopg[binary]" jinja2 python-multipart "passlib[bcrypt]" bcrypt==4.0.1 "python-jose[cryptography]" cryptography pandas "qrcode[pil]" scikit-learn faker python-dotenv
pip freeze > requirements.txt
```

P1 pushes the empty structure first; the other three clone it and create their own branch (`git checkout -b p2-data`).

**Master Context Prompt (P4 saves this as `docs/context_prompt.md`; everyone pastes it at the start of every new chat)**

```text
PROJECT CONTEXT:
I am building a hackathon prototype called APAAR Verify: an APAAR ID-based Student Data Management and Verification Platform for AICTE (SIH PS 26263).
STACK: Python 3.11, FastAPI, SQLModel. A DATABASE_URL env var chooses the database: if unset use SQLite file apaar.db, otherwise PostgreSQL via psycopg. Jinja2 server-rendered templates, Tailwind CSS via CDN, Chart.js via CDN, pandas, rapidfuzz, cryptography (Ed25519), qrcode. NO React, NO Docker, NO microservices, NO Node.
RUN: uvicorn app.main:app --reload
ROLES: AICTE_ADMIN, INSTITUTION, VERIFIER, STUDENT. APAAR ID is a 12-digit numeric string.
TABLES: User, Institution, Program, ApaarRegistry (mock), Student, ValidationFlag, AnomalyAlert, AuditLog (hash-chained), VerificationLog, Setting.
FILES: app/main.py, database.py, models.py, auth.py, audit.py, security.py, apaar_registry.py, validation.py, anomaly.py, routers/(institution, aicte, verify, api).py, templates/, static/, seed.py.
RULES FOR YOU:
1. Keep code simple and beginner-readable with short comments.
2. Only modify the files I name. Never rewrite the whole project.
3. Give complete contents for new files; for edits show only the changed functions.
4. Use dialect-neutral SQLModel code that works on SQLite and PostgreSQL.
5. Tell me the exact terminal commands to run and the output to expect.
6. If something may fail, tell me how I will see the error.
```

**P1 prompt: skeleton**

```text
Create app/main.py with a FastAPI app, Jinja2Templates pointing to app/templates, a static files mount at /static, a GET / route that renders base.html, and a GET /health route returning {status: ok}. Create empty router files in app/routers and register them in main.py. Show the folder tree and the run command.
```

**P2 prompt: registry skeleton**

```text
Create app/apaar_registry.py with three functions and docstrings: validate_apaar_format(apaar_id) returns True only for exactly 12 numeric digits; lookup_apaar(apaar_id, session) queries the ApaarRegistry table and returns a dict or None; match_identity(apaar_id, name, dob, session) returns a (name_ok, dob_ok) tuple using fuzzy name matching. Add a comment that lookup_apaar is the single place to swap in the real APAAR/DigiLocker API. Leave bodies minimal for now.
```

**P3 prompt: base layout**

```text
Create app/templates/base.html using Tailwind CSS CDN and Chart.js CDN. Include a top navbar with the title 'APAAR Verify: AICTE Student Data Platform', a placeholder area for role-based links, a flash-message area, and a content block. Add small CSS classes for severity badges: HIGH red, MEDIUM amber, LOW blue. Create index.html extending it with a short welcome and a Login button.
```

**P4:** write `docs/context_prompt.md`, create the PPT file from the official SIH template with slide titles from section 14, and create the README skeleton.

**Checkpoint (0:30):** everyone sees the home page at `http://127.0.0.1:8000` and Swagger at `/docs`. Merge to `main`.

### Phase 1: Foundations (0:30-1:45)

**Goal:** database, login for all four roles, hash-chained audit, seeded data, and sample CSVs.

**Install:** P2 runs `pip install rapidfuzz` then `pip freeze > requirements.txt` and pushes. P1 creates a Supabase project now (optional until Phase 4). Nobody else installs anything.

**P1 prompt 1: models and database switch**

```text
Using SQLModel, create app/models.py and app/database.py for these tables: [paste the Data Model table from section 5]. In database.py read DATABASE_URL from the environment with python-dotenv; if it is missing use sqlite:///apaar.db. Use pool_pre_ping and pool_recycle for PostgreSQL. Provide create_db_and_tables(), a get_session dependency and a reset_db() that does drop_all then create_all. Import all models before create_all. Call create_db_and_tables() at startup in main.py. Use only dialect-neutral types.
```

**P1 prompt 2: auth and RBAC**

```text
Create app/auth.py with bcrypt password hashing, JWT creation and decoding with python-jose, a POST /login route that sets an HttpOnly SameSite=Lax cookie, a GET /logout route, a get_current_user dependency that reads the cookie, and a require_role(*roles) dependency factory that returns 403 for wrong roles. After login redirect AICTE_ADMIN to /aicte/dashboard, INSTITUTION to /institution/dashboard, VERIFIER to /verify, STUDENT to /student/consent. Create the login route to render login.html.
```

**P1 prompt 3: hash-chained audit**

```text
Create app/audit.py with log_action(session, user, action, entity, entity_id, details). Each AuditLog row stores prev_hash (the row_hash of the previous row, or 'GENESIS' for the first) and row_hash = SHA256 of prev_hash plus the row's fields in canonical JSON. Add verify_chain(session) that walks all rows in id order and returns (ok, first_broken_id). Call log_action from login and logout.
```

**P2 prompt 1: registry (full)**

```text
Fill in app/apaar_registry.py. validate_apaar_format: exactly 12 digits. lookup_apaar: query ApaarRegistry by apaar_id. match_identity: compare the submitted name to the registry name using rapidfuzz token_sort_ratio with a threshold of 85, and compare dob exactly; return (name_ok, dob_ok). Also add load_registry_map(session) returning a dict apaar_id to record so bulk validation can avoid one query per row.
```

**P2 prompt 2: seed.py**

```text
Write seed.py using Faker('en_IN'), random.seed(42), Faker.seed(42) and my models. It calls reset_db() then creates: 1 AICTE admin (aicte_admin / Admin@123); 5 institutions in different states (Engineering, PGDM, Pharmacy, Management, Polytechnic) each with one INSTITUTION user (inst1..inst5 / Inst@123) and an API key; 2-4 programs per institution for two academic years with approved intake 60, 120 or 180 and supernumerary_cap of 10 percent; 1 VERIFIER (employer1 / Verify@123); about 800 mock ApaarRegistry rows; about 500 students, mostly clean; 5 STUDENT users linked to APAAR IDs. Plant these problems: institution 3 one program at 135 percent of intake; 3 duplicate APAAR IDs inside one institution; 4 APAAR IDs enrolled at two institutions at once; 5 APAAR IDs missing from the registry; 5 name or DOB mismatches; institution 4 with about 40 percent NRI share; institution 2 with a 3x year-on-year jump; a few foreign-national rows with nationality India; a cluster of students sharing one DOB. Consent level 2 for 40 percent, 1 for 30 percent, 0 for 30 percent. Print all credentials at the end.
```

**P3 prompt: login and shells**

```text
Create login.html (username, password, error message), 403.html and 404.html friendly error pages, and institution_dashboard.html as a shell with five KPI cards (Total Students, Approved Intake, Fill %, Open Flags, Compliance Score) filled by placeholder values and an empty area for a chart and a flags table. Make the navbar in base.html show links depending on a role variable passed by the template context.
```

**P4 prompt: sample CSVs and tests**

```text
Generate three CSV files for sample_data/ using these columns: apaar_id, student_id, full_name, dob, gender, category, program_name, admission_year, admission_type, is_nri, oci_status, is_foreign_national, nationality, mode, consent_given. good_upload.csv: 30 clean rows. bad_upload.csv: 40 rows containing 3 missing APAAR IDs, 3 with 11 digits, 3 not in the registry, 2 duplicate APAAR IDs, 3 name mismatches, 2 foreign nationals with nationality India, 2 future admission years, 2 unknown program names. cross_dup.csv: 4 rows whose APAAR IDs already exist at another institution. Use APAAR IDs printed by seed.py where a valid ID is needed.
```

P4 also drafts `docs/demo_script.md` from section 13.

**Checkpoint (1:45):** `python seed.py` runs, the server starts, and you can log in as `aicte_admin`, `inst1`, `employer1` and a student user. Merge.

### Phase 2: Core pipeline (1:45-3:30)

**Goal:** an institution can add a student, upload a CSV and see validation results; the integration API works.

**Install:** nothing new.

**P2 prompt 1: validation engine (start here, P1 and P3 depend on it)**

```text
Create app/validation.py implementing rules R1-R12 from this table: [paste the Validation rules table from section 6]. Write each rule as a small separate function returning a flag dict with rule_code, severity, message and recommended_action. validate_student_row(row, ctx) returns the flags for one row, where ctx holds preloaded sets and dicts (registry map, existing APAAR IDs per institution, active full-time enrolments per APAAR across institutions, program map, existing roll numbers) so no query runs per row. validate_program_intake(program_id, session) handles R6 and R7 using thresholds from the Setting table. run_full_validation(institution_id, session) clears OPEN flags and regenerates them. Rows with R1, R2, R9 or R11 are marked rejected.
```

**P2 prompt 2: Intake Guard**

```text
Add intake_check(program_id, session) to app/validation.py returning remaining seats, fill ratio and a decision: ALLOW under 90 percent, WARN from 90 to 100 percent, BLOCK if one more regular admission would exceed approved intake. Add GET /api/v1/programs/{program_id}/intake-check in routers/api.py that returns it as JSON.
```

**P1 prompt 1: student CRUD and CSV upload**

```text
In app/routers/institution.py add, protected by require_role('INSTITUTION'): GET /institution/students with search and program filter; GET and POST /institution/students/new and /institution/students/{id}/edit; GET /institution/upload with a link to download a CSV template; POST /institution/upload which reads the CSV with pandas, preloads the validation context once, runs validate_student_row for every row, rejects rows flagged R1, R2, R9 or R11, saves the rest as Student with ValidationFlag rows, then calls validate_program_intake for affected programs. Return a result page with counts (accepted, accepted with warnings, rejected) and a downloadable error CSV. Only allow the logged-in institution's own data. Call log_action for create, edit and upload. When a BLOCK decision from intake_check is overridden on the form, require a justification text and store it in the audit details.
```

**P1 prompt 2: bulk API**

```text
In app/routers/api.py add POST /api/v1/students/bulk accepting a JSON array, authenticated by an X-API-Key header matched to Institution.api_key, reusing the same validation path as the CSV upload, returning counts and per-row errors. Add PUT /api/v1/students/{apaar_id} for updates. Add clear OpenAPI summaries and example request bodies so Swagger shows them.
```

**P3 prompt: institution screens**

```text
Create templates: students.html (table with search box, program dropdown, and severity flag badges per row), student_form.html (all student fields; when a program is selected call GET /api/v1/programs/{id}/intake-check with fetch and show a live seat meter with ALLOW green, WARN amber, BLOCK red, and a justification textarea that appears on BLOCK), upload.html (file input, CSV template link), upload_result.html (counts, rejected rows table, error CSV download button), and flags.html (open flags with a Resolve button). Use Tailwind. Do not change routes.
```

**P4:** pull each merge, run the upload flow with the three sample CSVs, and log every bug in a shared sheet (file, steps, expected, actual).

**Checkpoint (3:30):** uploading `bad_upload.csv` as `inst3` gives the right rejections and flags, the seat meter changes colour, and the bulk API returns 200 from `/docs`. Merge and tag `core-done`.

### Phase 3: Intelligence and trust (3:30-5:30)

**Goal:** every remaining MVP feature exists: anomaly detection, dashboards, signed records, consent-aware verification, certificate, reports and audit page.

**Install:** nothing new (`scikit-learn`, `cryptography` and `qrcode` came in Phase 0).

**P1 prompt 1: signing and public verification**

```text
Create app/security.py. Generate or load an Ed25519 private key from a file path in .env (create it on first run). build_canonical_record(student) returns canonical JSON (sorted keys, no spaces) of apaar_id, student_id, institution aicte_id, program name, admission_year, status, full_name and dob. sign_record(student) returns a base64url Ed25519 signature stored in Student.record_signature on every create and update. verify_signature(student, sig) recomputes and checks it. Add GET /.well-known/aicte-public-key.pem and a make_qr_png(url) helper using qrcode. In routers/verify.py add the public page GET /verify/record/{student_id}?sig=... that shows 'Authentic record' or 'TAMPERED or not found' with minimal info only.
```

**P1 prompt 2: student consent and verifier portal**

```text
In routers/verify.py add: (a) a STUDENT login flow at /student/consent where the student enters their APAAR ID and the demo OTP 123456 (label it 'simulated DigiLocker OTP'), then sets consent level 0, 1 or 2 and sees a 'Who looked me up' list from VerificationLog; (b) a VERIFIER portal at /verify where the verifier enters an APAAR ID. Result tiers: not found shows 'No record'; level 0 shows only 'APAAR valid, student has not consented to share details'; level 1 shows institution, program, admission year and status; level 2 shows the full record plus the authenticity badge and QR. Write a VerificationLog row and an audit entry for each lookup. Add a simple in-memory rate limit of 30 lookups per minute per verifier that returns HTTP 429 with a friendly message.
```

**P2 prompt 1: anomaly engine and compliance score**

```text
Create app/anomaly.py with run_anomaly_detection(session) that fills AnomalyAlert rows. A1: z-score of enrolment divided by intake across institutions, flag absolute z above 2 or ratio above 1.0. A2: year-on-year enrolment growth above the Setting threshold (default 50 percent). A3: NRI, foreign national or OCI share above the Setting threshold or z-score above 2 versus institutions of the same type. A4: many students in one program sharing one DOB. A5: IsolationForest on fill_ratio, nri_share, fn_share, yoy_growth and flag_rate per institution, storing the anomaly score. Every alert needs a plain-English reason and a recommended action. Also add compliance_score(institution_id, session): start at 100, subtract 5 per open HIGH flag, 2 per MEDIUM and 0.5 per LOW (cap the total flag penalty at 70) and subtract extra for anomaly alerts; return an integer from 0 to 100.
```

**P2 prompt 2: AICTE JSON, reports and settings**

```text
In app/routers/aicte.py (admin only) add GET /api/aicte/summary returning totals (institutions, total enrolment, total intake, flagged institutions, cross-institution duplicate count), per-institution intake versus enrolment with fill ratio and compliance score, flags grouped by rule_code, the latest 10 HIGH alerts and anomaly alerts, with optional filters state, institution_type and academic_year. Add CSV download routes using Response with media_type text/csv for: enrolment versus intake, validation flags, category and NRI/OCI/FN breakdown, cross-institution duplicates, and a state-wise summary. Add a printable HTML Compliance Summary route. Add a settings page to edit the Setting thresholds (supernumerary percentage, NRI share limit, surge percentage, fill ratio limit) and log changes to the audit log. Add an admin-only POST /aicte/reset-demo that runs reset_db and the seed.
```

**P3 prompt 1: AICTE dashboard**

```text
Create templates/aicte_dashboard.html extending base.html. Five KPI cards (Institutions, Total Enrolment, Total Intake, Flagged Institutions, Cross-institution Duplicates); a Chart.js bar chart of fill ratio per institution (red above 100 percent); a bar chart of flags by rule code; a table ranking institutions by compliance score with colour-coded score and a drill-down link; an alerts panel with the latest HIGH flags and anomaly reasons; filters for state, institution type and academic year. Fetch /api/aicte/summary on load and every 10 seconds with setInterval and update the charts without reloading the page. Also create institution_detail.html for drill-down and duplicates.html showing each cross-institution duplicate with both enrolments side by side and Confirm and Resolve buttons.
```

**P3 prompt 2: certificate, verify pages, audit page**

```text
Create certificate.html at GET /certificate/{student_id}: a printable degree-style certificate showing institution name, student name, program, 'Student ID | APAAR ID' prominently, admission year, a QR code image pointing to the signed verify URL, and a signature snippet; add a Print or Save as PDF button using window.print() and print CSS that hides the navbar. Create verify_portal.html (APAAR input, tiered result card, authenticity badge, my verification history), record_authentic.html and record_tampered.html (green and red states), student_consent.html (OTP step then consent level selector and lookup log), and audit.html for admins with filters by user, action and date plus an 'Verify integrity' button that calls verify_chain and shows a green or red result. Do not change the route logic.
```

**P4:** take screenshots of every screen as it lands, draw the architecture diagram in draw.io from section 4, write PPT slide text from section 14, and rehearse the demo script against the live app.

**Checkpoint (5:30), FEATURE FREEZE:** both dashboards show the planted anomalies, verification shows all three tiers, the certificate prints, and the audit integrity check works. Run `git tag v1-demo`, zip a backup of the code. From now on only bug fixes visible in the demo.

### Phase 4: Integration test and fixes (5:30-6:15)

**Goal:** the 16-step test checklist in section 12 passes twice from a fresh seed.

**Install:** nothing new.

**Actions**

1. P4 runs `python seed.py` then walks the checklist, ticking each step and filing bugs.
2. P1, P2 and P3 fix only the bugs in their own files.
3. P1 sets `DATABASE_URL` to the Supabase Session Pooler string (Mumbai region, special characters in the password URL-encoded), enables Row Level Security on every table with no policies, runs the seed once and repeats three checklist steps. If it fails, stay on SQLite and mention PostgreSQL as the production path.
4. P2 confirms the Reset demo data button restores the exact seed.

**Bug-fix prompt template (any person)**

```text
Here is the full error traceback and the file it comes from. Fix only this bug and change nothing else. Explain the cause in one sentence, then show only the changed function.
[paste traceback]
[paste the one file]
```

**If the LLM loops** (same bug three times): run `git checkout .` on that file, restate the requirement in one concrete sentence, and ask for the simplest version that ignores edge cases.

**Checkpoint (6:15):** all 16 checklist steps pass twice; `git tag final`.

### Phase 5: PPT, video and README (6:15-7:15)

**Install (P4):** OBS Studio, CapCut or Clipchamp, HandBrake. Test the microphone for 30 seconds before recording.

**P4 prompt: PPT text**

```text
I am filling the official SIH PPT template for PS 26263, APAAR ID-Based Student Data Management and Verification Platform for AICTE. Write concise slide text (max 6 bullets per slide, each under 15 words) for these slides: [paste the PPT outline from section 14]. Use this feature list: [paste the Differentiators table from section 2]. State clearly that the APAAR registry and OTP consent are simulated in the prototype and show the replacement path.
```

**P4 prompt: voiceover script**

```text
Write a 4 minute 30 second voiceover script, about 560 words, for a demo video, matching these scenes and timings: [paste the Demo Video Script table from section 13]. Use short plain sentences. Mark each scene start with its timestamp.
```

**P4 prompt: README**

```text
Write README.md for the repo: one-paragraph description, feature list mapped to the 10 requirements, tech stack, setup steps (clone, venv, pip install -r requirements.txt, python seed.py, uvicorn app.main:app --reload), the DATABASE_URL option for PostgreSQL, a credentials table, a 3-step demo walkthrough, and a section on prototype boundaries (simulated registry and OTP, how production replaces them).
```

**Everyone**

- P3 turns screenshots and the architecture diagram into slide visuals.
- P1 records the video with OBS, scene by scene, clicking Reset demo data before each take (1080p, browser zoom 110-125%, notifications off, headphones to check audio).
- P2 and P4 read the voiceover live while P1 drives the screen, or record the voiceover separately.
- Compress the final MP4 with HandBrake if it exceeds the portal limit.

**Checkpoint (7:15):** PPT in the official template, video exported and played on a second device, README complete.

### Phase 6: Submission and buffer (7:15-8:00)

1. P4 uploads PPT, video and repo link to the SIH portal and takes a screenshot of the confirmation.
2. P1 checks the repo has no `.env`, no secrets and no private key committed (`git log --stat` and a quick search), and that the README steps work in a fresh clone.
3. P2 and P3 open every submitted link from their own accounts and confirm they play and load.
4. Keep the last 30 minutes free for portal delays and last fixes.
5. Do not add features in this phase.

### 19.3 Quick reference: who to ask when something breaks

| Symptom | Owner |
| --- | --- |
| Login, 403, cookie, JWT, API key problems | P1 |
| Signature, QR, consent, verifier tiers, rate limit | P1 |
| Wrong flag, missing flag, validation or seed data | P2 |
| Anomaly alerts, compliance score, report CSVs, settings | P2 |
| Page layout, chart not updating, print view, template error | P3 |
| Test failures, video, PPT, submission portal | P4 |
