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