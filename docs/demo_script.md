# APAAR Verify: Demo Video Script (4:30)

**Target Video Duration:** 4 minutes 30 seconds  
**Total Word Count:** ~560 words (~125 words/minute spoken pace)  
**Setup & Recording Instructions:**
- Screen Resolution: 1080p (1920x1080)
- Browser Zoom: 110% to 125%
- Audio: Headset/Condenser microphone, quiet environment, notifications disabled
- Reset State: Run `python seed.py` before recording to reset demo data cleanly

---

### Scene 1 (0:00 – 0:25) | The Problem & Regulatory Blindspot
**[Visual: Title slide, then transition to news clippings of AICTE quota violations and duplicate degree fraud]**

> "Today in Indian technical education, AICTE captures student-level enrollment data primarily for PGDM programs. For most engineering and management courses, regulators only receive aggregate enrollment numbers. This creates a dangerous blindspot. Colleges exceed approved seat quotas unnoticed, duplicate students claim double subsidies at multiple universities, and paper credentials remain prone to forgery. We present APAAR Verify, an automated, privacy-first platform anchored on the national twelve-digit APAAR ID."

---

### Scene 2 (0:25 – 0:50) | Architecture & Honest Prototype Boundaries
**[Visual: System architecture diagram highlighting Frontend, FastAPI Core, Validation Engine, and Database Layer]**

> "Our architecture is clean and lightweight. FastAPI powers high-speed validation, SQLModel handles database persistence, and Ed25519 cryptography provides asymmetric digital verification. In this prototype, the national APAAR registry and DigiLocker OTP are simulated with deterministic mock records. The backend uses an isolated adapter pattern, making it a single-line configuration change to connect official government APIs when granted production access."

---

### Scene 3 (0:50 – 1:40) | Institution Seat Meter & CSV Ingestion
**[Visual: Login as `inst1`, show real-time Program Seat Meter, upload `sample_data/bad_upload.csv`, download error report]**

> "Let's log in as Delhi Technological Institute. On the dashboard, our real-time Intake Guard visually tracks approved capacity. Green means seats are available, amber warns at ninety percent, and red blocks enrollment at full capacity. Now, we upload a batch CSV. Instantly, our vectorized validation engine processes every record. Clean students are enrolled immediately, while invalid records are stopped. Clicking Download Error Report gives the institution an exact row-by-row diagnosis of quota breaches and demographic mismatches."

---

### Scene 4 (1:40 – 2:10) | Live Concurrent Enrollment Detection
**[Visual: Login as `aicte_admin`, navigate to `/aicte/duplicates`, show cross-institution evidence panel]**

> "What happens when a student tries to enroll full-time at two institutions simultaneously? We switch to the AICTE regulator view and open Concurrent Enrollments. The platform catches cross-institution duplicates instantly. Here, student APAAR ending in zero-eleven is caught enrolled concurrently at Delhi Tech and Maharashtra Tech. Regulators see full forensic evidence, including admission dates and program IDs, eliminating ghost student fraud."

---

### Scene 5 (2:10 – 3:00) | Central AICTE Command & Explainable Anomalies
**[Visual: AICTE Dashboard, institutional compliance ranking, open `/aicte/anomalies`, review plain-English reasons]**

> "The central AICTE command dashboard aggregates institutional health into a single national compliance score. Regulators can sort colleges by risk. Below, our unsupervised anomaly detection engine flags irregular patterns. Instead of black-box alerts, the system gives plain-English reasons: this pharmacy college exceeded intake by thirty-five percent, this institute experienced an abnormal three-hundred percent year-over-year surge, and this campus has an unnatural cluster sharing one birthday."

---

### Scene 6 (3:00 – 3:40) | Consent Tiers & Cryptographic Verification
**[Visual: Employer login at `/verify`, query Tier 0 student, switch to student portal, change consent to Tier 2, re-query, show Authentic record, tamper record in DB, reload to show TAMPERED]**

> "Third-party background verification must respect privacy under the DPDP Act. When TCS queries a student with Tier Zero consent, the system confirms the APAAR is valid, but strictly withholds personal details. The student logs in via simulated DigiLocker OTP and upgrades consent to Tier Two. Refreshing the verifier portal instantly unlocks verified academic credentials with an AICTE Authentic badge. Even better, if someone edits a student record directly in the database, the Ed25519 signature breaks, and the gateway immediately displays TAMPERED."

---

### Scene 7 (3:40 – 4:10) | Verifiable Digital Certificate & Swagger API
**[Visual: Open `/certificate/{id}`, inspect QR code, open Swagger API docs at `/docs`, execute bulk student API]**

> "Every verified student receives an official digital certificate featuring their APAAR ID, college roll ID, and a live verification QR code. Anyone can scan this code to verify authenticity against the published AICTE root public key without needing login credentials. For university ERPs, our REST API provides automated endpoints secured with API keys, enabling seamless integration into existing state admission portals."

---

### Scene 8 (4:10 – 4:30) | Hash-Chained Audit Ledger & Closing Impact
**[Visual: Open `/aicte/audit`, click Verify Chain Integrity, demonstrate 403 RBAC denial on unauthorized route, closing slide]**

> "Every action across the platform is logged in a cryptographic SHA-256 hash-chained audit ledger, making administrative tampering mathematically impossible. Strict role-based access control prevents unauthorized access. APAAR Verify provides AICTE with total regulatory oversight, institutions with zero-effort compliance, and students with sovereign control over their academic identity. Thank you."
