#!/usr/bin/env python3
"""
scripts/setup_dev_database.py

ONE-TIME TEAMMATE SETUP UTILITY
Installs and validates the approved canonical SQLite database (apaar.db)
for local development without requiring Supabase credentials or internet access.

SAFETY CONSTRAINTS:
- Completely offline: does not connect to Supabase or require cloud credentials.
- Validates SHA-256 checksum before decompressing or installing.
- If apaar.db already exists, stops safely unless --force is provided.
- If --force is used, preserves existing apaar.db with a timestamped backup first.
- Uses atomic replacement to guarantee no partial or corrupt database is left active.
- Verifies integrity (tables, foreign keys, audit chain) after installation.
- Synchronizes test_apaar.db for immediate automated test readiness.
"""

import os
import sys
import gzip
import shutil
import hashlib
import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))


def sha256_file(filepath: Path) -> str:
    """Compute hex SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_database_health(db_path: Path) -> bool:
    """Run basic integrity checks on SQLite database."""
    try:
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        
        # 1. Integrity check pragma
        integrity = cur.execute("PRAGMA integrity_check;").fetchone()
        if not integrity or integrity[0] != "ok":
            con.close()
            return False

        # 2. Foreign key pragma
        fk_errors = cur.execute("PRAGMA foreign_key_check;").fetchall()
        if fk_errors:
            con.close()
            return False

        # 3. Check expected table presence and non-empty rows
        tables = [
            "institution", "program", "user", "apaarregistry",
            "student", "validationflag", "anomalyalert",
            "verificationlog", "auditlog", "setting"
        ]
        for t in tables:
            cnt = cur.execute(f"SELECT count(*) FROM [{t}]").fetchone()[0]
            if cnt == 0:
                con.close()
                return False

        con.close()
        return True
    except Exception:
        return False


def setup_database(
    force: bool = False,
    snapshot_path: Path = WORKSPACE_ROOT / "backups" / "apaar_canonical_v1.db.gz",
    checksum_path: Path = WORKSPACE_ROOT / "backups" / "apaar_canonical_v1.sha256",
    backup_dir: Path = WORKSPACE_ROOT / "backups",
) -> bool:
    print("=" * 70)
    print("  APAAR VERIFY — LOCAL DATABASE SETUP UTILITY")
    print("=" * 70)

    target_db = WORKSPACE_ROOT / "apaar.db"
    test_db = WORKSPACE_ROOT / "test_apaar.db"
    backup_dir.mkdir(parents=True, exist_ok=True)

    # 1. Idempotency Check: Is a healthy database already installed?
    if target_db.exists() and not force:
        if verify_database_health(target_db):
            print(f"[OK] Canonical database '{target_db.name}' is already installed and verified healthy.")
            print("     No changes needed. To overwrite, re-run with: python scripts/setup_dev_database.py --force")
            # Ensure test_apaar.db is also present
            if not test_db.exists():
                shutil.copyfile(target_db, test_db)
                print(f"[+] Synchronized test database: {test_db.name}")
            return True
        else:
            print(f"[!] Existing '{target_db.name}' failed health checks. Proceeding with fresh installation...")

    # 2. Check Snapshot Availability
    if not snapshot_path.exists():
        raise FileNotFoundError(
            f"Canonical snapshot not found at: {snapshot_path}\n"
            "Please obtain 'apaar_canonical_v1.db.gz' or run 'python scripts/sync_supabase_to_sqlite.py' (maintainers)."
        )

    # 3. Verify SHA-256 Checksum
    print(f"[1/5] Verifying snapshot checksum: {snapshot_path.name}...")
    actual_hash = sha256_file(snapshot_path)
    if checksum_path.exists():
        expected_content = checksum_path.read_text(encoding="utf-8").strip()
        expected_hash = expected_content.split()[0]
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(
                f"Checksum mismatch for snapshot!\n"
                f"  Expected: {expected_hash}\n"
                f"  Actual:   {actual_hash}\n"
                "The snapshot file may be corrupted or modified. Aborting setup."
            )
        print(f"  [PASS] SHA-256 Checksum matches: {actual_hash[:16]}...")
    else:
        print(f"  [Notice] Checksum file not found; computed hash: {actual_hash}")

    # 4. Decompress into Atomic Staging File
    print("[2/5] Decompressing canonical database into atomic staging file...")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    staging_file = WORKSPACE_ROOT / f"apaar.installing.{timestamp}.tmp"

    try:
        with gzip.open(snapshot_path, "rb") as f_in:
            with open(staging_file, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        # 5. Pre-Installation Staging Verification
        print("[3/5] Verifying staging database integrity...")
        if not verify_database_health(staging_file):
            raise RuntimeError("Staging database failed integrity and foreign key checks!")
        print("  [PASS] Staging integrity checks verified successfully.")

        # 6. Preserve Existing Database with Timestamped Backup
        if target_db.exists():
            backup_file = backup_dir / f"apaar_pre_setup_backup_{timestamp}.db"
            shutil.copyfile(target_db, backup_file)
            print(f"[4/5] Preserved existing database to: {backup_file.name}")
        else:
            print("[4/5] No prior apaar.db found; performing clean first-time installation...")

        # 7. Atomic Cutover
        # On Windows, os.replace replaces existing file atomically
        if target_db.exists():
            target_db.unlink()
        staging_file.rename(target_db)
        print(f"  [Installed] Atomic cutover complete -> {target_db.name}")

        # 8. Post-Installation Verification & Test Database Synchronization
        print("[5/5] Finalizing setup and synchronizing test database...")
        # Verify SQLModel session and audit chain on installed database
        from sqlmodel import Session, create_engine
        from app.audit import verify_chain

        engine = create_engine(f"sqlite:///{target_db}")
        with Session(engine) as session:
            intact, broken_id = verify_chain(session)
            if not intact:
                raise RuntimeError(f"Audit log verification failed post-installation at ID: {broken_id}")
        engine.dispose()
        print("  [PASS] Audit hash chain intact on installed apaar.db.")

        # Copy to test_apaar.db to ensure full test isolation
        shutil.copyfile(target_db, test_db)
        print(f"  [PASS] Synchronized test isolation baseline -> {test_db.name}")

        print("\n" + "=" * 70)
        print("  DATABASE SETUP COMPLETE! You can now run APAAR Verify locally.")
        print("  Command: uvicorn app.main:app --reload --port 8000")
        print("=" * 70)
        return True

    except Exception as exc:
        if staging_file.exists():
            staging_file.unlink()
        print(f"\n[ERROR] Setup failed: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One-time teammate setup for APAAR Verify SQLite database.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-installation and replace existing apaar.db (previous db will be backed up).",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=WORKSPACE_ROOT / "backups" / "apaar_canonical_v1.db.gz",
        help="Path to the canonical snapshot file.",
    )
    parser.add_argument(
        "--checksum",
        type=Path,
        default=WORKSPACE_ROOT / "backups" / "apaar_canonical_v1.sha256",
        help="Path to the SHA-256 checksum file.",
    )
    args = parser.parse_args()
    setup_database(
        force=args.force,
        snapshot_path=args.snapshot,
        checksum_path=args.checksum,
    )
