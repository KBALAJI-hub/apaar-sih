#!/usr/bin/env python3
"""
scripts/sync_supabase_to_sqlite.py

MAINTAINER-ONLY EXPORT UTILITY
Extracts the authoritative dataset from Supabase PostgreSQL via read-only access,
creates a strictly validated staging SQLite replica, verifies all foreign keys,
Ed25519 signatures, and audit hash chains, and produces a compressed, versioned
canonical snapshot (apaar_canonical_v1.db.gz) and SHA-256 checksum.

SAFETY CONSTRAINTS:
- Strictly read-only connection to Supabase (SET TRANSACTION READ ONLY).
- Never writes to, modifies, drops, or alters Supabase data or schema.
- Does not leak secrets, connection strings, passwords, or private keys.
- Stops without publishing or replacing anything if any validation check fails.
"""

import os
import sys
import gzip
import json
import shutil
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from dotenv import load_dotenv
load_dotenv(WORKSPACE_ROOT / ".env")

from sqlalchemy import text
from sqlmodel import SQLModel, Session, create_engine, select
import app.models as models
from app.audit import verify_chain
from app.security import verify_signature

# Table ingestion order (topological foreign key hierarchy)
EXPORT_TABLES = [
    ("setting", models.Setting),
    ("apaarregistry", models.ApaarRegistry),
    ("institution", models.Institution),
    ("program", models.Program),
    ("user", models.User),
    ("student", models.Student),
    ("validationflag", models.ValidationFlag),
    ("anomalyalert", models.AnomalyAlert),
    ("verificationlog", models.VerificationLog),
    ("auditlog", models.AuditLog),
]


def sha256_file(filepath: Path) -> str:
    """Compute hex SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_sanitized_url(raw_url: str) -> str:
    """Mask credentials in database URL for safe logging."""
    import re
    if not raw_url:
        return ""
    return re.sub(r"://([^:]+):([^@]+)@", r"://***:***@", raw_url)


def run_sync(
    output_dir: Path = WORKSPACE_ROOT / "backups",
    snapshot_filename: str = "apaar_canonical_v1.db.gz",
    install_local: bool = False,
) -> Path:
    print("=" * 70)
    print("  APAAR VERIFY — AUTHORITATIVE SNAPSHOT EXPORT UTILITY")
    print("=" * 70)

    # 1. Resolve Supabase Connection URL
    supabase_url = os.getenv("SUPABASE_DATABASE_URL") or os.getenv("POSTGRES_URL")
    if not supabase_url:
        raise RuntimeError(
            "SUPABASE_DATABASE_URL environment variable is required to export from Supabase."
        )

    print(f"[*] Target Source: {get_sanitized_url(supabase_url)}")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    staging_db_path = output_dir / f"apaar_staging_{timestamp}.db"
    if staging_db_path.exists():
        staging_db_path.unlink()

    pg_connect_args = {}
    if ":6543" in supabase_url:
        pg_connect_args["prepare_threshold"] = None

    pg_engine = create_engine(
        supabase_url,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args=pg_connect_args,
    )

    staging_engine = create_engine(
        f"sqlite:///{staging_db_path}",
        connect_args={"check_same_thread": False},
    )

    source_counts = {}
    destination_counts = {}

    try:
        # 2. Initialize Clean SQLite Schema
        print("[1/6] Creating clean SQLite schema from SQLModel metadata...")
        SQLModel.metadata.create_all(staging_engine)

        # 3. Read-Only Extraction & Staging Population
        print("[2/6] Streaming tables from Supabase into staging database...")
        with pg_engine.connect().execution_options(read_only=True) as pg_conn:
            # Enforce read-only transaction on PostgreSQL
            pg_conn.execute(text("SET TRANSACTION READ ONLY;"))

            with staging_engine.connect() as sqlite_conn:
                sqlite_conn.execute(text("PRAGMA foreign_keys = OFF;"))

                for table_name, model_cls in EXPORT_TABLES:
                    cols = [c.name for c in model_cls.__table__.columns]
                    col_list_str = ", ".join(f'"{c}"' for c in cols)
                    select_sql = f'SELECT {col_list_str} FROM "{table_name}"'
                    if table_name == "auditlog":
                        select_sql += ' ORDER BY "id" ASC'

                    res = pg_conn.execute(text(select_sql))
                    rows = res.fetchall()
                    source_counts[table_name] = len(rows)

                    if rows:
                        placeholders = ", ".join(f":{c}" for c in cols)
                        insert_sql = text(f'INSERT INTO "{table_name}" ({col_list_str}) VALUES ({placeholders})')
                        row_dicts = [dict(zip(cols, r)) for r in rows]
                        sqlite_conn.execute(insert_sql, row_dicts)

                    print(f"  --> Copied {len(rows):5d} rows for table '{table_name}'")

                sqlite_conn.commit()
                sqlite_conn.execute(text("PRAGMA foreign_keys = ON;"))

                # 4. Synchronize SQLite Autoincrement Sequences if sqlite_sequence exists
                print("[3/6] Checking and synchronizing SQLite autoincrement sequence counters...")
                seq_table_exists = sqlite_conn.execute(
                    text("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
                ).scalar() > 0

                if seq_table_exists:
                    for table_name, model_cls in EXPORT_TABLES:
                        max_id = sqlite_conn.execute(text(f'SELECT MAX("id") FROM "{table_name}"')).scalar()
                        if max_id is not None:
                            sqlite_conn.execute(
                                text(
                                    "INSERT OR REPLACE INTO sqlite_sequence (name, seq) VALUES (:name, :seq)"
                                ),
                                {"name": table_name, "seq": max_id},
                            )
                    sqlite_conn.commit()
                    print("  [PASS] sqlite_sequence counters synchronized.")
                else:
                    print("  [Info] SQLite using standard ROWID autoincrement (sqlite_sequence not required).")

        # 5. Validation Gates
        print("[4/6] Executing comprehensive validation gates...")

        # Gate A: Foreign Key Integrity Check
        with staging_engine.connect() as sqlite_conn:
            fk_violations = sqlite_conn.execute(text("PRAGMA foreign_key_check;")).fetchall()
            if fk_violations:
                raise RuntimeError(f"Foreign key integrity validation failed: {fk_violations}")
            print("  [PASS] Foreign key integrity: 0 violations.")

        # Gate B: Exact Row Count Matching
        with Session(staging_engine) as session:
            for table_name, model_cls in EXPORT_TABLES:
                cnt = session.exec(select(model_cls)).all()
                destination_counts[table_name] = len(cnt)
                if destination_counts[table_name] != source_counts[table_name]:
                    raise RuntimeError(
                        f"Row count mismatch for '{table_name}': "
                        f"Source={source_counts[table_name]}, Staged={destination_counts[table_name]}"
                    )
            print("  [PASS] Row count parity: All 10 tables match source counts exactly.")

            # Gate C: Cryptographic Audit Hash Chain Integrity
            chain_valid, broken_id = verify_chain(session)
            if not chain_valid:
                raise RuntimeError(
                    f"Audit log hash chain validation failed at record ID: {broken_id}"
                )
            print(f"  [PASS] Audit hash chain: Fully intact across {destination_counts['auditlog']} log entries.")

            # Gate D: Ed25519 Student Record Signatures
            signed_students = session.exec(
                select(models.Student).where(models.Student.record_signature != None)
            ).all()
            print(f"  Evaluating {len(signed_students)} Ed25519 student signatures...")
            for s in signed_students:
                if not verify_signature(s, session=session):
                    raise RuntimeError(
                        f"Ed25519 signature verification failed for student: {s.student_id} (APAAR: {s.apaar_id})"
                    )
            print(f"  [PASS] Ed25519 digital signatures: {len(signed_students)}/{len(signed_students)} records valid.")

        # Close staging engine before file packaging
        staging_engine.dispose()

        # 6. Package Canonical Snapshot & Checksum
        print("[5/6] Packaging compressed canonical snapshot...")
        uncompressed_hash = sha256_file(staging_db_path)
        snapshot_path = output_dir / snapshot_filename
        checksum_path = output_dir / f"{snapshot_filename.replace('.db.gz', '')}.sha256"

        with open(staging_db_path, "rb") as f_in:
            with gzip.open(snapshot_path, "wb", compresslevel=9) as f_out:
                shutil.copyfileobj(f_in, f_out)

        compressed_hash = sha256_file(snapshot_path)
        with open(checksum_path, "w", encoding="utf-8") as f:
            f.write(f"{compressed_hash}  {snapshot_path.name}\n")

        print(f"  [Output] Compressed Snapshot: {snapshot_path} ({snapshot_path.stat().st_size / (1024*1024):.2f} MB)")
        print(f"  [Output] SHA-256 Checksum:   {compressed_hash}")

        # 7. Write Migration Manifest
        manifest_path = output_dir / f"migration_manifest_{timestamp}.json"
        manifest_data = {
            "timestamp": timestamp,
            "status": "VALIDATED_AND_PACKAGED",
            "source": get_sanitized_url(supabase_url),
            "uncompressed_sqlite_sha256": uncompressed_hash,
            "compressed_snapshot_sha256": compressed_hash,
            "snapshot_file": str(snapshot_path.name),
            "source_row_counts": source_counts,
            "destination_row_counts": destination_counts,
            "validation_results": {
                "foreign_keys": "PASS (0 violations)",
                "audit_chain": "PASS (intact)",
                "ed25519_signatures": f"PASS ({len(signed_students)}/{len(signed_students)} verified)",
                "sqlite_sequence": "PASS (all counters synchronized)",
            },
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        print(f"  [Output] Migration Manifest: {manifest_path}")

        # Optional Local Installation
        if install_local:
            print("[6/6] Installing validated database directly as local apaar.db...")
            local_target = WORKSPACE_ROOT / "apaar.db"
            if local_target.exists():
                backup_target = output_dir / f"apaar_backup_{timestamp}.db"
                shutil.copyfile(local_target, backup_target)
                print(f"  [Backup] Preserved previous apaar.db to {backup_target}")
            shutil.copyfile(staging_db_path, local_target)
            print(f"  [Installed] Successfully updated local {local_target}")

        # Remove temporary staging db file
        staging_db_path.unlink()
        print("\n" + "=" * 70)
        print("  SNAPSHOT EXPORT COMPLETE: ALL VALIDATION GATES PASSED")
        print("=" * 70)
        return snapshot_path

    except Exception as exc:
        print(f"\n[ERROR] Migration/Export failed: {exc}", file=sys.stderr)
        try:
            staging_engine.dispose()
        except Exception:
            pass
        if staging_db_path.exists():
            try:
                staging_db_path.unlink()
            except Exception:
                pass
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export canonical SQLite snapshot from Supabase.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=WORKSPACE_ROOT / "backups",
        help="Directory to save snapshot and checksum files.",
    )
    parser.add_argument(
        "--snapshot-name",
        type=str,
        default="apaar_canonical_v1.db.gz",
        help="Target filename for the compressed snapshot.",
    )
    parser.add_argument(
        "--install-local",
        action="store_true",
        help="If set, also install the validated database as local apaar.db.",
    )
    args = parser.parse_args()
    run_sync(
        output_dir=args.output_dir,
        snapshot_filename=args.snapshot_name,
        install_local=args.install_local,
    )
