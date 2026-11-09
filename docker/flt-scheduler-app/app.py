import csv
import io
import logging
import os
import shutil
import sqlite3
import sys
import threading
from datetime import date, datetime, time, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from urllib.parse import quote

import pytz

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# Configure structured logging
def setup_logging():
    """Configure structured logging with consistent format."""
    # Create logs directory
    log_dir = os.path.join("data", "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Configure root logger
    logger = logging.getLogger("scheduler")
    logger.setLevel(logging.INFO)

    # Console handler (stderr) - structured format
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)

    # File handler with rotation - detailed format
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "scheduler.log"),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Suppress Flask's default logger to avoid duplicate logs
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

    return logger

# Initialize logger
logger = setup_logging()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me")
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file upload
app.config['WTF_CSRF_TIME_LIMIT'] = None  # Token valid for entire session, not just 1 hour

# Enable CSRF protection
csrf = CSRFProtect(app)

# Application version (semantic versioning: MAJOR.MINOR.PATCH-PRERELEASE)
# Read from VERSION file if it exists, otherwise use hardcoded default
try:
    with open("VERSION", "r") as f:
        APP_VERSION = f.read().strip()
except FileNotFoundError:
    APP_VERSION = "0.9.0-beta"

# Database configuration
DATA_DIR = "data"
DATABASE_TYPE = os.environ.get("DATABASE_TYPE", "sqlite").lower()

# SQLite configuration
SQLITE_DB_PATH = os.environ.get("SQLITE_DB_PATH")
if DATABASE_TYPE == "sqlite":
    if not SQLITE_DB_PATH:
        if os.environ.get("FLASK_ENV") == "development":
            SQLITE_DB_PATH = os.path.join(DATA_DIR, "scheduler.db")
            logger.warning("Using default SQLite path for development. Set SQLITE_DB_PATH in production!")
        else:
            raise RuntimeError("SQLITE_DB_PATH environment variable is required in production")
    DB_PATH = SQLITE_DB_PATH

# PostgreSQL configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_TYPE == "postgresql" and not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required when DATABASE_TYPE=postgresql")

BACKUP_DIR = os.path.join(DATA_DIR, "backups")
DATE_FMT = "%Y-%m-%d"
TIME_FMT = "%H:%M"
DATETIME_FMT = "%Y-%m-%d %H:%M"
BACKUP_RETENTION_DAYS = 7
ROLES = {"user", "scheduler", "approver", "admin"}

# Simple in-memory cache for crew and aircraft lists
_cache = {
    "crew": {"data": None, "timestamp": 0},
    "aircraft": {"data": None, "timestamp": 0},
}
CACHE_TTL = 60  # Cache time-to-live in seconds

SKYVECTOR_LL = "31.144812341768187,-97.717529291779"
SKYVECTOR_CHART = "301"
SKYVECTOR_ZOOM = "2"

# PostgreSQL connection pool (initialized on first use)
_pg_pool = None


def db_conn():
    """Create database connection (SQLite or PostgreSQL based on config)."""
    if DATABASE_TYPE == "sqlite":
        conn = sqlite3.connect(DB_PATH, timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Apply per-connection PRAGMA settings for stability
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    elif DATABASE_TYPE == "postgresql":
        import psycopg2
        import psycopg2.extras
        from psycopg2 import pool

        # Initialize connection pool on first use
        global _pg_pool
        if _pg_pool is None:
            _pg_pool = pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=20,  # 8 workers * 2-3 connections each
                dsn=DATABASE_URL
            )
            logger.info("PostgreSQL connection pool initialized (min=2, max=20)")

        # Get connection from pool and wrap with RealDictCursor factory
        conn = _pg_pool.getconn()

        # Create a wrapper class to handle pool return on context exit
        class PooledConnection:
            def __init__(self, connection, pool):
                self.conn = connection
                self.pool = pool
                # Set cursor factory for dict-like row access
                self.conn.cursor_factory = psycopg2.extras.RealDictCursor

            def __enter__(self):
                return self.conn

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    self.conn.commit()
                else:
                    self.conn.rollback()
                self.pool.putconn(self.conn)
                return False

            def execute(self, *args, **kwargs):
                # Allow direct execute calls
                cursor = self.conn.cursor()
                cursor.execute(*args, **kwargs)
                return cursor

            def cursor(self):
                return self.conn.cursor()

        return PooledConnection(conn, _pg_pool)

    else:
        raise ValueError(f"Unsupported DATABASE_TYPE: {DATABASE_TYPE}")


def quarantine_corrupt_db(reason: str):
    if not os.path.exists(DB_PATH):
        return
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{DB_PATH}.corrupt-{stamp}.bak"
    os.replace(DB_PATH, backup_path)
    logger.critical(f"Quarantined corrupt database to {backup_path}. Reason: {reason}")


def ensure_db_healthy():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(DB_PATH):
        return
    try:
        with sqlite3.connect(DB_PATH) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()
            status = (result[0] if result else "").strip().lower()
    except sqlite3.DatabaseError as exc:
        quarantine_corrupt_db(f"Database error during integrity check: {exc}")
        return

    if status != "ok":
        quarantine_corrupt_db(f"Integrity check failed: {status or 'unknown'}")


def create_backup() -> tuple[bool, str]:
    """Create a timestamped backup of the database (SQLite only). Returns (success, message)."""
    if DATABASE_TYPE != "sqlite":
        return False, "Backups only supported for SQLite (use PostgreSQL native tools like pg_dump)"

    if not os.path.exists(DB_PATH):
        return False, "Database does not exist"

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_filename = f"scheduler-backup-{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)

    try:
        # Checkpoint WAL to ensure all data is in the main database file
        with sqlite3.connect(DB_PATH, timeout=5.0) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        # Copy the database file
        shutil.copy2(DB_PATH, backup_path)

        # Also copy WAL and SHM files if they exist
        for ext in ["-wal", "-shm"]:
            src = f"{DB_PATH}{ext}"
            if os.path.exists(src):
                shutil.copy2(src, f"{backup_path}{ext}")

        # Verify backup integrity
        with sqlite3.connect(backup_path) as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0].lower() != "ok":
                os.remove(backup_path)
                return False, f"Backup failed integrity check: {result[0]}"

        file_size = os.path.getsize(backup_path)
        size_mb = file_size / (1024 * 1024)

        logger.info(f"Created backup: {backup_filename} ({size_mb:.2f} MB)")
        return True, f"Backup created: {backup_filename} ({size_mb:.2f} MB)"

    except Exception as exc:
        logger.error(f"Backup failed: {exc}", exc_info=True)
        if os.path.exists(backup_path):
            os.remove(backup_path)
        return False, f"Backup failed: {exc}"


def rotate_old_backups():
    """Remove backups older than BACKUP_RETENTION_DAYS."""
    if not os.path.exists(BACKUP_DIR):
        return

    now = datetime.utcnow()
    deleted = 0

    try:
        for filename in os.listdir(BACKUP_DIR):
            if not filename.startswith("scheduler-backup-") or not filename.endswith(".db"):
                continue

            filepath = os.path.join(BACKUP_DIR, filename)
            file_age = now - datetime.fromtimestamp(os.path.getmtime(filepath))

            if file_age.days >= BACKUP_RETENTION_DAYS:
                os.remove(filepath)
                # Also remove associated WAL/SHM files
                for ext in ["-wal", "-shm"]:
                    aux_file = f"{filepath}{ext}"
                    if os.path.exists(aux_file):
                        os.remove(aux_file)
                deleted += 1
                logger.debug(f"Deleted old backup: {filename} (age: {file_age.days} days)")

        if deleted > 0:
            logger.info(f"Backup rotation complete: removed {deleted} old backup(s)")

    except Exception as exc:
        logger.error(f"Backup rotation failed: {exc}", exc_info=True)


def archive_old_audit_logs():
    """Archive audit logs older than 90 days to keep query performance high."""
    try:
        with db_conn() as conn:
            cutoff = (datetime.utcnow() - timedelta(days=90)).strftime(DATETIME_FMT)

            count_result = conn.execute(
                "SELECT COUNT(*) as count FROM audit_logs WHERE created_at < ?",
                (cutoff,)
            ).fetchone()
            count = count_result["count"] if count_result else 0

            if count == 0:
                logger.debug("No audit logs to archive")
                return

            # Move to archive table
            conn.execute("""
                INSERT INTO audit_logs_archive (id, action, entity_type, entity_id, actor_username, details, created_at)
                SELECT id, action, entity_type, entity_id, actor_username, details, created_at
                FROM audit_logs WHERE created_at < ?
            """, (cutoff,))

            conn.execute("DELETE FROM audit_logs WHERE created_at < ?", (cutoff,))

            logger.info(f"Archived {count} audit logs older than 90 days")

    except Exception as exc:
        logger.error(f"Audit log archiving failed: {exc}", exc_info=True)


def daily_backup_task():
    """Background task that runs daily backups."""
    while True:
        try:
            # Wait 24 hours between backups
            threading.Event().wait(86400)  # 86400 seconds = 24 hours

            logger.info("Starting scheduled daily backup...")
            success, message = create_backup()

            if success:
                rotate_old_backups()
                archive_old_audit_logs()
                logger.info(f"Daily backup completed: {message}")
            else:
                logger.warning(f"Daily backup failed: {message}")

        except Exception as exc:
            logger.error(f"Daily backup task error: {exc}", exc_info=True)


def start_backup_scheduler():
    """Start the daily backup scheduler in a background thread."""
    backup_thread = threading.Thread(target=daily_backup_task, daemon=True, name="BackupScheduler")
    backup_thread.start()
    logger.info("Daily backup scheduler started")


def julian_prefix_from_date_str(flight_date: str) -> str:
    parsed = datetime.strptime(flight_date, DATE_FMT).date()
    return parsed.strftime("%Y%j")


def next_mission_id(conn: sqlite3.Connection, flight_date: str) -> str:
    prefix = julian_prefix_from_date_str(flight_date)
    last = conn.execute(
        """
        SELECT mission_id
        FROM flights
        WHERE mission_id LIKE ?
        ORDER BY mission_id DESC
        LIMIT 1
        """,
        (f"{prefix}-%",),
    ).fetchone()
    seq = int(last["mission_id"].split("-")[-1]) if last and last["mission_id"] else 0
    return f"{prefix}-{seq + 1:03d}"


def coerce_checkbox(value: str | None) -> int:
    return 1 if value in {"1", "on", "true", "yes"} else 0


def calculate_decimal_hours(actual_takeoff: str | None, actual_arrival: str | None) -> str:
    if not actual_takeoff or not actual_arrival:
        return ""
    try:
        takeoff = datetime.strptime(actual_takeoff, "%H:%M")
        arrival = datetime.strptime(actual_arrival, "%H:%M")
    except ValueError:
        return ""
    if arrival < takeoff:
        arrival += timedelta(days=1)
    total_minutes = int((arrival - takeoff).total_seconds() // 60)
    return f"{(total_minutes / 60):.2f}"


def build_skyvector_url(origin: str | None, route: str | None, destination: str | None) -> str:
    dep = (origin or "").strip().upper()
    rte = " ".join((route or "").strip().upper().split())
    arr = (destination or "").strip().upper()
    if not dep or not arr:
        return ""
    fpl_parts = [dep]
    if rte:
        fpl_parts.append(rte)
    fpl_parts.append(arr)
    fpl = quote(f" {' '.join(fpl_parts)}", safe="")
    return (
        "https://skyvector.com/"
        f"?ll={SKYVECTOR_LL}&chart={SKYVECTOR_CHART}&zoom={SKYVECTOR_ZOOM}&fpl={fpl}"
    )


def build_crew_summary(payload: dict) -> str:
    return (
        f'PIC: {payload["pic_name"]}'
        + (" (AMC)" if payload["pic_is_amc"] else "")
        + f' | Pilot: {payload["pilot_name"]}'
        + (f' | Crew: {payload["crew_members"]}' if payload["crew_members"] else "")
        + (f' | Non-rated: {payload["non_rated_crew"]}' if payload["non_rated_crew"] else "")
    )


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db_conn() as conn:
        return conn.execute(
            "SELECT id, username, role, active FROM users WHERE id = ?",
            (uid,),
        ).fetchone()


def actor_name():
    user = current_user()
    return user["username"] if user else "system"


def write_audit(action: str, entity_type: str, entity_id: str, details: str, conn=None):
    """Write an audit log entry. If conn is provided, use it; otherwise open a new connection."""
    actor = actor_name()

    def _write(connection):
        connection.execute(
            """
            INSERT INTO audit_logs (action, entity_type, entity_id, actor_username, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                entity_type,
                entity_id,
                actor,
                details[:1000],
                datetime.utcnow().strftime(DATETIME_FMT),
            ),
        )

    if conn is not None:
        # Use the provided connection (already in a transaction)
        _write(conn)
    else:
        # Open a new connection
        with db_conn() as new_conn:
            _write(new_conn)
    # Also log to application logger for real-time monitoring
    logger.info(f"AUDIT: {action} | {entity_type}:{entity_id} | {actor} | {details[:200]}")


def get_app_setting(key: str, default: str = "") -> str:
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_app_setting(key: str, value: str):
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def parse_active_value(raw: str | None, default: int = 1) -> int:
    if raw is None or str(raw).strip() == "":
        return default
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "y", "on", "active"}:
        return 1
    if value in {"0", "false", "no", "n", "off", "inactive"}:
        return 0
    return default


def read_bulk_import_text(form_key: str, file_key: str) -> str:
    text = request.form.get(form_key, "").strip()
    upload = request.files.get(file_key)
    file_text = ""
    if upload and upload.filename:
        payload = upload.read()
        if payload:
            try:
                file_text = payload.decode("utf-8-sig")
            except UnicodeDecodeError:
                file_text = payload.decode("latin-1", errors="ignore")
    combined = "\n".join(part for part in [text, file_text.strip()] if part).strip()
    return combined


def parse_bulk_rows(raw_text: str):
    rows = []
    for row in csv.reader(io.StringIO(raw_text)):
        normalized = [cell.strip() for cell in row]
        if any(normalized):
            rows.append(normalized)
    return rows


def migrate_flights(conn: sqlite3.Connection):
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(flights)").fetchall()}
    if "mission_id" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN mission_id TEXT")
    if "pic_name" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN pic_name TEXT DEFAULT ''")
    if "pic_is_amc" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN pic_is_amc INTEGER NOT NULL DEFAULT 0")
    if "pilot_name" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN pilot_name TEXT DEFAULT ''")
    if "crew_members" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN crew_members TEXT DEFAULT ''")
    if "non_rated_crew" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN non_rated_crew TEXT DEFAULT ''")
    if "is_team_flight" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN is_team_flight INTEGER NOT NULL DEFAULT 0")
    if "amc_mission_id" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN amc_mission_id TEXT DEFAULT ''")
    if "actual_takeoff" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN actual_takeoff TEXT DEFAULT ''")
    if "actual_arrival" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN actual_arrival TEXT DEFAULT ''")
    if "route" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN route TEXT DEFAULT ''")
    if "closeout_comments" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN closeout_comments TEXT DEFAULT ''")
    if "closed_out" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN closed_out INTEGER NOT NULL DEFAULT 0")
    if "closed_at" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN closed_at TEXT DEFAULT ''")
    if "cancel_weather" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN cancel_weather INTEGER NOT NULL DEFAULT 0")
    if "cancel_maintenance" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN cancel_maintenance INTEGER NOT NULL DEFAULT 0")
    if "cancel_other" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN cancel_other INTEGER NOT NULL DEFAULT 0")
    if "cancel_other_text" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN cancel_other_text TEXT DEFAULT ''")
    if "deleted" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")
    if "deleted_at" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN deleted_at TEXT DEFAULT ''")
    if "atp_company" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN atp_company TEXT NOT NULL DEFAULT 'A Co'")

    existing_rows = conn.execute(
        """
        SELECT id, flight_date, mission_id
        FROM flights
        ORDER BY flight_date, launch_time, id
        """
    ).fetchall()

    highest_by_prefix = {}
    for row in existing_rows:
        mission_id = row["mission_id"] or ""
        if "-" not in mission_id:
            continue
        prefix, suffix = mission_id.rsplit("-", 1)
        if suffix.isdigit():
            highest_by_prefix[prefix] = max(highest_by_prefix.get(prefix, 0), int(suffix))

    for row in existing_rows:
        if row["mission_id"]:
            continue
        prefix = julian_prefix_from_date_str(row["flight_date"])
        seq = highest_by_prefix.get(prefix, 0) + 1
        highest_by_prefix[prefix] = seq
        conn.execute(
            "UPDATE flights SET mission_id = ? WHERE id = ?",
            (f"{prefix}-{seq:03d}", row["id"]),
        )

    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_flights_mission_id ON flights(mission_id)")
    except sqlite3.OperationalError:
        pass


def init_db():
    ensure_db_healthy()
    os.makedirs(DATA_DIR, exist_ok=True)
    with db_conn() as conn:
        # SQLite-specific configuration
        if DATABASE_TYPE == "sqlite":
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA cache_size=-64000")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS flights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT,
                flight_date TEXT NOT NULL,
                launch_time TEXT NOT NULL,
                recovery_time TEXT NOT NULL,
                mission_type TEXT NOT NULL CHECK (mission_type IN ('training', 'mission')),
                mission_title TEXT NOT NULL,
                tail_number TEXT NOT NULL,
                origin TEXT NOT NULL,
                route TEXT DEFAULT '',
                destination TEXT NOT NULL,
                crew TEXT NOT NULL,
                pic_name TEXT DEFAULT '',
                pic_is_amc INTEGER NOT NULL DEFAULT 0,
                pilot_name TEXT DEFAULT '',
                crew_members TEXT DEFAULT '',
                non_rated_crew TEXT DEFAULT '',
                is_team_flight INTEGER NOT NULL DEFAULT 0,
                amc_mission_id TEXT DEFAULT '',
                actual_takeoff TEXT DEFAULT '',
                actual_arrival TEXT DEFAULT '',
                closeout_comments TEXT DEFAULT '',
                closed_out INTEGER NOT NULL DEFAULT 0,
                closed_at TEXT DEFAULT '',
                cancel_weather INTEGER NOT NULL DEFAULT 0,
                cancel_maintenance INTEGER NOT NULL DEFAULT 0,
                cancel_other INTEGER NOT NULL DEFAULT 0,
                cancel_other_text TEXT DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('planned', 'approved', 'cancelled')) DEFAULT 'planned',
                notes TEXT DEFAULT '',
                deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at TEXT DEFAULT '',
                atp_company TEXT NOT NULL CHECK (atp_company IN ('A Co', 'B Co', 'C Co')) DEFAULT 'A Co'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'scheduler', 'approver', 'admin')),
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                actor_username TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs_archive (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                actor_username TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS crew (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS aircraft (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tail_number TEXT NOT NULL UNIQUE,
                model TEXT DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

        # Create indexes for performance optimization
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_date ON flights(flight_date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_status ON flights(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_deleted ON flights(deleted)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_mission_id ON flights(mission_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_tail ON flights(tail_number)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flights_date_deleted_status ON flights(flight_date, deleted, status)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_archive_created ON audit_logs_archive(created_at)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_crew_active ON crew(active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_aircraft_active ON aircraft(active)")

        migrate_flights(conn)
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('ui_theme', 'light')"
        )
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('timezone', 'UTC')"
        )

        existing_admin = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
        if not existing_admin:
            default_admin = os.environ.get("DEFAULT_ADMIN_USER", "admin")
            default_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (default_admin, generate_password_hash(default_password)),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (action, entity_type, entity_id, actor_username, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "bootstrap_admin",
                    "user",
                    default_admin,
                    "system",
                    "Default admin created at startup",
                    datetime.utcnow().strftime(DATETIME_FMT),
                ),
            )


def parse_date(value: str | None) -> date:
    if not value:
        return date.today()
    try:
        return datetime.strptime(value, DATE_FMT).date()
    except ValueError:
        return date.today()


def week_start(day: date) -> date:
    return day - timedelta(days=day.weekday())


def load_week(day: date):
    start = week_start(day)
    end = start + timedelta(days=6)
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM flights
            WHERE flight_date BETWEEN ? AND ? AND deleted = 0
            ORDER BY flight_date, launch_time, tail_number
            """,
            (start.strftime(DATE_FMT), end.strftime(DATE_FMT)),
        ).fetchall()
    days = {(start + timedelta(days=i)).strftime(DATE_FMT): [] for i in range(7)}
    for row in rows:
        days[row["flight_date"]].append(row)
    return start, days


def load_daily(day: date):
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM flights
            WHERE flight_date = ? AND deleted = 0
            ORDER BY launch_time, tail_number
            """,
            (day.strftime(DATE_FMT),),
        ).fetchall()
    return [
        dict(row)
        | {
            "actual_hours_decimal": calculate_decimal_hours(row["actual_takeoff"], row["actual_arrival"]),
            "skyvector_url": build_skyvector_url(row["origin"], row["route"], row["destination"]),
            "route_display": " ".join(part for part in [row["origin"], row["route"], row["destination"]] if part),
            "cancel_reasons_display": ", ".join(
                part
                for part in [
                    "Weather" if row["cancel_weather"] else "",
                    "Maintenance" if row["cancel_maintenance"] else "",
                    "Other" if row["cancel_other"] else "",
                ]
                if part
            ),
        }
        for row in rows
    ]


def load_upcoming_48h():
    now = datetime.now()
    if now.time() >= time(6, 0):
        start_day = date.today()
    else:
        start_day = date.today() - timedelta(days=1)
    window_start = datetime.combine(start_day, time(6, 0))
    window_end = window_start + timedelta(days=2) - timedelta(minutes=1)
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM flights
            WHERE datetime(flight_date || ' ' || launch_time) BETWEEN ? AND ? AND deleted = 0
            ORDER BY flight_date, launch_time, tail_number
            """,
            (window_start.strftime(DATETIME_FMT), window_end.strftime(DATETIME_FMT)),
        ).fetchall()
    return [
        dict(row)
        | {
            "actual_hours_decimal": calculate_decimal_hours(row["actual_takeoff"], row["actual_arrival"]),
            "skyvector_url": build_skyvector_url(row["origin"], row["route"], row["destination"]),
            "route_display": " ".join(part for part in [row["origin"], row["route"], row["destination"]] if part),
        }
        for row in rows
    ], window_start, window_end


def load_recent_audit_logs(limit: int = 100):
    with db_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM audit_logs
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def invalidate_cache(cache_key=None):
    """Invalidate cache for a specific key or all keys."""
    if cache_key:
        _cache[cache_key] = {"data": None, "timestamp": 0}
    else:
        # Invalidate all caches
        for key in _cache:
            _cache[key] = {"data": None, "timestamp": 0}


def load_active_crew():
    """Load active crew with caching."""
    now = datetime.utcnow().timestamp()
    cache_entry = _cache["crew"]

    # Return cached data if still valid
    if cache_entry["data"] is not None and (now - cache_entry["timestamp"]) < CACHE_TTL:
        return cache_entry["data"]

    # Fetch fresh data
    with db_conn() as conn:
        data = conn.execute(
            "SELECT id, name FROM crew WHERE active = 1 ORDER BY name"
        ).fetchall()

    # Update cache
    _cache["crew"] = {"data": data, "timestamp": now}
    return data


def load_active_aircraft():
    """Load active aircraft with caching."""
    now = datetime.utcnow().timestamp()
    cache_entry = _cache["aircraft"]

    # Return cached data if still valid
    if cache_entry["data"] is not None and (now - cache_entry["timestamp"]) < CACHE_TTL:
        return cache_entry["data"]

    # Fetch fresh data
    with db_conn() as conn:
        data = conn.execute(
            "SELECT id, tail_number, model FROM aircraft WHERE active = 1 ORDER BY tail_number"
        ).fetchall()

    # Update cache
    _cache["aircraft"] = {"data": data, "timestamp": now}
    return data


def has_role(user, *roles):
    return bool(user and user["active"] and (user["role"] in roles or user["role"] == "admin"))


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user["active"]:
            session.clear()
            return redirect(url_for("login", error="Account is inactive"))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not has_role(user, *roles):
                return redirect(url_for("index"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.context_processor
def inject_user():
    return {
        "auth_user": current_user(),
        "ui_theme": get_app_setting("ui_theme", "light"),
        "app_version": APP_VERSION,
        "app_timezone": get_app_setting("timezone", "UTC")
    }


@app.get("/health")
def health_check():
    """Health check endpoint for Docker/Kubernetes monitoring - simplified for security."""
    from flask import jsonify

    health_status = {
        "status": "healthy",
        "version": APP_VERSION,
        "timestamp": datetime.utcnow().strftime(DATETIME_FMT),
    }

    # Check database connectivity
    try:
        with db_conn() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception:
        health_status["status"] = "unhealthy"
        logger.error("Health check: database connectivity failed", exc_info=True)

    # Check database integrity
    try:
        with db_conn() as conn:
            result = conn.execute("PRAGMA quick_check").fetchone()
            if not result or result[0].lower() != "ok":
                health_status["status"] = "degraded"
                logger.warning(f"Health check: database integrity check returned {result[0] if result else 'unknown'}")
    except Exception:
        health_status["status"] = "unhealthy"
        logger.error("Health check: database integrity check failed", exc_info=True)

    # Check disk space (minimal check without exposing details)
    try:
        disk_usage = shutil.disk_usage(DATA_DIR)
        free_mb = disk_usage.free / (1024 * 1024)

        if free_mb < 50:
            health_status["status"] = "unhealthy"
            logger.error(f"Health check: critically low disk space ({free_mb:.2f} MB free)")
        elif free_mb < 100:
            health_status["status"] = "degraded"
            logger.warning(f"Health check: low disk space ({free_mb:.2f} MB free)")
    except Exception:
        logger.error("Health check: disk space check failed", exc_info=True)

    # Check backup directory exists (without exposing count)
    try:
        if not os.path.exists(BACKUP_DIR):
            logger.warning("Health check: backup directory does not exist")
    except Exception:
        logger.error("Health check: backup directory check failed", exc_info=True)

    # Determine HTTP status code
    status_code = 200 if health_status["status"] == "healthy" else \
                  503 if health_status["status"] == "unhealthy" else 200

    return jsonify(health_status), status_code


@app.get("/login")
def login():
    if current_user():
        return redirect(url_for("index"))
    return render_template("login.html", error=request.args.get("error", ""))


@app.post("/login")
def login_submit():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("login"))

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not user or not user["active"] or not check_password_hash(user["password_hash"], password):
        write_audit("login_failed", "auth", username or "unknown", "Invalid login attempt")
        flash("Invalid credentials or account is inactive.", "error")
        return redirect(url_for("login"))

    session["user_id"] = user["id"]
    write_audit("login_success", "auth", str(user["id"]), f"User {user['username']} signed in")
    flash(f"Welcome back, {user['username']}!", "success")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    user = current_user()
    if user:
        write_audit("logout", "auth", str(user["id"]), f"User {user['username']} signed out")
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


@app.get("/help")
@login_required
def help_page():
    """Help and documentation page for users."""
    return render_template("help.html")


@app.get("/")
@login_required
def index():
    user = current_user()
    selected = parse_date(request.args.get("date"))
    edit_mission_id = request.args.get("edit_mission_id", "").strip()
    start, weekly = load_week(selected)
    daily = load_daily(selected)
    upcoming, window_start, window_end = load_upcoming_48h()
    roster_crew = load_active_crew()
    aircraft_roster = load_active_aircraft()
    edit_flight = None
    form_defaults = {
        "flight_id": "",
        "flight_date": selected.strftime(DATE_FMT),
        "launch_time": "",
        "recovery_time": "",
        "mission_type": "training",
        "mission_title": "",
        "tail_number": "",
        "origin": "KHLR",
        "route": "",
        "destination": "KHLR",
        "pic_name": "",
        "pic_is_amc": 0,
        "pilot_name": "",
        "crew_members": "",
        "non_rated_crew": "",
        "is_team_flight": 0,
        "amc_mission_id": "",
        "notes": "",
        "atp_company": "",
    }

    if edit_mission_id and has_role(user, "scheduler"):
        with db_conn() as conn:
            row = conn.execute("SELECT * FROM flights WHERE mission_id = ? AND deleted = 0", (edit_mission_id,)).fetchone()
        if row:
            edit_flight = dict(row)
            form_defaults.update(
                {
                    "flight_id": row["id"],
                    "flight_date": row["flight_date"],
                    "launch_time": row["launch_time"],
                    "recovery_time": row["recovery_time"],
                    "mission_type": row["mission_type"],
                    "mission_title": row["mission_title"],
                    "tail_number": row["tail_number"],
                    "origin": row["origin"],
                    "route": row["route"],
                    "destination": row["destination"],
                    "pic_name": row["pic_name"],
                    "pic_is_amc": row["pic_is_amc"],
                    "pilot_name": row["pilot_name"],
                    "crew_members": row["crew_members"],
                    "non_rated_crew": row["non_rated_crew"],
                    "is_team_flight": row["is_team_flight"],
                    "amc_mission_id": row["amc_mission_id"],
                    "notes": row["notes"],
                    "atp_company": row["atp_company"],
                }
            )

    return render_template(
        "index.html",
        today=date.today().strftime(DATE_FMT),
        selected_date=selected.strftime(DATE_FMT),
        week_start=start.strftime(DATE_FMT),
        week_end=(start + timedelta(days=6)).strftime(DATE_FMT),
        weekly=weekly,
        daily=daily,
        upcoming=upcoming,
        upcoming_start=window_start.strftime(DATETIME_FMT),
        upcoming_end=window_end.strftime(DATETIME_FMT),
        can_schedule=has_role(user, "scheduler"),
        can_approve=has_role(user, "approver"),
        is_admin=has_role(user, "admin"),
        roster_crew=roster_crew,
        aircraft_roster=aircraft_roster,
        edit_flight=edit_flight,
        form_defaults=form_defaults,
    )


@app.get("/settings")
@login_required
@role_required("admin")
def settings_page():
    return redirect(url_for("settings_admin_page"))


@app.get("/settings/admin")
@login_required
@role_required("admin")
def settings_admin_page():
    with db_conn() as conn:
        users = conn.execute("SELECT id, username, role, active FROM users ORDER BY username").fetchall()
    logs = load_recent_audit_logs()
    export_start = date.today().strftime(DATE_FMT)
    export_end = (date.today() + timedelta(days=7)).strftime(DATE_FMT)
    return render_template(
        "settings_admin.html",
        users=users,
        audit_logs=logs,
        ui_theme=get_app_setting("ui_theme", "light"),
        export_start=export_start,
        export_end=export_end,
    )


@app.get("/settings/crew")
@login_required
@role_required("admin")
def settings_crew_page():
    with db_conn() as conn:
        crew = conn.execute("SELECT id, name, active FROM crew ORDER BY name").fetchall()
    return render_template(
        "settings_crew.html",
        crew=crew,
        ui_theme=get_app_setting("ui_theme", "light"),
    )


@app.get("/settings/aircraft")
@login_required
@role_required("admin")
def settings_aircraft_page():
    with db_conn() as conn:
        aircraft = conn.execute(
            "SELECT id, tail_number, model, active FROM aircraft ORDER BY tail_number"
        ).fetchall()
    return render_template(
        "settings_aircraft.html",
        aircraft=aircraft,
        ui_theme=get_app_setting("ui_theme", "light"),
    )


@app.post("/flights")
@login_required
@role_required("scheduler")
def create_flight():
    flight_id_raw = request.form.get("flight_id", "").strip()
    editing_id = int(flight_id_raw) if flight_id_raw.isdigit() else None
    payload = {
        "flight_date": request.form.get("flight_date", "").strip(),
        "launch_time": request.form.get("launch_time", "").strip(),
        "recovery_time": request.form.get("recovery_time", "").strip(),
        "mission_type": request.form.get("mission_type", "").strip(),
        "mission_title": request.form.get("mission_title", "").strip(),
        "tail_number": request.form.get("tail_number", "").strip(),
        "origin": request.form.get("origin", "").strip(),
        "route": request.form.get("route", "").strip().upper(),
        "destination": request.form.get("destination", "").strip(),
        "pic_name": request.form.get("pic_name", "").strip(),
        "pic_is_amc": coerce_checkbox(request.form.get("pic_is_amc")),
        "pilot_name": request.form.get("pilot_name", "").strip(),
        "crew_members": request.form.get("crew_members", "").strip(),
        "non_rated_crew": request.form.get("non_rated_crew", "").strip(),
        "is_team_flight": coerce_checkbox(request.form.get("is_team_flight")),
        "amc_mission_id": request.form.get("amc_mission_id", "").strip(),
        "notes": request.form.get("notes", "").strip(),
        "atp_company": request.form.get("atp_company", "A Co").strip(),
    }
    payload["crew"] = build_crew_summary(payload)

    required = [
        "flight_date",
        "launch_time",
        "recovery_time",
        "mission_type",
        "mission_title",
        "tail_number",
        "origin",
        "destination",
        "pic_name",
        "pilot_name",
        "atp_company",
    ]
    missing = [k for k in required if not payload[k]]
    if missing:
        flash(f"Missing required fields: {', '.join(missing).replace('_', ' ').title()}", "error")
        return redirect(url_for("index", date=payload["flight_date"] or date.today().strftime(DATE_FMT)))
    if payload["is_team_flight"] and not payload["amc_mission_id"]:
        flash("AMC Mission ID is required for team flights.", "error")
        return redirect(url_for("index", date=payload["flight_date"] or date.today().strftime(DATE_FMT)))

    update_fields = [
        "flight_date",
        "launch_time",
        "recovery_time",
        "mission_type",
        "mission_title",
        "tail_number",
        "origin",
        "route",
        "destination",
        "crew",
        "pic_name",
        "pic_is_amc",
        "pilot_name",
        "crew_members",
        "non_rated_crew",
        "is_team_flight",
        "amc_mission_id",
        "notes",
        "atp_company",
    ]

    if editing_id:
        with db_conn() as conn:
            current = conn.execute("SELECT * FROM flights WHERE id = ? AND deleted = 0", (editing_id,)).fetchone()
            if not current:
                flash("Flight not found or has been deleted.", "error")
                return redirect(url_for("index", date=payload["flight_date"]))

            changed = any(
                str(current[field] if current[field] is not None else "") != str(payload[field] if payload[field] is not None else "")
                for field in update_fields
            )

            conn.execute(
                """
                UPDATE flights
                SET flight_date = ?, launch_time = ?, recovery_time = ?, mission_type = ?, mission_title = ?,
                    tail_number = ?, origin = ?, route = ?, destination = ?, crew = ?, pic_name = ?, pic_is_amc = ?,
                    pilot_name = ?, crew_members = ?, non_rated_crew = ?, is_team_flight = ?, amc_mission_id = ?, notes = ?,
                    atp_company = ?, status = ?, closed_out = ?, closed_at = ?, closeout_comments = ?, actual_takeoff = ?, actual_arrival = ?,
                    cancel_weather = ?, cancel_maintenance = ?, cancel_other = ?, cancel_other_text = ?
                WHERE id = ?
                """,
                (
                    payload["flight_date"],
                    payload["launch_time"],
                    payload["recovery_time"],
                    payload["mission_type"],
                    payload["mission_title"],
                    payload["tail_number"],
                    payload["origin"],
                    payload["route"],
                    payload["destination"],
                    payload["crew"],
                    payload["pic_name"],
                    payload["pic_is_amc"],
                    payload["pilot_name"],
                    payload["crew_members"],
                    payload["non_rated_crew"],
                    payload["is_team_flight"],
                    payload["amc_mission_id"],
                    payload["notes"],
                    payload["atp_company"],
                    "planned" if changed else current["status"],
                    0 if changed else current["closed_out"],
                    "" if changed else current["closed_at"],
                    "" if changed else current["closeout_comments"],
                    "" if changed else current["actual_takeoff"],
                    "" if changed else current["actual_arrival"],
                    0 if changed else current["cancel_weather"],
                    0 if changed else current["cancel_maintenance"],
                    0 if changed else current["cancel_other"],
                    "" if changed else current["cancel_other_text"],
                    editing_id,
                ),
            )

        write_audit(
            "update_flight",
            "flight",
            str(editing_id),
            f"Mission {current['mission_id']} updated; changed={changed}; status={'planned' if changed else current['status']}",
            conn=conn
        )
        if changed:
            flash(f"Mission {current['mission_id']} updated successfully. Status reset to 'planned' for re-approval.", "success")
        else:
            flash(f"Mission {current['mission_id']} updated (no changes detected).", "info")
        return redirect(url_for("index", date=payload["flight_date"]))

    try:
        with db_conn() as conn:
            mission_id = next_mission_id(conn, payload["flight_date"])
            cursor = conn.execute(
                """
                INSERT INTO flights (
                    mission_id, flight_date, launch_time, recovery_time, mission_type, mission_title,
                    tail_number, origin, route, destination, crew, pic_name, pic_is_amc, pilot_name,
                    crew_members, non_rated_crew, is_team_flight, amc_mission_id, notes, atp_company
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mission_id,
                    payload["flight_date"],
                    payload["launch_time"],
                    payload["recovery_time"],
                    payload["mission_type"],
                    payload["mission_title"],
                    payload["tail_number"],
                    payload["origin"],
                    payload["route"],
                    payload["destination"],
                    payload["crew"],
                    payload["pic_name"],
                    payload["pic_is_amc"],
                    payload["pilot_name"],
                    payload["crew_members"],
                    payload["non_rated_crew"],
                    payload["is_team_flight"],
                    payload["amc_mission_id"],
                    payload["notes"],
                    payload["atp_company"],
                ),
            )
            flight_id = cursor.lastrowid
            write_audit(
                "create_flight",
                "flight",
                str(flight_id),
                f"Mission {mission_id} created for {payload['flight_date']} {payload['launch_time']}",
                conn=conn
            )
    except sqlite3.DatabaseError as exc:
        logger.error(f"Flight insert failed, attempting database recovery: {exc}", exc_info=True)
        ensure_db_healthy()
        init_db()
        flash("Database error occurred. Please try again or contact an administrator.", "error")
        return redirect(url_for("index", date=payload["flight_date"]))

    flash(f"Mission {mission_id} created successfully for {payload['flight_date']}.", "success")
    return redirect(url_for("index", date=payload["flight_date"]))


@app.post("/flights/<int:flight_id>/closeout")
@login_required
@role_required("scheduler")
def closeout_flight(flight_id: int):
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    actual_takeoff = request.form.get("actual_takeoff", "").strip()
    actual_arrival = request.form.get("actual_arrival", "").strip()
    closeout_comments = request.form.get("closeout_comments", "").strip()
    cancel_weather = coerce_checkbox(request.form.get("cancel_weather"))
    cancel_maintenance = coerce_checkbox(request.form.get("cancel_maintenance"))
    cancel_other = coerce_checkbox(request.form.get("cancel_other"))
    cancel_other_text = request.form.get("cancel_other_text", "").strip()
    closed_out = coerce_checkbox(request.form.get("closed_out"))

    with db_conn() as conn:
        row = conn.execute("SELECT mission_id, status FROM flights WHERE id = ? AND deleted = 0", (flight_id,)).fetchone()
        if row and row["status"] != "cancelled":
            cancel_weather = 0
            cancel_maintenance = 0
            cancel_other = 0
            cancel_other_text = ""
        conn.execute(
            """
            UPDATE flights
            SET actual_takeoff = ?, actual_arrival = ?, closeout_comments = ?, closed_out = ?,
                closed_at = ?, cancel_weather = ?, cancel_maintenance = ?, cancel_other = ?, cancel_other_text = ?
            WHERE id = ?
            """,
            (
                actual_takeoff,
                actual_arrival,
                closeout_comments,
                closed_out,
                datetime.utcnow().strftime(DATETIME_FMT) if closed_out else "",
                cancel_weather,
                cancel_maintenance,
                cancel_other,
                cancel_other_text,
                flight_id,
            ),
        )
        if row:
            hours = calculate_decimal_hours(actual_takeoff, actual_arrival)
            reasons = ", ".join(
                part
                for part in [
                    "Weather" if cancel_weather else "",
                    "Maintenance" if cancel_maintenance else "",
                    f"Other ({cancel_other_text})" if cancel_other and cancel_other_text else ("Other" if cancel_other else ""),
                ]
                if part
            )
            write_audit(
                "closeout_flight",
                "flight",
                str(flight_id),
                f"{row['mission_id']} closeout={closed_out} actuals {actual_takeoff}-{actual_arrival} ({hours}h); reasons={reasons}; comments={closeout_comments[:120]}",
                conn=conn
            )
    if row:
        if closed_out:
            flash(f"Mission {row['mission_id']} closed out successfully ({hours} flight hours).", "success")
        else:
            flash(f"Mission {row['mission_id']} closeout information updated.", "info")
    return redirect(url_for("index", date=focus_date))


@app.post("/flights/<int:flight_id>/status")
@login_required
@role_required("approver")
def set_status(flight_id: int):
    status = request.form.get("status", "planned")
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    if status not in {"planned", "approved", "cancelled"}:
        flash("Invalid status value.", "error")
        return redirect(url_for("index", date=focus_date))
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ?",
            (flight_id,),
        ).fetchone()
        conn.execute("UPDATE flights SET status = ? WHERE id = ?", (status, flight_id))
        if row:
            write_audit("update_flight_status", "flight", str(flight_id), f"{row['mission_id']} set to {status}", conn=conn)
    if row:
        flash(f"Mission {row['mission_id']} status changed to '{status}'.", "success")
    else:
        flash("Mission not found.", "error")
    return redirect(url_for("index", date=focus_date))


@app.post("/flights/bulk-approve")
@login_required
@role_required("approver", "admin")
def bulk_approve_flights():
    """Approve multiple flights at once (approvers and admins)."""
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    flight_ids = request.form.getlist("flight_ids")

    if not flight_ids:
        flash("No flights selected for approval.", "error")
        return redirect(url_for("index", date=focus_date))

    approved_count = 0
    skipped_count = 0
    mission_ids = []

    with db_conn() as conn:
        for flight_id in flight_ids:
            try:
                # Get flight info and verify it's in planned status
                row = conn.execute(
                    "SELECT mission_id, status FROM flights WHERE id = ? AND deleted = 0",
                    (flight_id,)
                ).fetchone()

                if not row:
                    skipped_count += 1
                    continue

                if row["status"] != "planned":
                    skipped_count += 1
                    logger.warning(f"Skipped flight {row['mission_id']} - status is {row['status']}, not 'planned'")
                    continue

                # Approve the flight
                conn.execute("UPDATE flights SET status = 'approved' WHERE id = ?", (flight_id,))
                mission_ids.append(row["mission_id"])
                write_audit(
                    "bulk_approve_flight",
                    "flight",
                    str(flight_id),
                    f"{row['mission_id']} approved via bulk action",
                    conn=conn
                )
                approved_count += 1

            except Exception as e:
                logger.error(f"Error approving flight {flight_id}: {e}")
                skipped_count += 1

    # Build flash message
    if approved_count > 0:
        missions_str = ", ".join(mission_ids[:5])  # Show first 5
        if len(mission_ids) > 5:
            missions_str += f" and {len(mission_ids) - 5} more"
        flash(f"Approved {approved_count} flight{'s' if approved_count > 1 else ''}: {missions_str}", "success")

    if skipped_count > 0:
        flash(f"Skipped {skipped_count} flight{'s' if skipped_count > 1 else ''} (already approved or not found)", "warning")

    return redirect(url_for("index", date=focus_date))


@app.post("/flights/<int:flight_id>/delete")
@login_required
@role_required("scheduler")
def delete_flight(flight_id: int):
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ? AND deleted = 0",
            (flight_id,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE flights SET deleted = 1, deleted_at = ? WHERE id = ?",
                (datetime.utcnow().strftime(DATETIME_FMT), flight_id),
            )
            write_audit("delete_flight", "flight", str(flight_id), f"Soft deleted mission {row['mission_id']}", conn=conn)
            flash(f"Mission {row['mission_id']} deleted. Can be restored from Settings > Deleted Flights.", "info")
        else:
            flash("Mission not found.", "error")
    return redirect(url_for("index", date=focus_date))


@app.get("/settings/deleted-flights")
@login_required
@role_required("admin")
def deleted_flights_page():
    """View soft-deleted flights for recovery or permanent deletion."""
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM flights
            WHERE deleted = 1
            ORDER BY deleted_at DESC, flight_date DESC
            """
        ).fetchall()
    deleted_flights = [
        dict(row)
        | {
            "actual_hours_decimal": calculate_decimal_hours(row["actual_takeoff"], row["actual_arrival"]),
            "skyvector_url": build_skyvector_url(row["origin"], row["route"], row["destination"]),
        }
        for row in rows
    ]
    return render_template("deleted_flights.html", deleted_flights=deleted_flights)


@app.post("/flights/<int:flight_id>/restore")
@login_required
@role_required("admin")
def restore_flight(flight_id: int):
    """Restore a soft-deleted flight."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ? AND deleted = 1",
            (flight_id,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE flights SET deleted = 0, deleted_at = '' WHERE id = ?",
                (flight_id,),
            )
            write_audit("restore_flight", "flight", str(flight_id), f"Restored mission {row['mission_id']}", conn=conn)
            flash(f"Mission {row['mission_id']} restored successfully.", "success")
        else:
            flash("Mission not found in deleted flights.", "error")
    return redirect(url_for("deleted_flights_page"))


@app.post("/flights/<int:flight_id>/purge")
@login_required
@role_required("admin")
def purge_flight(flight_id: int):
    """Permanently delete a soft-deleted flight."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ? AND deleted = 1",
            (flight_id,),
        ).fetchone()
        if row:
            conn.execute("DELETE FROM flights WHERE id = ?", (flight_id,))
            write_audit("purge_flight", "flight", str(flight_id), f"Permanently deleted mission {row['mission_id']}", conn=conn)
            flash(f"Mission {row['mission_id']} permanently deleted. This action cannot be undone.", "warning")
        else:
            flash("Mission not found in deleted flights.", "error")
    return redirect(url_for("deleted_flights_page"))


@app.get("/daily.csv")
@login_required
def daily_csv():
    selected = parse_date(request.args.get("date"))
    rows = load_daily(selected)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Mission ID",
            "Date",
            "Launch",
            "Recovery",
            "Type",
            "Mission",
            "Tail",
            "Route",
            "SkyVector URL",
            "PIC",
            "PIC AMC",
            "Pilot",
            "Crew Members",
            "Non-rated Crew",
            "Team Flight",
            "AMC Mission ID",
            "Crew Summary",
            "Actual Takeoff",
            "Actual Arrival",
            "Actual Hours (Decimal)",
            "Closed Out",
            "Closed At (UTC)",
            "Closeout Comments",
            "Cancel Weather",
            "Cancel Maintenance",
            "Cancel Other",
            "Cancel Other Details",
            "Status",
            "Notes",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row["mission_id"],
                row["flight_date"],
                row["launch_time"],
                row["recovery_time"],
                row["mission_type"],
                row["mission_title"],
                row["tail_number"],
                " ".join(part for part in [row["origin"], row["route"], row["destination"]] if part),
                build_skyvector_url(row["origin"], row["route"], row["destination"]),
                row["pic_name"],
                "Yes" if row["pic_is_amc"] else "No",
                row["pilot_name"],
                row["crew_members"],
                row["non_rated_crew"],
                "Yes" if row["is_team_flight"] else "No",
                row["amc_mission_id"],
                row["crew"],
                row["actual_takeoff"],
                row["actual_arrival"],
                calculate_decimal_hours(row["actual_takeoff"], row["actual_arrival"]),
                "Yes" if row["closed_out"] else "No",
                row["closed_at"],
                row["closeout_comments"],
                "Yes" if row["cancel_weather"] else "No",
                "Yes" if row["cancel_maintenance"] else "No",
                "Yes" if row["cancel_other"] else "No",
                row["cancel_other_text"],
                row["status"],
                row["notes"],
            ]
        )

    buffer = io.BytesIO(output.getvalue().encode("utf-8"))
    filename = f"daily-missions-{selected.strftime(DATE_FMT)}.csv"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )


@app.post("/settings/users")
@login_required
@role_required("admin")
def settings_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0

    if not username or not password or role not in ROLES:
        flash("Username, password, and valid role are required.", "error")
        return redirect(url_for("settings_admin_page"))

    # Enforce minimum password length (8 characters)
    if len(password) < 8:
        write_audit("create_user_failed", "user", username, "Password too short (minimum 8 characters)")
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for("settings_admin_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, role, active) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, active),
            )
            user_id = cursor.lastrowid
            write_audit("create_user", "user", str(user_id), f"Created {username} as {role} (active={active})", conn=conn)
        flash(f"User '{username}' created successfully with role '{role}'.", "success")
    except sqlite3.IntegrityError:
        write_audit("create_user_failed", "user", username, "Username already exists")
        flash(f"Username '{username}' already exists.", "error")
        return redirect(url_for("settings_admin_page"))
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/role")
@login_required
@role_required("admin")
def settings_update_user_role(user_id: int):
    role = request.form.get("role", "user")
    if role not in ROLES:
        flash("Invalid role selected.", "error")
        return redirect(url_for("settings_admin_page"))

    user = current_user()
    if user and user["id"] == user_id and role != "admin":
        flash("You cannot remove your own admin privileges.", "error")
        return redirect(url_for("settings_admin_page"))

    with db_conn() as conn:
        target = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if target:
            write_audit("update_user_role", "user", str(user_id), f"{target['username']} role {target['role']} -> {role}", conn=conn)
    if target:
        flash(f"User '{target['username']}' role updated to '{role}'.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/active")
@login_required
@role_required("admin")
def settings_update_user_active(user_id: int):
    user = current_user()
    if user and user["id"] == user_id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("settings_admin_page"))

    active = 1 if request.form.get("active", "0") == "1" else 0
    with db_conn() as conn:
        target = conn.execute("SELECT username, active FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (active, user_id))
        if target:
            write_audit(
                "update_user_active",
                "user",
                str(user_id),
                f"{target['username']} active {target['active']} -> {active}",
                conn=conn
            )
    if target:
        status_text = "activated" if active else "deactivated"
        flash(f"User '{target['username']}' {status_text} successfully.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/password")
@login_required
@role_required("admin")
def settings_update_user_password(user_id: int):
    new_password = request.form.get("password", "")
    if not new_password:
        flash("Password cannot be empty.", "error")
        return redirect(url_for("settings_admin_page"))

    # Enforce minimum password length (8 characters)
    if len(new_password) < 8:
        write_audit("update_user_password_failed", "user", str(user_id), "Password too short (minimum 8 characters)")
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for("settings_admin_page"))

    with db_conn() as conn:
        target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        if target:
            write_audit("update_user_password", "user", str(user_id), f"Password reset for {target['username']}", conn=conn)
    if target:
        flash(f"Password updated successfully for user '{target['username']}'.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/crew")
@login_required
@role_required("admin")
def settings_create_crew():
    name = request.form.get("name", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not name:
        flash("Crew member name is required.", "error")
        return redirect(url_for("settings_crew_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO crew (name, active) VALUES (?, ?)",
                (name, active),
            )
            crew_id = cursor.lastrowid
            write_audit("create_crew", "crew", str(crew_id), f"Created crew {name} (active={active})", conn=conn)
        invalidate_cache("crew")
        flash(f"Crew member '{name}' added successfully.", "success")
    except sqlite3.IntegrityError:
        write_audit("create_crew_failed", "crew", name, "Crew member already exists")
        flash(f"Crew member '{name}' already exists.", "error")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/import")
@login_required
@role_required("admin")
def settings_import_crew():
    raw = read_bulk_import_text("crew_import_text", "crew_import_file")
    if not raw:
        flash("No import data provided.", "error")
        return redirect(url_for("settings_crew_page"))

    rows = parse_bulk_rows(raw)
    if not rows:
        flash("No valid data found to import.", "error")
        return redirect(url_for("settings_crew_page"))

    start_idx = 0
    header_tokens = {cell.strip().lower() for cell in rows[0]}
    if "name" in header_tokens or "crew name" in header_tokens:
        start_idx = 1

    created = 0
    updated = 0
    skipped = 0
    with db_conn() as conn:
        for row in rows[start_idx:]:
            name = row[0].strip() if row else ""
            if not name:
                skipped += 1
                continue
            active = parse_active_value(row[1] if len(row) > 1 else None, 1)
            existing = conn.execute("SELECT id FROM crew WHERE name = ?", (name,)).fetchone()
            if existing:
                conn.execute("UPDATE crew SET active = ? WHERE id = ?", (active, existing["id"]))
                updated += 1
            else:
                conn.execute("INSERT INTO crew (name, active) VALUES (?, ?)", (name, active))
                created += 1

    write_audit(
        "bulk_import_crew",
        "crew",
        "bulk",
        f"Crew import complete: created={created}, updated={updated}, skipped={skipped}",
    )
    invalidate_cache("crew")
    flash(f"Crew import complete: {created} created, {updated} updated, {skipped} skipped.", "success")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/<int:crew_id>/active")
@login_required
@role_required("admin")
def settings_update_crew_active(crew_id: int):
    active = 1 if request.form.get("active", "0") == "1" else 0
    with db_conn() as conn:
        target = conn.execute("SELECT name, active FROM crew WHERE id = ?", (crew_id,)).fetchone()
        conn.execute("UPDATE crew SET active = ? WHERE id = ?", (active, crew_id))
        if target:
            write_audit("update_crew_active", "crew", str(crew_id), f"{target['name']} active {target['active']} -> {active}", conn=conn)
    if target:
        invalidate_cache("crew")
        status_text = "activated" if active else "deactivated"
        flash(f"Crew member '{target['name']}' {status_text} successfully.", "success")
    else:
        flash("Crew member not found.", "error")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/<int:crew_id>/update")
@login_required
@role_required("admin")
def settings_update_crew(crew_id: int):
    name = request.form.get("name", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not name:
        flash("Crew member name is required.", "error")
        return redirect(url_for("settings_crew_page"))

    try:
        with db_conn() as conn:
            target = conn.execute("SELECT name, active FROM crew WHERE id = ?", (crew_id,)).fetchone()
            conn.execute(
                "UPDATE crew SET name = ?, active = ? WHERE id = ?",
                (name, active, crew_id),
            )
            if target:
                write_audit(
                    "update_crew",
                    "crew",
                    str(crew_id),
                    f"{target['name']} ({target['active']}) -> {name} ({active})",
                    conn=conn
                )
        if target:
            invalidate_cache("crew")
            flash(f"Crew member '{name}' updated successfully.", "success")
    except sqlite3.IntegrityError:
        write_audit("update_crew_failed", "crew", str(crew_id), f"Duplicate crew name: {name}")
        flash(f"Crew member name '{name}' already exists.", "error")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/<int:crew_id>/delete")
@login_required
@role_required("admin")
def settings_delete_crew(crew_id: int):
    """Delete a crew member if not referenced in any flights."""
    with db_conn() as conn:
        # Get crew info
        crew = conn.execute("SELECT name FROM crew WHERE id = ?", (crew_id,)).fetchone()
        if not crew:
            flash("Crew member not found.", "error")
            return redirect(url_for("settings_crew_page"))

        # Check if crew member is referenced in any flights (including deleted ones)
        # Check multiple crew fields: pic_name, pilot_name, crew_members, non_rated_crew, crew
        flight_count = conn.execute(
            """
            SELECT COUNT(*) as count FROM flights
            WHERE pic_name = ?
               OR pilot_name = ?
               OR crew_members LIKE ?
               OR non_rated_crew LIKE ?
               OR crew LIKE ?
            """,
            (crew['name'], crew['name'], f"%{crew['name']}%", f"%{crew['name']}%", f"%{crew['name']}%"),
        ).fetchone()['count']

        if flight_count > 0:
            logger.warning(
                f"Cannot delete crew member '{crew['name']}' - referenced in {flight_count} flight(s). "
                "Mark as inactive instead."
            )
            write_audit(
                "delete_crew_failed",
                "crew",
                str(crew_id),
                f"Cannot delete '{crew['name']}' - referenced in {flight_count} flight(s)",
                conn=conn
            )
            flash(f"Cannot delete crew member '{crew['name']}' - referenced in {flight_count} flight(s). Mark as inactive instead.", "error")
            return redirect(url_for("settings_crew_page"))

        # Safe to delete
        conn.execute("DELETE FROM crew WHERE id = ?", (crew_id,))
        write_audit("delete_crew", "crew", str(crew_id), f"Deleted crew member: {crew['name']}", conn=conn)
        logger.info(f"Deleted crew member: {crew['name']} (ID: {crew_id})")
        invalidate_cache("crew")
        flash(f"Crew member '{crew['name']}' deleted successfully.", "success")

    return redirect(url_for("settings_crew_page"))


@app.post("/settings/aircraft")
@login_required
@role_required("admin")
def settings_create_aircraft():
    tail_number = request.form.get("tail_number", "").strip().upper()
    model = request.form.get("model", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not tail_number:
        flash("Tail number is required.", "error")
        return redirect(url_for("settings_aircraft_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO aircraft (tail_number, model, active) VALUES (?, ?, ?)",
                (tail_number, model, active),
            )
            aircraft_id = cursor.lastrowid
            write_audit("create_aircraft", "aircraft", str(aircraft_id), f"Added {tail_number} ({model}) active={active}", conn=conn)
        invalidate_cache("aircraft")
        flash(f"Aircraft '{tail_number}' added successfully.", "success")
    except sqlite3.IntegrityError:
        write_audit("create_aircraft_failed", "aircraft", tail_number, "Aircraft already exists")
        flash(f"Aircraft '{tail_number}' already exists.", "error")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/import")
@login_required
@role_required("admin")
def settings_import_aircraft():
    raw = read_bulk_import_text("aircraft_import_text", "aircraft_import_file")
    if not raw:
        flash("No import data provided.", "error")
        return redirect(url_for("settings_aircraft_page"))

    rows = parse_bulk_rows(raw)
    if not rows:
        flash("No valid data found to import.", "error")
        return redirect(url_for("settings_aircraft_page"))

    start_idx = 0
    header = [cell.strip().lower() for cell in rows[0]]
    index = {"tail": 0, "model": 1, "active": 2}
    if any(token in {"tail", "tail_number", "tail number"} for token in header):
        start_idx = 1
        for i, token in enumerate(header):
            if token in {"tail", "tail_number", "tail number"}:
                index["tail"] = i
            elif token == "model":
                index["model"] = i
            elif token == "active":
                index["active"] = i

    created = 0
    updated = 0
    skipped = 0
    with db_conn() as conn:
        for row in rows[start_idx:]:
            tail_number = row[index["tail"]].strip().upper() if len(row) > index["tail"] else ""
            model = row[index["model"]].strip() if len(row) > index["model"] else ""
            active = parse_active_value(row[index["active"]] if len(row) > index["active"] else None, 1)
            if not tail_number:
                skipped += 1
                continue
            existing = conn.execute(
                "SELECT id FROM aircraft WHERE tail_number = ?",
                (tail_number,),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE aircraft SET model = ?, active = ? WHERE id = ?",
                    (model, active, existing["id"]),
                )
                updated += 1
            else:
                conn.execute(
                    "INSERT INTO aircraft (tail_number, model, active) VALUES (?, ?, ?)",
                    (tail_number, model, active),
                )
                created += 1

    write_audit(
        "bulk_import_aircraft",
        "aircraft",
        "bulk",
        f"Aircraft import complete: created={created}, updated={updated}, skipped={skipped}",
    )
    invalidate_cache("aircraft")
    flash(f"Aircraft import complete: {created} created, {updated} updated, {skipped} skipped.", "success")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/<int:aircraft_id>/active")
@login_required
@role_required("admin")
def settings_update_aircraft_active(aircraft_id: int):
    active = 1 if request.form.get("active", "0") == "1" else 0
    with db_conn() as conn:
        target = conn.execute(
            "SELECT tail_number, active FROM aircraft WHERE id = ?",
            (aircraft_id,),
        ).fetchone()
        conn.execute("UPDATE aircraft SET active = ? WHERE id = ?", (active, aircraft_id))
        if target:
            write_audit(
                "update_aircraft_active",
                "aircraft",
                str(aircraft_id),
                f"{target['tail_number']} active {target['active']} -> {active}",
                conn=conn
            )
    if target:
        invalidate_cache("aircraft")
        status_text = "activated" if active else "deactivated"
        flash(f"Aircraft '{target['tail_number']}' {status_text} successfully.", "success")
    else:
        flash("Aircraft not found.", "error")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/<int:aircraft_id>/update")
@login_required
@role_required("admin")
def settings_update_aircraft(aircraft_id: int):
    tail_number = request.form.get("tail_number", "").strip().upper()
    model = request.form.get("model", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not tail_number:
        flash("Tail number is required.", "error")
        return redirect(url_for("settings_aircraft_page"))

    try:
        with db_conn() as conn:
            target = conn.execute(
                "SELECT tail_number, model, active FROM aircraft WHERE id = ?",
                (aircraft_id,),
            ).fetchone()
            conn.execute(
                "UPDATE aircraft SET tail_number = ?, model = ?, active = ? WHERE id = ?",
                (tail_number, model, active, aircraft_id),
            )
            if target:
                write_audit(
                    "update_aircraft",
                    "aircraft",
                    str(aircraft_id),
                    f"{target['tail_number']} {target['model']} ({target['active']}) -> {tail_number} {model} ({active})",
                    conn=conn
                )
        if target:
            invalidate_cache("aircraft")
            flash(f"Aircraft '{tail_number}' updated successfully.", "success")
    except sqlite3.IntegrityError:
        write_audit("update_aircraft_failed", "aircraft", str(aircraft_id), f"Duplicate tail number: {tail_number}")
        flash(f"Aircraft tail number '{tail_number}' already exists.", "error")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/<int:aircraft_id>/delete")
@login_required
@role_required("admin")
def settings_delete_aircraft(aircraft_id: int):
    """Delete an aircraft if not referenced in any flights."""
    with db_conn() as conn:
        # Get aircraft info
        aircraft = conn.execute(
            "SELECT tail_number, model FROM aircraft WHERE id = ?",
            (aircraft_id,)
        ).fetchone()
        if not aircraft:
            flash("Aircraft not found.", "error")
            return redirect(url_for("settings_aircraft_page"))

        # Check if aircraft is referenced in any flights (including deleted ones)
        flight_count = conn.execute(
            "SELECT COUNT(*) as count FROM flights WHERE tail_number = ?",
            (aircraft['tail_number'],)
        ).fetchone()['count']

        if flight_count > 0:
            logger.warning(
                f"Cannot delete aircraft '{aircraft['tail_number']}' - referenced in {flight_count} flight(s). "
                "Mark as inactive instead."
            )
            write_audit(
                "delete_aircraft_failed",
                "aircraft",
                str(aircraft_id),
                f"Cannot delete '{aircraft['tail_number']}' - referenced in {flight_count} flight(s)",
                conn=conn
            )
            flash(f"Cannot delete aircraft '{aircraft['tail_number']}' - referenced in {flight_count} flight(s). Mark as inactive instead.", "error")
            return redirect(url_for("settings_aircraft_page"))

        # Safe to delete
        conn.execute("DELETE FROM aircraft WHERE id = ?", (aircraft_id,))
        write_audit(
            "delete_aircraft",
            "aircraft",
            str(aircraft_id),
            f"Deleted aircraft: {aircraft['tail_number']} {aircraft['model']}",
            conn=conn
        )
        logger.info(f"Deleted aircraft: {aircraft['tail_number']} {aircraft['model']} (ID: {aircraft_id})")
        invalidate_cache("aircraft")
        flash(f"Aircraft '{aircraft['tail_number']}' deleted successfully.", "success")

    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/theme")
@login_required
@role_required("admin")
def settings_theme():
    theme = request.form.get("theme", "light").strip().lower()
    if theme not in {"light", "dark"}:
        flash("Invalid theme selected.", "error")
        return redirect(url_for("settings_admin_page"))
    set_app_setting("ui_theme", theme)
    write_audit("update_ui_theme", "app_settings", "ui_theme", f"Theme set to {theme}")
    flash(f"Theme changed to '{theme}' mode.", "success")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/timezone")
@login_required
@role_required("admin")
def settings_timezone():
    timezone = request.form.get("timezone", "UTC").strip()
    # Validate timezone
    try:
        pytz.timezone(timezone)
    except pytz.exceptions.UnknownTimeZoneError:
        flash("Invalid timezone selected.", "error")
        return redirect(url_for("settings_admin_page"))
    set_app_setting("timezone", timezone)
    write_audit("update_timezone", "app_settings", "timezone", f"Timezone set to {timezone}")
    flash(f"Timezone changed to '{timezone}'.", "success")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/backup/create")
@login_required
@role_required("admin")
def settings_create_backup():
    success, message = create_backup()
    if success:
        rotate_old_backups()
        write_audit("create_backup", "database", "manual", message)
        flash(f"Backup created successfully: {message}", "success")
    else:
        write_audit("create_backup_failed", "database", "manual", message)
        flash(f"Backup failed: {message}", "error")
    return redirect(url_for("settings_admin_page"))


@app.get("/settings/backup/list")
@login_required
@role_required("admin")
def settings_list_backups():
    from flask import jsonify

    if not os.path.exists(BACKUP_DIR):
        return jsonify([])

    backups = []
    for filename in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not filename.startswith("scheduler-backup-") or not filename.endswith(".db"):
            continue

        filepath = os.path.join(BACKUP_DIR, filename)
        stat_info = os.stat(filepath)
        backups.append({
            "filename": filename,
            "size": stat_info.st_size,
            "size_mb": round(stat_info.st_size / (1024 * 1024), 2),
            "created": datetime.fromtimestamp(stat_info.st_mtime).strftime(DATETIME_FMT),
            "age_days": (datetime.utcnow() - datetime.fromtimestamp(stat_info.st_mtime)).days,
        })

    return jsonify(backups)


@app.get("/settings/backup/download/<filename>")
@login_required
@role_required("admin")
def settings_download_backup(filename: str):
    # Security: only allow downloading files that match the backup pattern
    if not filename.startswith("scheduler-backup-") or not filename.endswith(".db"):
        return redirect(url_for("settings_admin_page"))

    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        return redirect(url_for("settings_admin_page"))

    write_audit("download_backup", "database", filename, f"Downloaded backup: {filename}")
    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename,
        mimetype="application/x-sqlite3",
    )


@app.post("/settings/backup/delete/<filename>")
@login_required
@role_required("admin")
def settings_delete_backup(filename: str):
    from flask import jsonify

    # Security: only allow deleting files that match the backup pattern
    if not filename.startswith("scheduler-backup-") or not filename.endswith(".db"):
        return jsonify({"success": False, "error": "Invalid backup filename"}), 400

    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"success": False, "error": "Backup file not found"}), 404

    # Prevent deletion of the most recent backup as a safety measure
    backups = []
    for fname in os.listdir(BACKUP_DIR):
        if fname.startswith("scheduler-backup-") and fname.endswith(".db"):
            backups.append((fname, os.path.getmtime(os.path.join(BACKUP_DIR, fname))))

    if backups:
        backups.sort(key=lambda x: x[1], reverse=True)
        most_recent = backups[0][0]

        if filename == most_recent:
            return jsonify({
                "success": False,
                "error": "Cannot delete the most recent backup. This is a safety measure."
            }), 403

    try:
        os.remove(filepath)
        write_audit("delete_backup", "database", filename, f"Deleted backup: {filename}")
        flash(f"Backup {filename} deleted successfully.", "success")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Failed to delete backup {filename}: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.get("/settings/export/flights.csv")
@login_required
@role_required("admin")
def settings_export_flights_csv():
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))
    if end_date < start_date:
        start_date, end_date = end_date, start_date

    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM flights
            WHERE flight_date BETWEEN ? AND ? AND deleted = 0
            ORDER BY flight_date, launch_time, tail_number
            """,
            (start_date.strftime(DATE_FMT), end_date.strftime(DATE_FMT)),
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Mission ID",
            "Date",
            "Launch",
            "Recovery",
            "Type",
            "Mission",
            "Tail",
            "Origin",
            "Route",
            "Destination",
            "SkyVector URL",
            "PIC",
            "PIC AMC",
            "Pilot",
            "Crew Members",
            "Non-rated Crew",
            "Team Flight",
            "AMC Mission ID",
            "Crew Summary",
            "Actual Takeoff",
            "Actual Arrival",
            "Actual Hours (Decimal)",
            "Closed Out",
            "Closed At (UTC)",
            "Closeout Comments",
            "Cancel Weather",
            "Cancel Maintenance",
            "Cancel Other",
            "Cancel Other Details",
            "Status",
            "Notes",
        ]
    )

    for row in rows:
        writer.writerow(
            [
                row["mission_id"],
                row["flight_date"],
                row["launch_time"],
                row["recovery_time"],
                row["mission_type"],
                row["mission_title"],
                row["tail_number"],
                row["origin"],
                row["route"],
                row["destination"],
                build_skyvector_url(row["origin"], row["route"], row["destination"]),
                row["pic_name"],
                "Yes" if row["pic_is_amc"] else "No",
                row["pilot_name"],
                row["crew_members"],
                row["non_rated_crew"],
                "Yes" if row["is_team_flight"] else "No",
                row["amc_mission_id"],
                row["crew"],
                row["actual_takeoff"],
                row["actual_arrival"],
                calculate_decimal_hours(row["actual_takeoff"], row["actual_arrival"]),
                "Yes" if row["closed_out"] else "No",
                row["closed_at"],
                row["closeout_comments"],
                "Yes" if row["cancel_weather"] else "No",
                "Yes" if row["cancel_maintenance"] else "No",
                "Yes" if row["cancel_other"] else "No",
                row["cancel_other_text"],
                row["status"],
                row["notes"],
            ]
        )

    write_audit(
        "export_flights_csv",
        "flight",
        "range",
        f"Exported flights from {start_date.strftime(DATE_FMT)} to {end_date.strftime(DATE_FMT)} ({len(rows)} rows)",
    )

    buffer = io.BytesIO(output.getvalue().encode("utf-8"))
    filename = f"scheduled-flights-{start_date.strftime(DATE_FMT)}-to-{end_date.strftime(DATE_FMT)}.csv"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )


@app.get("/settings/import-flights")
@login_required
@role_required("admin", "scheduler")
def settings_import_flights_page():
    """Display the mass flight import page."""
    return render_template("import_flights.html", app_version=APP_VERSION)


@app.post("/settings/import-flights")
@login_required
@role_required("admin", "scheduler")
def settings_import_flights():
    """Process CSV flight import with validation and auto-creation of crew/aircraft."""
    # Read uploaded file
    upload = request.files.get("import_file")
    if not upload or not upload.filename:
        flash("No file uploaded.", "error")
        return redirect(url_for("settings_import_flights_page"))

    # Parse CSV
    try:
        payload = upload.read()
        try:
            file_text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            file_text = payload.decode("latin-1", errors="ignore")
    except Exception as e:
        flash(f"Error reading file: {str(e)}", "error")
        return redirect(url_for("settings_import_flights_page"))

    rows = parse_bulk_rows(file_text)
    if not rows:
        flash("No data found in file.", "error")
        return redirect(url_for("settings_import_flights_page"))

    # Expected headers
    expected_headers = [
        "flight_date", "launch_time", "recovery_time", "mission_type", "mission_title",
        "atp_company", "tail_number", "aircraft_model", "origin", "route", "destination",
        "pic_name", "pic_is_amc", "pilot_name", "crew_members", "non_rated_crew",
        "is_team_flight", "amc_mission_id", "notes"
    ]

    # Check if first row is headers
    header_row = rows[0]
    has_headers = any(h.lower().replace("_", " ").replace("-", " ") in [c.lower().replace("_", " ").replace("-", " ") for c in header_row] for h in expected_headers[:5])

    start_idx = 1 if has_headers else 0
    data_rows = rows[start_idx:]

    if not data_rows:
        flash("No data rows found after headers.", "error")
        return redirect(url_for("settings_import_flights_page"))

    # Process rows with validation
    results = []
    success_count = 0
    error_count = 0

    with db_conn() as conn:
        for idx, row in enumerate(data_rows, start=start_idx + 1):
            result = {
                "row_number": idx,
                "status": "success",
                "errors": [],
                "warnings": [],
                "data": {},
                "mission_id": None
            }

            try:
                # Parse and validate required fields
                if len(row) < 11:  # Minimum required fields
                    result["status"] = "error"
                    result["errors"].append(f"Insufficient columns (need at least 11, got {len(row)})")
                    error_count += 1
                    results.append(result)
                    continue

                # Extract fields (with defaults for optional fields)
                flight_date = row[0].strip() if len(row) > 0 else ""
                launch_time = row[1].strip() if len(row) > 1 else ""
                recovery_time = row[2].strip() if len(row) > 2 else ""
                mission_type = row[3].strip().lower() if len(row) > 3 else "training"
                mission_title = row[4].strip() if len(row) > 4 else ""
                atp_company = row[5].strip() if len(row) > 5 else ""
                tail_number = row[6].strip() if len(row) > 6 else ""
                aircraft_model = row[7].strip() if len(row) > 7 else ""
                origin = row[8].strip() if len(row) > 8 else ""
                route = row[9].strip() if len(row) > 9 else ""
                destination = row[10].strip() if len(row) > 10 else ""
                pic_name = row[11].strip() if len(row) > 11 else ""
                pic_is_amc = coerce_checkbox(row[12].strip() if len(row) > 12 else "0")
                pilot_name = row[13].strip() if len(row) > 13 else ""
                crew_members = row[14].strip() if len(row) > 14 else ""
                non_rated_crew = row[15].strip() if len(row) > 15 else ""
                is_team_flight = coerce_checkbox(row[16].strip() if len(row) > 16 else "0")
                amc_mission_id = row[17].strip() if len(row) > 17 else ""
                notes = row[18].strip() if len(row) > 18 else ""

                # Validate required fields
                if not flight_date:
                    result["errors"].append("Missing flight_date")
                if not launch_time:
                    result["errors"].append("Missing launch_time")
                if not recovery_time:
                    result["errors"].append("Missing recovery_time")
                if not mission_title:
                    result["errors"].append("Missing mission_title")
                if not atp_company:
                    result["errors"].append("Missing atp_company")
                elif atp_company not in ["A Co", "B Co", "C Co"]:
                    result["errors"].append(f"Invalid atp_company '{atp_company}' (must be A Co, B Co, or C Co)")
                if not tail_number:
                    result["errors"].append("Missing tail_number")
                if not origin:
                    result["errors"].append("Missing origin")
                if not destination:
                    result["errors"].append("Missing destination")
                if not pic_name:
                    result["errors"].append("Missing pic_name")
                if not pilot_name:
                    result["errors"].append("Missing pilot_name")

                # Validate mission type
                if mission_type not in ["training", "mission"]:
                    result["errors"].append(f"Invalid mission_type '{mission_type}' (must be 'training' or 'mission')")
                    mission_type = "training"  # Default fallback

                # Validate date format
                try:
                    datetime.strptime(flight_date, DATE_FMT)
                except ValueError:
                    result["errors"].append(f"Invalid date format '{flight_date}' (expected YYYY-MM-DD)")

                # Validate time formats
                try:
                    datetime.strptime(launch_time, TIME_FMT)
                except ValueError:
                    result["errors"].append(f"Invalid launch_time format '{launch_time}' (expected HH:MM)")

                try:
                    datetime.strptime(recovery_time, TIME_FMT)
                except ValueError:
                    result["errors"].append(f"Invalid recovery_time format '{recovery_time}' (expected HH:MM)")

                # If validation errors, mark as error and continue
                if result["errors"]:
                    result["status"] = "error"
                    error_count += 1
                    results.append(result)
                    continue

                # Auto-create PIC if doesn't exist
                existing_pic = conn.execute("SELECT id FROM crew WHERE name = ?", (pic_name,)).fetchone()
                if not existing_pic:
                    conn.execute("INSERT INTO crew (name, active) VALUES (?, 1)", (pic_name,))
                    result["warnings"].append(f"Auto-created crew member: {pic_name}")

                # Auto-create Pilot if doesn't exist (and different from PIC)
                if pilot_name != pic_name:
                    existing_pilot = conn.execute("SELECT id FROM crew WHERE name = ?", (pilot_name,)).fetchone()
                    if not existing_pilot:
                        conn.execute("INSERT INTO crew (name, active) VALUES (?, 1)", (pilot_name,))
                        result["warnings"].append(f"Auto-created crew member: {pilot_name}")

                # Auto-create aircraft if doesn't exist
                existing_aircraft = conn.execute("SELECT id FROM aircraft WHERE tail_number = ?", (tail_number,)).fetchone()
                if not existing_aircraft:
                    conn.execute("INSERT INTO aircraft (tail_number, model, active) VALUES (?, ?, 1)", (tail_number, aircraft_model or "Unknown"))
                    result["warnings"].append(f"Auto-created aircraft: {tail_number} ({aircraft_model or 'Unknown'})")

                # Generate mission ID
                mission_id = next_mission_id(conn, flight_date)
                result["mission_id"] = mission_id

                # Build crew summary
                crew_data = {
                    "pic_name": pic_name,
                    "pic_is_amc": pic_is_amc,
                    "pilot_name": pilot_name,
                    "crew_members": crew_members,
                    "non_rated_crew": non_rated_crew
                }
                crew_summary = build_crew_summary(crew_data)

                # Insert flight
                conn.execute(
                    """
                    INSERT INTO flights (
                        mission_id, flight_date, launch_time, recovery_time, mission_type, mission_title,
                        tail_number, origin, route, destination, crew, pic_name, pic_is_amc, pilot_name,
                        crew_members, non_rated_crew, is_team_flight, amc_mission_id, notes, atp_company
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mission_id, flight_date, launch_time, recovery_time, mission_type, mission_title,
                        tail_number, origin, route, destination, crew_summary, pic_name, pic_is_amc, pilot_name,
                        crew_members, non_rated_crew, is_team_flight, amc_mission_id, notes, atp_company
                    )
                )

                # Store parsed data for display
                result["data"] = {
                    "mission_id": mission_id,
                    "flight_date": flight_date,
                    "launch_time": launch_time,
                    "recovery_time": recovery_time,
                    "mission_type": mission_type,
                    "mission_title": mission_title,
                    "atp_company": atp_company,
                    "tail_number": tail_number,
                    "pic_name": pic_name,
                    "pilot_name": pilot_name
                }

                success_count += 1

            except Exception as e:
                result["status"] = "error"
                result["errors"].append(f"Unexpected error: {str(e)}")
                error_count += 1

            results.append(result)

    # Invalidate caches
    invalidate_cache("crew")
    invalidate_cache("aircraft")

    # Write audit log
    write_audit(
        "bulk_import_flights",
        "flight",
        "bulk",
        f"Flight import complete: {success_count} imported, {error_count} failed"
    )

    # Render results page
    return render_template(
        "import_flights.html",
        results=results,
        success_count=success_count,
        error_count=error_count,
        total_count=len(data_rows),
        app_version=APP_VERSION
    )


init_db()

# Create initial backup on startup
logger.info("Application starting up...")
success, message = create_backup()
if success:
    logger.info(f"Startup backup: {message}")
    rotate_old_backups()
else:
    logger.warning(f"Startup backup failed: {message}")

# Start daily backup scheduler
start_backup_scheduler()

# For local development only - production uses Gunicorn (see Dockerfile)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
