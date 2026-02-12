import csv
import io
import os
import sqlite3
import sys
from datetime import date, datetime, time, timedelta
from functools import wraps
from urllib.parse import quote

from flask import Flask, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me")

DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "scheduler.db")
DATE_FMT = "%Y-%m-%d"
DATETIME_FMT = "%Y-%m-%d %H:%M"
ROLES = {"user", "scheduler", "approver", "admin"}
SKYVECTOR_LL = "31.144812341768187,-97.717529291779"
SKYVECTOR_CHART = "301"
SKYVECTOR_ZOOM = "2"


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def quarantine_corrupt_db(reason: str):
    if not os.path.exists(DB_PATH):
        return
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{DB_PATH}.corrupt-{stamp}.bak"
    os.replace(DB_PATH, backup_path)
    print(f"[db-recovery] Quarantined corrupt database to {backup_path}. Reason: {reason}", file=sys.stderr)


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


def write_audit(action: str, entity_type: str, entity_id: str, details: str):
    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (action, entity_type, entity_id, actor_username, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                entity_type,
                entity_id,
                actor_name(),
                details[:1000],
                datetime.utcnow().strftime(DATETIME_FMT),
            ),
        )


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
                notes TEXT DEFAULT ''
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

        migrate_flights(conn)
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('ui_theme', 'light')"
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
            WHERE flight_date BETWEEN ? AND ?
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
            WHERE flight_date = ?
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
            WHERE datetime(flight_date || ' ' || launch_time) BETWEEN ? AND ?
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


def load_active_crew():
    with db_conn() as conn:
        return conn.execute(
            "SELECT id, name FROM crew WHERE active = 1 ORDER BY name"
        ).fetchall()


def load_active_aircraft():
    with db_conn() as conn:
        return conn.execute(
            "SELECT id, tail_number, model FROM aircraft WHERE active = 1 ORDER BY tail_number"
        ).fetchall()


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
    return {"auth_user": current_user(), "ui_theme": get_app_setting("ui_theme", "light")}


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
        return redirect(url_for("login", error="Username and password required"))

    with db_conn() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not user or not user["active"] or not check_password_hash(user["password_hash"], password):
        write_audit("login_failed", "auth", username or "unknown", "Invalid login attempt")
        return redirect(url_for("login", error="Invalid credentials"))

    session["user_id"] = user["id"]
    write_audit("login_success", "auth", str(user["id"]), f"User {user['username']} signed in")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    user = current_user()
    if user:
        write_audit("logout", "auth", str(user["id"]), f"User {user['username']} signed out")
    session.clear()
    return redirect(url_for("login"))


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
    }

    if edit_mission_id and has_role(user, "scheduler"):
        with db_conn() as conn:
            row = conn.execute("SELECT * FROM flights WHERE mission_id = ?", (edit_mission_id,)).fetchone()
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
    ]
    missing = [k for k in required if not payload[k]]
    if missing:
        return redirect(url_for("index", date=payload["flight_date"] or date.today().strftime(DATE_FMT)))
    if payload["is_team_flight"] and not payload["amc_mission_id"]:
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
    ]

    if editing_id:
        with db_conn() as conn:
            current = conn.execute("SELECT * FROM flights WHERE id = ?", (editing_id,)).fetchone()
            if not current:
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
                    status = ?, closed_out = ?, closed_at = ?, closeout_comments = ?, actual_takeoff = ?, actual_arrival = ?,
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
        )
        return redirect(url_for("index", date=payload["flight_date"]))

    try:
        with db_conn() as conn:
            mission_id = next_mission_id(conn, payload["flight_date"])
            cursor = conn.execute(
                """
                INSERT INTO flights (
                    mission_id, flight_date, launch_time, recovery_time, mission_type, mission_title,
                    tail_number, origin, route, destination, crew, pic_name, pic_is_amc, pilot_name,
                    crew_members, non_rated_crew, is_team_flight, amc_mission_id, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            flight_id = cursor.lastrowid
    except sqlite3.DatabaseError as exc:
        print(f"[db-recovery] Flight insert failed: {exc}", file=sys.stderr)
        ensure_db_healthy()
        init_db()
        return redirect(url_for("index", date=payload["flight_date"]))

    write_audit(
        "create_flight",
        "flight",
        str(flight_id),
        f"Mission {mission_id} created for {payload['flight_date']} {payload['launch_time']}",
    )
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
        row = conn.execute("SELECT mission_id, status FROM flights WHERE id = ?", (flight_id,)).fetchone()
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
        )
    return redirect(url_for("index", date=focus_date))


@app.post("/flights/<int:flight_id>/status")
@login_required
@role_required("approver")
def set_status(flight_id: int):
    status = request.form.get("status", "planned")
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    if status not in {"planned", "approved", "cancelled"}:
        return redirect(url_for("index", date=focus_date))
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ?",
            (flight_id,),
        ).fetchone()
        conn.execute("UPDATE flights SET status = ? WHERE id = ?", (status, flight_id))
    if row:
        write_audit("update_flight_status", "flight", str(flight_id), f"{row['mission_id']} set to {status}")
    return redirect(url_for("index", date=focus_date))


@app.post("/flights/<int:flight_id>/delete")
@login_required
@role_required("scheduler")
def delete_flight(flight_id: int):
    focus_date = request.form.get("focus_date", date.today().strftime(DATE_FMT))
    with db_conn() as conn:
        row = conn.execute(
            "SELECT mission_id FROM flights WHERE id = ?",
            (flight_id,),
        ).fetchone()
        conn.execute("DELETE FROM flights WHERE id = ?", (flight_id,))
    if row:
        write_audit("delete_flight", "flight", str(flight_id), f"Deleted mission {row['mission_id']}")
    return redirect(url_for("index", date=focus_date))


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
        return redirect(url_for("settings_admin_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, role, active) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, active),
            )
            user_id = cursor.lastrowid
        write_audit("create_user", "user", str(user_id), f"Created {username} as {role} (active={active})")
    except sqlite3.IntegrityError:
        write_audit("create_user_failed", "user", username, "Username already exists")
        return redirect(url_for("settings_admin_page"))
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/role")
@login_required
@role_required("admin")
def settings_update_user_role(user_id: int):
    role = request.form.get("role", "user")
    if role not in ROLES:
        return redirect(url_for("settings_admin_page"))

    user = current_user()
    if user and user["id"] == user_id and role != "admin":
        return redirect(url_for("settings_admin_page"))

    with db_conn() as conn:
        target = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    if target:
        write_audit("update_user_role", "user", str(user_id), f"{target['username']} role {target['role']} -> {role}")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/active")
@login_required
@role_required("admin")
def settings_update_user_active(user_id: int):
    user = current_user()
    if user and user["id"] == user_id:
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
        )
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/users/<int:user_id>/password")
@login_required
@role_required("admin")
def settings_update_user_password(user_id: int):
    new_password = request.form.get("password", "")
    if not new_password:
        return redirect(url_for("settings_admin_page"))

    with db_conn() as conn:
        target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
    if target:
        write_audit("update_user_password", "user", str(user_id), f"Password reset for {target['username']}")
    return redirect(url_for("settings_admin_page"))


@app.post("/settings/crew")
@login_required
@role_required("admin")
def settings_create_crew():
    name = request.form.get("name", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not name:
        return redirect(url_for("settings_crew_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO crew (name, active) VALUES (?, ?)",
                (name, active),
            )
            crew_id = cursor.lastrowid
        write_audit("create_crew", "crew", str(crew_id), f"Created crew {name} (active={active})")
    except sqlite3.IntegrityError:
        write_audit("create_crew_failed", "crew", name, "Crew member already exists")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/import")
@login_required
@role_required("admin")
def settings_import_crew():
    raw = read_bulk_import_text("crew_import_text", "crew_import_file")
    if not raw:
        return redirect(url_for("settings_crew_page"))

    rows = parse_bulk_rows(raw)
    if not rows:
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
        write_audit("update_crew_active", "crew", str(crew_id), f"{target['name']} active {target['active']} -> {active}")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/crew/<int:crew_id>/update")
@login_required
@role_required("admin")
def settings_update_crew(crew_id: int):
    name = request.form.get("name", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not name:
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
            )
    except sqlite3.IntegrityError:
        write_audit("update_crew_failed", "crew", str(crew_id), f"Duplicate crew name: {name}")
    return redirect(url_for("settings_crew_page"))


@app.post("/settings/aircraft")
@login_required
@role_required("admin")
def settings_create_aircraft():
    tail_number = request.form.get("tail_number", "").strip().upper()
    model = request.form.get("model", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not tail_number:
        return redirect(url_for("settings_aircraft_page"))

    try:
        with db_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO aircraft (tail_number, model, active) VALUES (?, ?, ?)",
                (tail_number, model, active),
            )
            aircraft_id = cursor.lastrowid
        write_audit("create_aircraft", "aircraft", str(aircraft_id), f"Added {tail_number} ({model}) active={active}")
    except sqlite3.IntegrityError:
        write_audit("create_aircraft_failed", "aircraft", tail_number, "Aircraft already exists")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/import")
@login_required
@role_required("admin")
def settings_import_aircraft():
    raw = read_bulk_import_text("aircraft_import_text", "aircraft_import_file")
    if not raw:
        return redirect(url_for("settings_aircraft_page"))

    rows = parse_bulk_rows(raw)
    if not rows:
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
        )
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/aircraft/<int:aircraft_id>/update")
@login_required
@role_required("admin")
def settings_update_aircraft(aircraft_id: int):
    tail_number = request.form.get("tail_number", "").strip().upper()
    model = request.form.get("model", "").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0
    if not tail_number:
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
            )
    except sqlite3.IntegrityError:
        write_audit("update_aircraft_failed", "aircraft", str(aircraft_id), f"Duplicate tail number: {tail_number}")
    return redirect(url_for("settings_aircraft_page"))


@app.post("/settings/theme")
@login_required
@role_required("admin")
def settings_theme():
    theme = request.form.get("theme", "light").strip().lower()
    if theme not in {"light", "dark"}:
        return redirect(url_for("settings_admin_page"))
    set_app_setting("ui_theme", theme)
    write_audit("update_ui_theme", "app_settings", "ui_theme", f"Theme set to {theme}")
    return redirect(url_for("settings_admin_page"))


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
            WHERE flight_date BETWEEN ? AND ?
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


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
