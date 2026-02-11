import csv
import io
import os
import sqlite3
from datetime import date, datetime, time, timedelta
from functools import wraps

from flask import Flask, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me")

DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "scheduler.db")
DATE_FMT = "%Y-%m-%d"
DATETIME_FMT = "%Y-%m-%d %H:%M"
ROLES = {"user", "scheduler", "approver", "admin"}


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def migrate_flights(conn: sqlite3.Connection):
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(flights)").fetchall()}
    if "mission_id" not in cols:
        conn.execute("ALTER TABLE flights ADD COLUMN mission_id TEXT")

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
                destination TEXT NOT NULL,
                crew TEXT NOT NULL,
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

        migrate_flights(conn)

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
    return rows


def load_upcoming_48h():
    now = datetime.now()
    window_start = datetime.combine(date.today(), time.min)
    window_end = now + timedelta(hours=48)
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
    return rows, window_start, window_end


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
    return {"auth_user": current_user()}


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
    start, weekly = load_week(selected)
    daily = load_daily(selected)
    upcoming, window_start, window_end = load_upcoming_48h()
    admin_users = []
    audit_logs = []

    if has_role(user, "admin"):
        with db_conn() as conn:
            admin_users = conn.execute(
                "SELECT id, username, role, active FROM users ORDER BY username"
            ).fetchall()
        audit_logs = load_recent_audit_logs()

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
        admin_users=admin_users,
        audit_logs=audit_logs,
    )


@app.post("/flights")
@login_required
@role_required("scheduler")
def create_flight():
    payload = {
        "flight_date": request.form.get("flight_date", "").strip(),
        "launch_time": request.form.get("launch_time", "").strip(),
        "recovery_time": request.form.get("recovery_time", "").strip(),
        "mission_type": request.form.get("mission_type", "").strip(),
        "mission_title": request.form.get("mission_title", "").strip(),
        "tail_number": request.form.get("tail_number", "").strip(),
        "origin": request.form.get("origin", "").strip(),
        "destination": request.form.get("destination", "").strip(),
        "crew": request.form.get("crew", "").strip(),
        "notes": request.form.get("notes", "").strip(),
    }

    missing = [k for k, v in payload.items() if k != "notes" and not v]
    if missing:
        return redirect(url_for("index", date=payload["flight_date"] or date.today().strftime(DATE_FMT)))

    with db_conn() as conn:
        mission_id = next_mission_id(conn, payload["flight_date"])
        cursor = conn.execute(
            """
            INSERT INTO flights (
                mission_id, flight_date, launch_time, recovery_time, mission_type, mission_title,
                tail_number, origin, destination, crew, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                payload["destination"],
                payload["crew"],
                payload["notes"],
            ),
        )
        flight_id = cursor.lastrowid

    write_audit(
        "create_flight",
        "flight",
        str(flight_id),
        f"Mission {mission_id} created for {payload['flight_date']} {payload['launch_time']}",
    )
    return redirect(url_for("index", date=payload["flight_date"]))


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
            "Crew",
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
                f'{row["origin"]}-{row["destination"]}',
                row["crew"],
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


@app.post("/admin/users")
@login_required
@role_required("admin")
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user").strip()
    active = 1 if request.form.get("active", "1") == "1" else 0

    if not username or not password or role not in ROLES:
        return redirect(url_for("index"))

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
        return redirect(url_for("index"))
    return redirect(url_for("index"))


@app.post("/admin/users/<int:user_id>/role")
@login_required
@role_required("admin")
def update_user_role(user_id: int):
    role = request.form.get("role", "user")
    if role not in ROLES:
        return redirect(url_for("index"))

    user = current_user()
    if user and user["id"] == user_id and role != "admin":
        return redirect(url_for("index"))

    with db_conn() as conn:
        target = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    if target:
        write_audit("update_user_role", "user", str(user_id), f"{target['username']} role {target['role']} -> {role}")
    return redirect(url_for("index"))


@app.post("/admin/users/<int:user_id>/active")
@login_required
@role_required("admin")
def update_user_active(user_id: int):
    user = current_user()
    if user and user["id"] == user_id:
        return redirect(url_for("index"))

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
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
