import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import time
import uuid
from email import policy
from email.parser import BytesParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PORTAL_DATA_DIR", ROOT / "data")).resolve()
DB_PATH = DATA_DIR / "portal.sqlite3"
UPLOAD_DIR = DATA_DIR / "uploads"
MAX_JSON_BYTES = 32_768
MAX_REPORT_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 50 * 1024 * 1024
SESSION_SECONDS = 60 * 60 * 12
PASSWORD_ITERATIONS = 310_000
COOKIE_SECURE = os.environ.get("PORTAL_COOKIE_SECURE", "0").lower() in ("1", "true", "yes")
LOGIN_LIMITS = {}
ALLOWED_MEDIA = {"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/webm", "video/quicktime"}


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','employee')),
                job_title TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                salary REAL NOT NULL DEFAULT 0,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payroll (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                period TEXT NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS expenses (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                category TEXT NOT NULL, description TEXT NOT NULL, amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                date TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL, site TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                date TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
                completed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS time_entries (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                date TEXT NOT NULL, time_in TEXT NOT NULL, time_out TEXT NOT NULL DEFAULT '',
                UNIQUE(staff_id, date)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY, staff_id TEXT NOT NULL REFERENCES users(id),
                date TEXT NOT NULL, site TEXT NOT NULL, task TEXT NOT NULL,
                work TEXT NOT NULL, next_steps TEXT NOT NULL,
                sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS report_files (
                id TEXT PRIMARY KEY, report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL, content_type TEXT NOT NULL, stored_name TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_entries_date ON time_entries(date);
            CREATE INDEX IF NOT EXISTS idx_reports_staff ON reports(staff_id, date);
            CREATE INDEX IF NOT EXISTS idx_tasks_staff ON tasks(staff_id, date);
        """)


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password, password_hash, password_salt):
    try:
        actual, _ = hash_password(password, bytes.fromhex(password_salt))
        return secrets.compare_digest(actual, password_hash)
    except (ValueError, TypeError):
        return False


def json_response(handler, status, payload, headers=None):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    if headers:
        for key, value in headers.items():
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def body_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0 or length > MAX_JSON_BYTES:
        raise ValueError("Request body is missing or too large")
    value = json.loads(handler.rfile.read(length))
    if not isinstance(value, dict):
        raise ValueError("Invalid request body")
    return value


def clean_text(value, label, limit, required=True):
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = value.strip()
    if required and not value:
        raise ValueError(label + " is required")
    if len(value) > limit:
        raise ValueError(label + " is too long")
    return value


def clean_amount(value):
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise ValueError("Amount must be a number")
    if amount < 0 or amount > 100_000_000:
        raise ValueError("Amount is outside the allowed range")
    return amount


def email_value(value):
    email = clean_text(value, "Email", 120).lower()
    if "@" not in email or email.startswith("@") or email.endswith("@") or any(ch.isspace() for ch in email):
        raise ValueError("Enter a valid email address")
    return email


def public_user(row):
    return {"id": row["id"], "name": row["name"], "role": row["role"], "roleTitle": row["job_title"], "email": row["email"], "salary": row["salary"]}


def cookie_user(handler, db):
    cookies = SimpleCookie()
    try:
        cookies.load(handler.headers.get("Cookie", ""))
        token = cookies["infinite_session"].value
    except (KeyError, Exception):
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute("SELECT users.*, sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?", (token_hash,)).fetchone()
    if row is None or row["expires_at"] <= int(time.time()):
        if row is not None:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            db.commit()
        return None
    return row


def require_user(handler, db, admin=False):
    user = cookie_user(handler, db)
    if user is None:
        json_response(handler, 401, {"error": "Please sign in"})
        return None
    if admin and user["role"] != "admin":
        json_response(handler, 403, {"error": "Administrator access required"})
        return None
    return user


def same_origin(handler):
    origin = handler.headers.get("Origin")
    if not origin:
        return True
    parsed = urlsplit(origin)
    host = handler.headers.get("Host", "").lower()
    return parsed.netloc.lower() == host and parsed.scheme in ("http", "https")


def data_for_user(db, user):
    admin = user["role"] == "admin"
    staff_rows = db.execute("SELECT * FROM users WHERE role='employee' ORDER BY name").fetchall() if admin else [db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()]
    ids = [row["id"] for row in staff_rows if row]
    if not ids:
        ids = [""]
    marks = ",".join("?" for _ in ids)
    data = {"currentUser": public_user(user), "staff": [public_user(row) for row in staff_rows if row]}
    query_map = {
        "payroll": ("SELECT * FROM payroll WHERE staff_id IN (" + marks + ") ORDER BY created_at DESC", ids),
        "expenses": ("SELECT * FROM expenses WHERE staff_id IN (" + marks + ") ORDER BY created_at DESC", ids),
        "schedules": ("SELECT * FROM schedules WHERE staff_id IN (" + marks + ") ORDER BY date", ids),
        "tasks": ("SELECT * FROM tasks WHERE staff_id IN (" + marks + ") ORDER BY date", ids),
        "timeEntries": ("SELECT * FROM time_entries WHERE staff_id IN (" + marks + ") ORDER BY date DESC", ids),
        "reports": ("SELECT * FROM reports WHERE staff_id IN (" + marks + ") ORDER BY sent_at DESC", ids),
    }
    for key, (sql, params) in query_map.items():
        records = [dict(row) for row in db.execute(sql, params).fetchall()]
        for record in records:
            if "staff_id" in record:
                record["staffId"] = record.pop("staff_id")
            if "time_in" in record:
                record["timeIn"] = record.pop("time_in")
            if "time_out" in record:
                record["timeOut"] = record.pop("time_out")
            if "created_at" in record:
                record["createdAt"] = record.pop("created_at")
        data[key] = records
    for record in data["tasks"]:
        record["completed"] = bool(record["completed"])
    for report in data["reports"]:
        report["next"] = report.pop("next_steps")
        report["sentAt"] = report.pop("sent_at")
        report["files"] = [{"id": row["id"], "name": row["original_name"], "type": row["content_type"], "url": "/uploads/" + row["id"]} for row in db.execute("SELECT * FROM report_files WHERE report_id=?", (report["id"],)).fetchall()]
    return data


def _send_file(handler, path, content_type, filename=None):
    try:
        size = path.stat().st_size
        stream = path.open("rb")
    except OSError:
        json_response(handler, 404, {"error": "File not found"})
        return
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(size))
    handler.send_header("Cache-Control", "private, no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    if filename:
        handler.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + __import__("urllib.parse", fromlist=["quote"]).quote(filename))
    handler.end_headers()
    with stream:
        while True:
            block = stream.read(64 * 1024)
            if not block:
                break
            handler.wfile.write(block)


def handle_get(handler, path):
    if not path.startswith("/api/portal/") and not path.startswith("/uploads/"):
        return False
    with connect() as db:
        if path == "/api/portal/status":
            setup_required = db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone() is None
            user = cookie_user(handler, db)
            json_response(handler, 200, {"setupRequired": setup_required, "user": public_user(user) if user else None})
            return True
        if path == "/api/portal/data":
            user = require_user(handler, db)
            if user:
                json_response(handler, 200, data_for_user(db, user))
            return True
        if path.startswith("/uploads/"):
            file_id = path.removeprefix("/uploads/")
            user = require_user(handler, db)
            if user is None:
                return True
            row = db.execute("SELECT report_files.*, reports.staff_id FROM report_files JOIN reports ON reports.id=report_files.report_id WHERE report_files.id=?", (file_id,)).fetchone()
            if row is None or (user["role"] != "admin" and row["staff_id"] != user["id"]):
                json_response(handler, 404, {"error": "File not found"})
                return True
            _send_file(handler, UPLOAD_DIR / row["stored_name"], row["content_type"], row["original_name"])
            return True
    return False


def handle_post(handler, path):
    if not path.startswith("/api/portal/"):
        return False
    if not same_origin(handler):
        json_response(handler, 403, {"error": "Cross-origin request denied"})
        return True
    if path == "/api/portal/setup":
        try:
            body = body_json(handler)
            name = clean_text(body.get("name"), "Name", 80)
            email = email_value(body.get("email"))
            password = clean_text(body.get("password"), "Password", 256)
            if len(password) < 12:
                raise ValueError("Password must be at least 12 characters")
            digest, salt = hash_password(password)
            user_id = str(uuid.uuid4())
            with connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
                    json_response(handler, 409, {"error": "Administrator setup is already complete"})
                    return True
                db.execute("INSERT INTO users(id,name,role,email,password_hash,password_salt) VALUES(?,?,'admin',?,?,?)", (user_id, name, email, digest, salt))
                db.commit()
                return create_session(handler, db, user_id)
        except sqlite3.IntegrityError:
            json_response(handler, 409, {"error": "That email address is already registered"})
        except (ValueError, json.JSONDecodeError) as error:
            json_response(handler, 400, {"error": str(error)})
        return True

    if path == "/api/portal/login":
        try:
            body = body_json(handler)
            email = email_value(body.get("email"))
            password = clean_text(body.get("password"), "Password", 256)
        except (ValueError, json.JSONDecodeError) as error:
            json_response(handler, 400, {"error": str(error)})
            return True
        ip = handler.client_address[0]
        now = time.monotonic()
        attempts = [stamp for stamp in LOGIN_LIMITS.get(ip, []) if now - stamp < 300]
        if len(attempts) >= 10:
            json_response(handler, 429, {"error": "Too many sign-in attempts. Wait a few minutes and try again."})
            return True
        attempts.append(now)
        LOGIN_LIMITS[ip] = attempts
        with connect() as db:
            row = db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
            if row is None or not verify_password(password, row["password_hash"], row["password_salt"]):
                json_response(handler, 401, {"error": "Email or password was not recognized"})
                return True
            LOGIN_LIMITS[ip] = []
            return create_session(handler, db, row["id"])

    if path == "/api/portal/logout":
        cookies = SimpleCookie()
        cookies.load(handler.headers.get("Cookie", ""))
        token = cookies.get("infinite_session")
        if token:
            with connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.value.encode()).hexdigest(),))
                db.commit()
        expired_cookie = "infinite_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        if COOKIE_SECURE:
            expired_cookie += "; Secure"
        json_response(handler, 200, {"ok": True}, {"Set-Cookie": expired_cookie})
        return True

    with connect() as db:
        admin = path not in ("/api/portal/time/clock", "/api/portal/reports", "/api/portal/password") and not path.startswith("/api/portal/tasks/")
        user = require_user(handler, db, admin=admin)
        if user is None:
            return True
        if path == "/api/portal/password":
            return change_password(handler, db, user)
        if path == "/api/portal/staff":
            return add_staff(handler, db)
        if path == "/api/portal/payroll":
            return add_payroll(handler, db)
        if path == "/api/portal/expenses":
            return add_expense(handler, db)
        if path.startswith("/api/portal/expenses/") and path.endswith("/paid"):
            item_id = path.split("/")[-2]
            db.execute("UPDATE expenses SET status='Paid' WHERE id=?", (item_id,))
            if db.total_changes == 0:
                json_response(handler, 404, {"error": "Expense not found"})
            else:
                db.commit()
                json_response(handler, 200, {"ok": True})
            return True
        if path == "/api/portal/schedules":
            return add_schedule(handler, db)
        if path == "/api/portal/tasks":
            return add_task(handler, db)
        if path.startswith("/api/portal/tasks/") and path.endswith("/complete"):
            task_id = path.split("/")[-2]
            if user["role"] == "admin":
                result = db.execute("UPDATE tasks SET completed=1 WHERE id=?", (task_id,))
            else:
                result = db.execute("UPDATE tasks SET completed=1 WHERE id=? AND staff_id=?", (task_id, user["id"]))
            if result.rowcount == 0:
                json_response(handler, 404, {"error": "Task not found"})
            else:
                db.commit()
                json_response(handler, 200, {"ok": True})
            return True
        if path == "/api/portal/time/clock":
            return clock_time(handler, db, user)
        if path == "/api/portal/reports":
            return add_report(handler, db, user)
    return False


def create_session(handler, db, user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = int(time.time()) + SESSION_SECONDS
    db.execute("DELETE FROM sessions WHERE expires_at<=?", (int(time.time()),))
    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (token_hash, user_id, expires))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    cookie = "infinite_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + str(SESSION_SECONDS)
    if COOKIE_SECURE:
        cookie += "; Secure"
    json_response(handler, 200, {"user": public_user(user)}, {"Set-Cookie": cookie})
    return True


def change_password(handler, db, user):
    try:
        body = body_json(handler)
        old_password = clean_text(body.get("currentPassword"), "Current password", 256)
        new_password = clean_text(body.get("newPassword"), "New password", 256)
        if len(new_password) < 12:
            raise ValueError("New password must be at least 12 characters")
        if not verify_password(old_password, user["password_hash"], user["password_salt"]):
            json_response(handler, 401, {"error": "Current password is incorrect"})
            return True
        digest, salt = hash_password(new_password)
        token_cookie = SimpleCookie()
        token_cookie.load(handler.headers.get("Cookie", ""))
        current_token = token_cookie.get("infinite_session")
        current_hash = hashlib.sha256(current_token.value.encode()).hexdigest() if current_token else ""
        db.execute("UPDATE users SET password_hash=?,password_salt=? WHERE id=?", (digest, salt, user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user["id"], current_hash))
        db.commit()
        json_response(handler, 200, {"ok": True})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def admin_staff_exists(db, staff_id):
    return db.execute("SELECT 1 FROM users WHERE id=? AND role='employee'", (staff_id,)).fetchone() is not None


def read_body(handler, maximum):
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0 or length > maximum:
        raise ValueError("Request body is missing or too large")
    return handler.rfile.read(length)


def add_staff(handler, db):
    try:
        body = body_json(handler)
        name = clean_text(body.get("name"), "Name", 80)
        role = clean_text(body.get("role"), "Job title", 80)
        email = email_value(body.get("email"))
        salary = clean_amount(body.get("salary"))
        password = secrets.token_urlsafe(15)
        digest, salt = hash_password(password)
        staff_id = str(uuid.uuid4())
        db.execute("INSERT INTO users(id,name,role,job_title,email,salary,password_hash,password_salt) VALUES(?,?,'employee',?,?,?,?,?)", (staff_id, name, role, email, salary, digest, salt))
        db.commit()
        json_response(handler, 201, {"staff": public_user(db.execute("SELECT * FROM users WHERE id=?", (staff_id,)).fetchone()), "temporaryPassword": password})
    except sqlite3.IntegrityError:
        json_response(handler, 409, {"error": "That email address is already registered"})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def add_payroll(handler, db):
    try:
        body = body_json(handler)
        staff_id = clean_text(body.get("staffId"), "Employee", 80)
        period = clean_text(body.get("period"), "Pay period", 7)
        amount = clean_amount(body.get("amount"))
        status = body.get("status")
        if status not in ("Paid", "Pending"):
            raise ValueError("Choose a valid payroll status")
        if not admin_staff_exists(db, staff_id):
            raise ValueError("Select a valid employee")
        item_id = str(uuid.uuid4())
        db.execute("INSERT INTO payroll(id,staff_id,period,amount,status) VALUES(?,?,?,?,?)", (item_id, staff_id, period, amount, status))
        db.commit()
        json_response(handler, 201, {"id": item_id})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def add_expense(handler, db):
    try:
        body = body_json(handler)
        staff_id = clean_text(body.get("staffId"), "Employee", 80)
        category = clean_text(body.get("category"), "Category", 60)
        description = clean_text(body.get("description"), "Description", 160)
        amount = clean_amount(body.get("amount"))
        if not admin_staff_exists(db, staff_id):
            raise ValueError("Select a valid employee")
        item_id = str(uuid.uuid4())
        db.execute("INSERT INTO expenses(id,staff_id,category,description,amount) VALUES(?,?,?,?,?)", (item_id, staff_id, category, description, amount))
        db.commit()
        json_response(handler, 201, {"id": item_id})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def add_schedule(handler, db):
    try:
        body = body_json(handler)
        staff_id = clean_text(body.get("staffId"), "Employee", 80)
        date = clean_text(body.get("date"), "Date", 10)
        start = clean_text(body.get("start"), "Start time", 5)
        end = clean_text(body.get("end"), "End time", 5)
        site = clean_text(body.get("site"), "Location", 120)
        if not admin_staff_exists(db, staff_id):
            raise ValueError("Select a valid employee")
        item_id = str(uuid.uuid4())
        db.execute("INSERT INTO schedules(id,staff_id,date,start,end,site) VALUES(?,?,?,?,?,?)", (item_id, staff_id, date, start, end, site))
        db.commit()
        json_response(handler, 201, {"id": item_id})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def add_task(handler, db):
    try:
        body = body_json(handler)
        staff_id = clean_text(body.get("staffId"), "Employee", 80)
        date = clean_text(body.get("date"), "Date", 10)
        title = clean_text(body.get("title"), "Task title", 120)
        details = clean_text(body.get("details", ""), "Instructions", 500, required=False)
        if not admin_staff_exists(db, staff_id):
            raise ValueError("Select a valid employee")
        item_id = str(uuid.uuid4())
        db.execute("INSERT INTO tasks(id,staff_id,date,title,details) VALUES(?,?,?,?,?)", (item_id, staff_id, date, title, details))
        db.commit()
        json_response(handler, 201, {"id": item_id})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def clock_time(handler, db, user):
    if user["role"] != "employee":
        json_response(handler, 403, {"error": "Employee access required"})
        return True
    try:
        body = body_json(handler)
        action = body.get("action")
        if action not in ("in", "out"):
            raise ValueError("Invalid clock action")
        now = time.localtime()
        date = time.strftime("%Y-%m-%d", now)
        clock = time.strftime("%I:%M %p", now).lstrip("0")
        row = db.execute("SELECT * FROM time_entries WHERE staff_id=? AND date=?", (user["id"], date)).fetchone()
        if action == "in":
            if row:
                raise ValueError("Your time-in for today is already recorded")
            item_id = str(uuid.uuid4())
            db.execute("INSERT INTO time_entries(id,staff_id,date,time_in) VALUES(?,?,?,?)", (item_id, user["id"], date, clock))
        else:
            if row is None or row["time_out"]:
                raise ValueError("There is no open time record to clock out")
            db.execute("UPDATE time_entries SET time_out=? WHERE id=?", (clock, row["id"]))
        db.commit()
        json_response(handler, 200, {"ok": True})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


def add_report(handler, db, user):
    if user["role"] != "employee":
        json_response(handler, 403, {"error": "Employee access required"})
        return True
    try:
        raw = read_body(handler, MAX_REPORT_BYTES)
        content_type = handler.headers.get("Content-Type", "")
        message = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + content_type.encode("ascii", "ignore") + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw)
        if not message.is_multipart():
            raise ValueError("Expected a multipart work report")
        fields = {}
        uploads = []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is not None:
                if len(payload) > MAX_FILE_BYTES:
                    raise ValueError("Each photo or video must be under 50 MB")
                media_type = part.get_content_type().lower()
                if media_type not in ALLOWED_MEDIA:
                    raise ValueError("Only common image and video formats are allowed")
                original = Path(unquote(filename)).name[:180]
                uploads.append((original, media_type, payload))
            elif name:
                fields[name] = payload.decode("utf-8", "replace")
        date = clean_text(fields.get("date"), "Work date", 10)
        site = clean_text(fields.get("site"), "Site", 120)
        task = clean_text(fields.get("task"), "Task", 160)
        work = clean_text(fields.get("work"), "Work description", 1200)
        next_steps = clean_text(fields.get("next"), "Next steps", 800)
        report_id = str(uuid.uuid4())
        stored_files = []
        for original, media_type, payload in uploads:
            file_id = str(uuid.uuid4())
            extension = mimetypes.guess_extension(media_type) or ".bin"
            stored_name = file_id + extension
            (UPLOAD_DIR / stored_name).write_bytes(payload)
            stored_files.append((file_id, report_id, original, media_type, stored_name))
        try:
            db.execute("INSERT INTO reports(id,staff_id,date,site,task,work,next_steps) VALUES(?,?,?,?,?,?,?)", (report_id, user["id"], date, site, task, work, next_steps))
            db.executemany("INSERT INTO report_files(id,report_id,original_name,content_type,stored_name) VALUES(?,?,?,?,?)", stored_files)
            db.commit()
        except Exception:
            for _, _, _, _, stored_name in stored_files:
                (UPLOAD_DIR / stored_name).unlink(missing_ok=True)
            raise
        json_response(handler, 201, {"id": report_id})
    except (ValueError, json.JSONDecodeError) as error:
        json_response(handler, 400, {"error": str(error)})
    return True


initialize()
