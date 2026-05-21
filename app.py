"""
SD Studio — License Server
==========================
Deploy on Railway. Set these environment variables:
    ADMIN_PW_HASH  = sha256 hash of your admin password
    FLASK_SECRET   = any long random string
    DATABASE_URL   = set automatically when you add Railway PostgreSQL addon
"""

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, flash, g, redirect, render_template,
    request, session, url_for,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE-ME-IN-PRODUCTION-USE-RANDOM-STRING")

# ── Database Mode Detection ───────────────────────────────────────────────────
# Railway PostgreSQL sets DATABASE_URL automatically when you add the addon.
# Falls back to SQLite for local development.
_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USE_PG = bool(_DATABASE_URL)

# SQLite fallback path (local dev only)
_DB_DIR = os.environ.get("DB_DIR", str(Path(__file__).parent))
_DB_PATH = Path(_DB_DIR) / "licenses.db"

# Admin password
_DEFAULT_HASH = hashlib.sha256(b"admin123").hexdigest()
ADMIN_PW_HASH = os.environ.get("ADMIN_PW_HASH", _DEFAULT_HASH)


# ── DB Abstraction ────────────────────────────────────────────────────────────

def _pg_conn():
    import psycopg2
    import psycopg2.extras
    conn = psycopg2.connect(_DATABASE_URL, connect_timeout=5)
    return conn


def get_db():
    if "db" not in g:
        if _USE_PG:
            import psycopg2.extras
            conn = _pg_conn()
            conn.autocommit = False
            g.db = conn
            g.db_cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            conn = sqlite3.connect(_DB_PATH)
            conn.row_factory = sqlite3.Row
            g.db = conn
    return g.db


def db_execute(sql: str, params=()) -> list:
    """Execute SQL and return all rows as list of dicts."""
    if _USE_PG:
        sql_pg = sql.replace("?", "%s")
        cursor = g.db_cursor
        cursor.execute(sql_pg, params)
        try:
            return [dict(r) for r in cursor.fetchall()]
        except Exception:
            return []
    else:
        return [dict(r) for r in get_db().execute(sql, params).fetchall()]


def db_execute_one(sql: str, params=()) -> dict | None:
    rows = db_execute(sql, params)
    return rows[0] if rows else None


def db_write(sql: str, params=()):
    """Execute a write statement (INSERT/UPDATE/DELETE)."""
    if _USE_PG:
        sql_pg = sql.replace("?", "%s")
        # Strip SQLite-specific datetime() calls
        sql_pg = sql_pg.replace("datetime('now')", "NOW()")
        g.db_cursor.execute(sql_pg, params)
    else:
        get_db().execute(sql, params)


def db_commit():
    if _USE_PG:
        g.db.commit()
    else:
        get_db().commit()


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    if _USE_PG:
        conn = _pg_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id                 SERIAL PRIMARY KEY,
                key                TEXT    UNIQUE NOT NULL,
                client_name        TEXT    NOT NULL,
                is_blocked         INTEGER DEFAULT 0,
                expires_month      TEXT    NOT NULL,
                device_fingerprint TEXT    DEFAULT '',
                device_name        TEXT    DEFAULT '',
                username           TEXT    DEFAULT '',
                last_seen          TEXT    DEFAULT '',
                last_ip            TEXT    DEFAULT '',
                activation_count   INTEGER DEFAULT 0,
                created_at         TEXT    DEFAULT to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.commit()
        conn.close()
    else:
        Path(_DB_DIR).mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(_DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                key                TEXT    UNIQUE NOT NULL,
                client_name        TEXT    NOT NULL,
                is_blocked         INTEGER DEFAULT 0,
                expires_month      TEXT    NOT NULL,
                device_fingerprint TEXT    DEFAULT '',
                device_name        TEXT    DEFAULT '',
                username           TEXT    DEFAULT '',
                last_seen          TEXT    DEFAULT '',
                last_ip            TEXT    DEFAULT '',
                activation_count   INTEGER DEFAULT 0,
                created_at         TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        conn.close()


try:
    init_db()
except Exception as _e:
    print(f"[WARN] init_db failed (DB may be starting up): {_e}")


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


# ── Admin Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("admin_login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin"):
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if hashlib.sha256(pw.encode()).hexdigest() == ADMIN_PW_HASH:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Incorrect password.", "error")
    return render_template("admin/login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/")
@login_required
def admin_dashboard():
    get_db()
    licenses = db_execute("SELECT * FROM licenses ORDER BY created_at DESC")
    now_month = datetime.now().strftime("%Y-%m")
    new_key = session.pop("new_key", None)
    new_client = session.pop("new_client", None)
    return render_template(
        "admin/dashboard.html",
        licenses=licenses,
        now_month=now_month,
        new_key=new_key,
        new_client=new_client,
    )


@app.route("/admin/create", methods=["POST"])
@login_required
def admin_create():
    client_name = request.form.get("client_name", "").strip()
    expires_month = request.form.get("expires_month", "").strip()

    if not client_name or not expires_month:
        flash("Client name and expiry month are required.", "error")
        return redirect(url_for("admin_dashboard"))

    raw = secrets.token_hex(8).upper()
    key = f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"

    get_db()
    try:
        db_write(
            "INSERT INTO licenses (key, client_name, expires_month) VALUES (?, ?, ?)",
            (key, client_name, expires_month),
        )
        db_commit()
        session["new_key"] = key
        session["new_client"] = client_name
    except Exception:
        flash("Key collision — please try again.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/block/<int:lic_id>", methods=["POST"])
@login_required
def admin_block(lic_id):
    get_db()
    row = db_execute_one("SELECT is_blocked FROM licenses WHERE id=?", (lic_id,))
    if row:
        db_write(
            "UPDATE licenses SET is_blocked=? WHERE id=?",
            (0 if row["is_blocked"] else 1, lic_id),
        )
        db_commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/extend/<int:lic_id>", methods=["POST"])
@login_required
def admin_extend(lic_id):
    get_db()
    row = db_execute_one("SELECT expires_month FROM licenses WHERE id=?", (lic_id,))
    if row:
        yr, mo = map(int, row["expires_month"].split("-"))
        mo += 1
        if mo > 12:
            mo = 1
            yr += 1
        db_write(
            "UPDATE licenses SET expires_month=? WHERE id=?",
            (f"{yr}-{mo:02d}", lic_id),
        )
        db_commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete/<int:lic_id>", methods=["POST"])
@login_required
def admin_delete(lic_id):
    get_db()
    db_write("DELETE FROM licenses WHERE id=?", (lic_id,))
    db_commit()
    return redirect(url_for("admin_dashboard"))


# ── Client Validation API ─────────────────────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
def api_validate():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip().upper()
    device_fp = str(data.get("device_fingerprint", ""))[:64]
    device_name = str(data.get("device_name", ""))[:128]
    username = str(data.get("username", ""))[:64]
    client_ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:64]

    if not key:
        return {"ok": False, "reason": "no_key"}, 400

<<<<<<< HEAD
    try:
        get_db()
    except Exception as _e:
        print(f"[ERROR] DB connection failed: {_e}")
        return {"ok": False, "reason": "offline"}, 503
=======
    get_db()
>>>>>>> 917c00f508df9c50183115ecc0e17e95964c8cdf
    row = db_execute_one("SELECT * FROM licenses WHERE key=?", (key,))

    if not row:
        return {"ok": False, "reason": "invalid_key"}

    if row["is_blocked"]:
        return {"ok": False, "reason": "blocked", "client_name": row["client_name"]}

    now_month = datetime.now().strftime("%Y-%m")
    if row["expires_month"] < now_month:
        return {"ok": False, "reason": "expired",
                "client_name": row["client_name"],
                "expires_month": row["expires_month"]}

    db_write("""
        UPDATE licenses SET
            device_fingerprint = ?,
            device_name        = ?,
            username           = ?,
            last_seen          = datetime('now'),
            last_ip            = ?,
            activation_count   = activation_count + 1
        WHERE id = ?
    """, (device_fp, device_name, username, client_ip, row["id"]))
<<<<<<< HEAD
    # Note: db_write() auto-converts datetime('now') → NOW() for PostgreSQL
=======
>>>>>>> 917c00f508df9c50183115ecc0e17e95964c8cdf
    db_commit()

    return {
        "ok": True,
        "client_name": row["client_name"],
        "expires_month": row["expires_month"],
    }


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"Using {'PostgreSQL' if _USE_PG else 'SQLite'}")
    print(f"Admin panel: http://localhost:{port}/admin/login")
    app.run(debug=False, host="0.0.0.0", port=port)
