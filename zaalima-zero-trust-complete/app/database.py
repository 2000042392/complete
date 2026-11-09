import sqlite3, json
from contextlib import contextmanager
from datetime import datetime, timezone
from .config import DATABASE_PATH

@contextmanager
def connection():
    db = sqlite3.connect(DATABASE_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def _add_column(db, table, column, declaration):
    cols = {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

def init_db():
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          did TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL,
          username TEXT, details TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          credential_id TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL,
          sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '[]',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
          username TEXT NOT NULL, purpose TEXT NOT NULL, challenge TEXT NOT NULL,
          expires_at INTEGER NOT NULL, PRIMARY KEY(username,purpose)
        );
        CREATE TABLE IF NOT EXISTS oauth_codes (
          code_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, client_id TEXT NOT NULL,
          redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, code_challenge TEXT NOT NULL,
          expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
        );
        """)
        _add_column(db, "users", "encrypted_private_key", "TEXT")
        _add_column(db, "users", "identity_signature", "TEXT")
        _add_column(db, "oauth_codes", "nonce", "TEXT")

def audit(event, username=None, details=None):
    with connection() as db:
        db.execute("""INSERT INTO audit_logs(event,username,details,created_at)
          VALUES(?,?,?,?)""", (event, username, json.dumps(details or {}),
          datetime.now(timezone.utc).isoformat()))

def get_logs(limit=100):
    with connection() as db:
        return [dict(r) for r in db.execute(
          "SELECT event,username,details,created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
          (limit,)).fetchall()]

def get_users():
    with connection() as db:
        return [dict(r) for r in db.execute(
          "SELECT id,username,email,did,role,created_at FROM users ORDER BY id DESC"
        ).fetchall()]
