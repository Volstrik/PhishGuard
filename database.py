# database.py

import sqlite3
import hashlib
import os
from config import Config
from datetime import datetime

def get_db_connection():
    conn = sqlite3.connect(
        Config.DATABASE_NAME,
        timeout=10  # wait up to 10s for a lock to clear instead of failing instantly
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # allows concurrent reads during a write
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ── USERS TABLE ─────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL
        )
    """)

    # ── SCANS TABLE ──────────────────────────────────────────────
    # user_id links each scan to the user who ran it
    # NULL user_id = scan run before auth was added
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          INTEGER REFERENCES users(id),
            url              TEXT    NOT NULL,
            score            INTEGER NOT NULL,
            risk_level       TEXT    NOT NULL,
            safe_count       INTEGER DEFAULT 0,
            malicious_count  INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            undetected_count INTEGER DEFAULT 0,
            scanned_at       TEXT    NOT NULL
        )
    """)

    # ── MIGRATION: add user_id column if it doesn't exist yet ───
    # (handles existing databases that already have scans)
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
    except Exception:
        pass  # column already exists — ignore

    conn.commit()
    conn.close()


# ── PASSWORD HASHING ─────────────────────────────────────────────
def hash_password(password):
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )
    return (salt + key).hex()


def verify_password(password, stored_hash):
    try:
        raw  = bytes.fromhex(stored_hash)
        salt = raw[:32]
        key  = raw[32:]
        test = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100_000
        )
        return test == key
    except Exception:
        return False


# ── USER FUNCTIONS ───────────────────────────────────────────────
def create_user(username, email, password, is_admin=False):
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO users (username, email, password_hash, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username.strip(),
            email.strip().lower(),
            hash_password(password),
            1 if is_admin else 0,
            datetime.now().strftime("%d/%m/%Y %H:%M")
        ))
        conn.commit()
        return True, "Account created successfully"
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return False, "Username already taken"
        if "email" in str(e):
            return False, "Email already registered"
        return False, "Registration failed"
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username.strip(),)
    ).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return user


def get_all_users():
    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, is_admin, created_at FROM users ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return users


# ── SCAN FUNCTIONS ───────────────────────────────────────────────
def save_scan(url, score, risk_level, safe, malicious, suspicious, undetected, user_id=None):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO scans (
            user_id, url, score, risk_level,
            safe_count, malicious_count,
            suspicious_count, undetected_count,
            scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        url, score, risk_level,
        safe, malicious, suspicious, undetected,
        datetime.now().strftime("%d/%m/%Y %H:%M")
    ))
    conn.commit()
    conn.close()


def get_all_scans():
    # Admin — returns every scan with username
    conn = get_db_connection()
    scans = conn.execute("""
        SELECT s.*, u.username
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.id DESC
    """).fetchall()
    conn.close()
    return scans


def get_user_scans(user_id):
    # Regular user — returns only their own scans
    conn = get_db_connection()
    scans = conn.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return scans


def get_stats(user_id=None):
    conn   = get_db_connection()
    cursor = conn.cursor()

    # Filter by user if not admin
    where = "WHERE user_id = ?" if user_id else ""
    args  = (user_id,) if user_id else ()

    total      = cursor.execute(f"SELECT COUNT(*)    FROM scans {where}", args).fetchone()[0]
    safe       = cursor.execute(f"SELECT COUNT(*)    FROM scans {where} {'AND' if user_id else 'WHERE'} risk_level='Safe'",       args).fetchone()[0]
    suspicious = cursor.execute(f"SELECT COUNT(*)    FROM scans {where} {'AND' if user_id else 'WHERE'} risk_level='Suspicious'",  args).fetchone()[0]
    high_risk  = cursor.execute(f"SELECT COUNT(*)    FROM scans {where} {'AND' if user_id else 'WHERE'} risk_level='High Risk'",   args).fetchone()[0]
    malicious  = cursor.execute(f"SELECT COUNT(*)    FROM scans {where} {'AND' if user_id else 'WHERE'} risk_level='Malicious'",   args).fetchone()[0]
    avg_score  = cursor.execute(f"SELECT AVG(score)  FROM scans {where}", args).fetchone()[0]

    conn.close()
    return {
        "total":      total,
        "safe":       safe,
        "suspicious": suspicious,
        "high_risk":  high_risk,
        "malicious":  malicious,
        "avg_score":  round(avg_score, 1) if avg_score else 0
    }


def get_top_threats(user_id=None, limit=5):
    conn  = get_db_connection()
    where = "WHERE s.user_id = ? AND s.risk_level != 'Safe'" if user_id else "WHERE s.risk_level != 'Safe'"
    args  = (user_id, limit) if user_id else (limit,)
    threats = conn.execute(f"""
        SELECT s.*, u.username
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        {where}
        ORDER BY s.score DESC LIMIT ?
    """, args).fetchall()
    conn.close()
    return threats


def delete_scan(scan_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


def get_admin_stats():
    conn   = get_db_connection()
    cursor = conn.cursor()
    total_users  = cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0]
    total_scans  = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_threats= cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level != 'Safe'").fetchone()[0]
    most_active  = cursor.execute("""
        SELECT u.username, COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
        WHERE u.is_admin = 0
        GROUP BY u.id
        ORDER BY scan_count DESC LIMIT 1
    """).fetchone()
    conn.close()
    return {
        "total_users":   total_users,
        "total_scans":   total_scans,
        "total_threats": total_threats,
        "most_active":   most_active["username"] if most_active else "N/A"
    }