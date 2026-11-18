import sqlite3
import os
import time
from datetime import datetime

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, 'ids.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Login Events Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            datetime_str TEXT NOT NULL,
            username TEXT,
            ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            req_size INTEGER NOT NULL,
            user_agent TEXT NOT NULL,
            success INTEGER NOT NULL,
            status_code INTEGER NOT NULL,
            session_id TEXT,
            device_id TEXT
        )
    ''')

    # Traffic Events Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            datetime_str TEXT NOT NULL,
            ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            req_size INTEGER NOT NULL,
            user_agent TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            port INTEGER DEFAULT 5000
        )
    ''')

    # Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            datetime_str TEXT NOT NULL,
            username TEXT,
            ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            threat_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            details TEXT NOT NULL
        )
    ''')

    # User Baselines Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_baselines (
            username TEXT PRIMARY KEY,
            usual_device_id TEXT NOT NULL,
            usual_start_hour INTEGER DEFAULT 8,
            usual_end_hour INTEGER DEFAULT 22,
            avg_req_frequency_60s REAL DEFAULT 2.0,
            avg_interval_sec REAL DEFAULT 15.0
        )
    ''')

    # Insert default demo accounts if not exist
    demo_users = [
        ('demo1', 'password123', 'demo1@bankguard.local', '+91 9876543210'),
        ('demo2', 'securepass456', 'demo2@bankguard.local', '+91 9876543211'),
        ('demo3', 'adminpass789', 'demo3@bankguard.local', '+91 9876543212')
    ]

    for uname, pwd, email, phone in demo_users:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, email, phone)
            VALUES (?, ?, ?, ?)
        ''', (uname, pwd, email, phone))

    # Insert default user baselines
    baselines = [
        ('demo1', 'device_mac_demo1_legit', 8, 22, 2.5, 15.0),
        ('demo2', 'device_mac_demo2_legit', 9, 21, 2.0, 20.0),
        ('demo3', 'device_mac_demo3_legit', 7, 23, 3.0, 10.0)
    ]

    for uname, dev_id, s_hr, e_hr, req_freq, avg_int in baselines:
        cursor.execute('''
            INSERT OR IGNORE INTO user_baselines 
            (username, usual_device_id, usual_start_hour, usual_end_hour, avg_req_frequency_60s, avg_interval_sec)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (uname, dev_id, s_hr, e_hr, req_freq, avg_int))

    conn.commit()
    conn.close()

def reset_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM login_events')
    cursor.execute('DELETE FROM traffic_events')
    cursor.execute('DELETE FROM alerts')
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('login_events', 'traffic_events', 'alerts')")
    except Exception:
        pass
    conn.commit()
    conn.close()
    print("Database reset: cleared events, alerts, and autoincrement sequences.")


if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at", DB_PATH)
