import time
from datetime import datetime
import sys
import os

# Add parent directory to path to allow database imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.init_db import get_db_connection

import re

FEATURE_NAMES = [
    'reqs_last_10s',
    'reqs_last_60s',
    'failed_logins_60s',
    'success_logins_60s',
    'avg_interval_sec',
    'unique_accounts_targeted',
    'req_size',
    'is_new_device',
    'time_deviation',
    'behavioral_deviation',
    'sql_injection_score'
]

SQL_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"'\s*OR\s*'",
    r"\"\s*OR\s*\"",
    r"\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b",
    r"\bSELECT\b\s+.*\s+\bFROM\b",
    r"\bDROP\b\s+\bTABLE\b",
    r"\bINSERT\b\s+\bINTO\b",
    r"\bDELETE\b\s+\bFROM\b",
    r"--",
    r"/\*.*\*/",
    r";"
]


def extract_features_for_event(event_data):
    """
    Extracts 10 behavioral features based on the current event and historical database state.
    event_data dict structure:
    {
        'timestamp': float,
        'username': str or None,
        'ip': str,
        'endpoint': str,
        'method': str,
        'req_size': int,
        'user_agent': str,
        'success': int (1 or 0),
        'device_id': str
    }
    """
    now = event_data.get('timestamp', time.time())
    username = event_data.get('username')
    device_id = event_data.get('device_id', 'unknown_device')
    req_size = event_data.get('req_size', 256)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Requests in last 10s
    cursor.execute('''
        SELECT COUNT(*) FROM login_events WHERE timestamp >= ?
    ''', (now - 10.0,))
    reqs_last_10s = cursor.fetchone()[0] + 1  # count current request

    # 2. Requests in last 60s
    cursor.execute('''
        SELECT COUNT(*) FROM login_events WHERE timestamp >= ?
    ''', (now - 60.0,))
    reqs_last_60s = cursor.fetchone()[0] + 1

    # 3. Failed logins in last 60s
    cursor.execute('''
        SELECT COUNT(*) FROM login_events WHERE timestamp >= ? AND success = 0
    ''', (now - 60.0,))
    failed_logins_60s = cursor.fetchone()[0] + (1 if event_data.get('success') == 0 else 0)

    # 4. Successful logins in last 60s
    cursor.execute('''
        SELECT COUNT(*) FROM login_events WHERE timestamp >= ? AND success = 1
    ''', (now - 60.0,))
    success_logins_60s = cursor.fetchone()[0] + (1 if event_data.get('success') == 1 else 0)

    # 5. Average time between attempts in last 60s
    cursor.execute('''
        SELECT timestamp FROM login_events WHERE timestamp >= ? ORDER BY timestamp ASC
    ''', (now - 60.0,))
    timestamps = [row['timestamp'] for row in cursor.fetchall()]
    timestamps.append(now)

    if len(timestamps) > 1:
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        avg_interval_sec = sum(intervals) / len(intervals)
    else:
        avg_interval_sec = 60.0

    # 6. Unique accounts targeted in last 60s
    cursor.execute('''
        SELECT COUNT(DISTINCT username) FROM login_events 
        WHERE timestamp >= ? AND username IS NOT NULL AND username != ''
    ''', (now - 60.0,))
    unique_acc_count = cursor.fetchone()[0]
    if username and username not in ['', 'None']:
        # check if this username is distinct
        cursor.execute('''
            SELECT COUNT(*) FROM login_events 
            WHERE timestamp >= ? AND username = ?
        ''', (now - 60.0, username))
        if cursor.fetchone()[0] == 0:
            unique_acc_count += 1
    unique_accounts_targeted = max(1, unique_acc_count)

    # 7. Request size
    # req_size variable already set

    # Fetch User Baseline if username available
    usual_device = 'device_mac_demo1_legit'
    start_hr = 8
    end_hr = 22
    avg_req_freq_base = 2.0
    avg_interval_base = 15.0

    if username:
        cursor.execute('SELECT * FROM user_baselines WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            usual_device = row['usual_device_id']
            start_hr = row['usual_start_hour']
            end_hr = row['usual_end_hour']
            avg_req_freq_base = row['avg_req_frequency_60s']
            avg_interval_base = row['avg_interval_sec']

    conn.close()

    # 8. Is new device
    is_new_device = 1 if (device_id and device_id != usual_device) else 0

    # 9. Time deviation
    current_hour = datetime.fromtimestamp(now).hour
    if current_hour < start_hr or current_hour >= end_hr:
        time_deviation = 1.0
    else:
        time_deviation = 0.0

    # 10. Behavioral deviation calculation
    freq_ratio = reqs_last_60s / max(1.0, avg_req_freq_base)
    freq_dev = min(1.0, max(0.0, (freq_ratio - 1.0) / 10.0))

    if avg_interval_sec < avg_interval_base:
        interval_dev = min(1.0, (avg_interval_base - avg_interval_sec) / avg_interval_base)
    else:
        interval_dev = 0.0

    account_spread_dev = min(1.0, (unique_accounts_targeted - 1) / 5.0)

    # Weighted combination for behavioral deviation
    behavioral_deviation = min(1.0, 
        0.30 * is_new_device +
        0.25 * time_deviation +
        0.25 * freq_dev +
        0.20 * account_spread_dev
    )

    # 11. SQL Injection payload score
    sql_matches = 0
    test_str = str(username or '') + " " + str(event_data.get('payload_str', ''))
    for pat in SQL_PATTERNS:
        if re.search(pat, test_str, re.IGNORECASE):
            sql_matches += 1

    sql_injection_score = min(1.0, sql_matches * 0.50)

    feature_dict = {
        'reqs_last_10s': float(reqs_last_10s),
        'reqs_last_60s': float(reqs_last_60s),
        'failed_logins_60s': float(failed_logins_60s),
        'success_logins_60s': float(success_logins_60s),
        'avg_interval_sec': float(round(avg_interval_sec, 2)),
        'unique_accounts_targeted': float(unique_accounts_targeted),
        'req_size': float(req_size),
        'is_new_device': float(is_new_device),
        'time_deviation': float(time_deviation),
        'behavioral_deviation': float(round(behavioral_deviation, 4)),
        'sql_injection_score': float(round(sql_injection_score, 4))
    }

    feature_vector = [feature_dict[fname] for fname in FEATURE_NAMES]

    return feature_dict, feature_vector

