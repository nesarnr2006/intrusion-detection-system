from flask import Blueprint, jsonify, request, render_template
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.init_db import get_db_connection, reset_db
from ml.feature_engineering import extract_features_for_event
from ml.predict import evaluate_threat

ids_bp = Blueprint('ids', __name__)

@ids_bp.route('/ids', methods=['GET'])
def ids_dashboard_page():
    return render_template('ids_dashboard.html')

@ids_bp.route('/api/current-threat', methods=['GET'])
def get_current_threat():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM login_events ORDER BY id DESC LIMIT 1')
    last_event = cursor.fetchone()
    conn.close()

    if not last_event:
        return jsonify({
            'threat_score': 0.05,
            'risk_level': 'LOW',
            'action': 'ALLOW',
            'rf_score': 0.02,
            'predicted_category': 'NORMAL',
            'anomaly_score': 0.05,
            'behavioral_deviation': 0.04,
            'explanations': ['System operating normally. No recent threats logged.']
        })

    event_data = {
        'timestamp': last_event['timestamp'],
        'username': last_event['username'],
        'ip': last_event['ip'],
        'endpoint': last_event['endpoint'],
        'method': last_event['method'],
        'req_size': last_event['req_size'],
        'user_agent': last_event['user_agent'],
        'success': last_event['success'],
        'device_id': last_event['device_id']
    }

    feature_dict, feature_vector = extract_features_for_event(event_data)
    threat_result = evaluate_threat(feature_dict, feature_vector)
    return jsonify(threat_result)

@ids_bp.route('/api/dashboard', methods=['GET'])
def get_dashboard_summary():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get recent traffic events (limit 15)
    cursor.execute('SELECT * FROM login_events ORDER BY id DESC LIMIT 15')
    event_rows = cursor.fetchall()

    events = []
    for r in event_rows:
        events.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'time_str': r['datetime_str'].split(' ')[-1],
            'username': r['username'] or 'anonymous',
            'ip': r['ip'],
            'endpoint': r['endpoint'],
            'success': 'SUCCESS' if r['success'] == 1 else 'FAILED',
            'status_code': r['status_code'],
            'device_id': r['device_id']
        })

    # Get recent alerts (limit 10)
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 10')
    alert_rows = cursor.fetchall()

    alerts = []
    for a in alert_rows:
        alerts.append({
            'id': a['id'],
            'time_str': a['datetime_str'].split(' ')[-1],
            'username': a['username'],
            'ip': a['ip'],
            'attack_type': a['attack_type'],
            'threat_score': round(a['threat_score'], 2),
            'risk_level': a['risk_level'],
            'action_taken': a['action_taken'],
            'details': a['details']
        })

    # Calculate latest features & threat score
    last_event = event_rows[0] if event_rows else None
    if last_event:
        event_data = {
            'timestamp': last_event['timestamp'],
            'username': last_event['username'],
            'ip': last_event['ip'],
            'endpoint': last_event['endpoint'],
            'method': last_event['method'],
            'req_size': last_event['req_size'],
            'user_agent': last_event['user_agent'],
            'success': last_event['success'],
            'device_id': last_event['device_id']
        }
        feature_dict, feature_vector = extract_features_for_event(event_data)
        threat_result = evaluate_threat(feature_dict, feature_vector)
    else:
        feature_dict = {
            'reqs_last_10s': 0,
            'reqs_last_60s': 0,
            'failed_logins_60s': 0,
            'success_logins_60s': 0,
            'avg_interval_sec': 60.0,
            'unique_accounts_targeted': 1,
            'req_size': 256,
            'is_new_device': 0,
            'time_deviation': 0,
            'behavioral_deviation': 0.0
        }
        threat_result = {
            'threat_score': 0.05,
            'risk_level': 'LOW',
            'action': 'ALLOW',
            'rf_score': 0.02,
            'predicted_category': 'NORMAL',
            'anomaly_score': 0.05,
            'behavioral_deviation': 0.02,
            'explanations': ['System operating normally. No active threats.']
        }

    conn.close()

    system_status = 'ATTACK DETECTED' if threat_result['threat_score'] >= 0.60 else 'PROTECTED'

    return jsonify({
        'success': True,
        'system_status': system_status,
        'threat_summary': threat_result,
        'features': feature_dict,
        'recent_events': events,
        'recent_alerts': alerts
    })

@ids_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 50')
    rows = cursor.fetchall()
    conn.close()

    alerts = [dict(r) for r in rows]
    return jsonify({'success': True, 'count': len(alerts), 'alerts': alerts})

# ==================== DEMO MODE ENDPOINTS ====================

@ids_bp.route('/api/demo/normal', methods=['POST'])
def demo_normal():
    reset_db()
    now = time.time()
    now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_events 
        (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (now, now_str, 'demo1', '127.0.0.1', '/api/login', 'POST', 320, 'Mozilla/5.0 (Windows NT 10.0)', 1, 200, 'sess_legit', 'device_mac_demo1_legit'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Normal login event generated.'})

@ids_bp.route('/api/demo/forgot-password', methods=['POST'])
def demo_forgot_password():
    reset_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    # 3 Failed attempts on legitimate device + 1 successful attempt
    for i in range(3):
        now = time.time() + (i * 2.0)
        now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            INSERT INTO login_events 
            (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, now_str, 'demo1', '127.0.0.1', '/api/login', 'POST', 310, 'Mozilla/5.0 (Windows NT 10.0)', 0, 401, 'sess_demo1', 'device_mac_demo1_legit'))
    
    # Final successful attempt
    now = time.time() + 8.0
    now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        INSERT INTO login_events 
        (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (now, now_str, 'demo1', '127.0.0.1', '/api/login', 'POST', 310, 'Mozilla/5.0 (Windows NT 10.0)', 1, 200, 'sess_demo1', 'device_mac_demo1_legit'))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Genuine forgotten password scenario generated.'})

@ids_bp.route('/api/demo/bruteforce', methods=['POST'])
def demo_bruteforce():
    reset_db()
    import random
    conn = get_db_connection()
    cursor = conn.cursor()
    now_base = time.time()
    num_reqs = random.randint(30, 60)
    for i in range(num_reqs):
        now = now_base + (i * random.uniform(0.08, 0.20))
        now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        req_sz = random.randint(260, 420)
        cursor.execute('''
            INSERT INTO login_events 
            (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, now_str, 'demo1', '127.0.0.1', '/api/login', 'POST', req_sz, 'Python-requests/2.31', 0, 401, f'sess_bf_{i}', 'unregistered_device_99'))

    # Evaluate latest threat and log alert
    event_data = {
        'timestamp': now_base + 5.0,
        'username': 'demo1',
        'ip': '127.0.0.1',
        'endpoint': '/api/login',
        'method': 'POST',
        'req_size': 320,
        'user_agent': 'Python-requests/2.31',
        'success': 0,
        'device_id': 'unregistered_device_99'
    }
    feat_dict, feat_vec = extract_features_for_event(event_data)
    eval_res = evaluate_threat(feat_dict, feat_vec)

    cursor.execute('''
        INSERT INTO alerts 
        (timestamp, datetime_str, username, ip, attack_type, threat_score, risk_level, action_taken, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now_base + 5.0, datetime.fromtimestamp(now_base + 5.0).strftime('%Y-%m-%d %H:%M:%S'),
        'demo1', '127.0.0.1', 'BRUTE_FORCE', eval_res['threat_score'], eval_res['risk_level'], eval_res['action'],
        f'Rapid login failure burst: {num_reqs} requests in 5 seconds from unrecognized device'
    ))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Brute Force attack scenario generated ({num_reqs} requests).', 'threat': eval_res})


@ids_bp.route('/api/demo/slow', methods=['POST'])
def demo_slow():
    reset_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_base = time.time()
    # 4 slow requests spaced 15s apart, off-hours, new device
    for i in range(4):
        now = now_base - (45.0 - i * 15.0)
        now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            INSERT INTO login_events 
            (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, now_str, 'demo1', '127.0.0.1', '/api/login', 'POST', 315, 'Python-requests/2.31', 0, 401, 'sess_slow', 'stealth_device_x4'))

    event_data = {
        'timestamp': now_base,
        'username': 'demo1',
        'ip': '127.0.0.1',
        'endpoint': '/api/login',
        'method': 'POST',
        'req_size': 315,
        'user_agent': 'Python-requests/2.31',
        'success': 0,
        'device_id': 'stealth_device_x4'
    }
    feat_dict, feat_vec = extract_features_for_event(event_data)
    eval_res = evaluate_threat(feat_dict, feat_vec)

    cursor.execute('''
        INSERT INTO alerts 
        (timestamp, datetime_str, username, ip, attack_type, threat_score, risk_level, action_taken, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now_base, datetime.fromtimestamp(now_base).strftime('%Y-%m-%d %H:%M:%S'),
        'demo1', '127.0.0.1', 'LOW_AND_SLOW', eval_res['threat_score'], eval_res['risk_level'], eval_res['action'],
        'Low-and-Slow anomaly: Low request rate but high behavioral deviation and unrecognized device.'
    ))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Low-and-Slow attack scenario generated.', 'threat': eval_res})

@ids_bp.route('/api/demo/credential-stuffing', methods=['POST'])
def demo_credential_stuffing():
    reset_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_base = time.time()
    targets = ['demo1', 'demo2', 'demo3', 'admin', 'root', 'user10']
    for i, uname in enumerate(targets):
        now = now_base + (i * 0.4)
        now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            INSERT INTO login_events 
            (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, now_str, uname, '127.0.0.1', '/api/login', 'POST', 330, 'ProxyBot/1.0', 0, 401, f'sess_cs_{i}', 'botnet_node_3'))

    event_data = {
        'timestamp': now_base + 2.0,
        'username': 'user10',
        'ip': '127.0.0.1',
        'endpoint': '/api/login',
        'method': 'POST',
        'req_size': 330,
        'user_agent': 'ProxyBot/1.0',
        'success': 0,
        'device_id': 'botnet_node_3'
    }
    feat_dict, feat_vec = extract_features_for_event(event_data)
    eval_res = evaluate_threat(feat_dict, feat_vec)

    cursor.execute('''
        INSERT INTO alerts 
        (timestamp, datetime_str, username, ip, attack_type, threat_score, risk_level, action_taken, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now_base + 2.0, datetime.fromtimestamp(now_base + 2.0).strftime('%Y-%m-%d %H:%M:%S'),
        'multiple', '127.0.0.1', 'CREDENTIAL_STUFFING', eval_res['threat_score'], eval_res['risk_level'], eval_res['action'],
        f"Credential Stuffing: {len(targets)} distinct user accounts targeted rapidly."
    ))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Credential Stuffing scenario generated.', 'threat': eval_res})

@ids_bp.route('/api/demo/sqli', methods=['POST'])
def demo_sqli():
    reset_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now = time.time()
    now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

    sqli_username = "admin' OR '1'='1"
    sqli_payload = "admin' OR '1'='1 -- UNION SELECT NULL, username, password FROM users"

    cursor.execute('''
        INSERT INTO login_events 
        (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (now, now_str, sqli_username[:20], '127.0.0.1', '/api/login', 'POST', 680, 'SQLiHunter/3.1', 0, 401, 'sess_sqli', 'suspicious_scanner_device'))

    event_data = {
        'timestamp': now,
        'username': sqli_username,
        'payload_str': sqli_payload,
        'ip': '127.0.0.1',
        'endpoint': '/api/login',
        'method': 'POST',
        'req_size': 680,
        'user_agent': 'SQLiHunter/3.1',
        'success': 0,
        'device_id': 'suspicious_scanner_device'
    }
    feat_dict, feat_vec = extract_features_for_event(event_data)
    eval_res = evaluate_threat(feat_dict, feat_vec)

    cursor.execute('''
        INSERT INTO alerts 
        (timestamp, datetime_str, username, ip, attack_type, threat_score, risk_level, action_taken, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now, now_str, sqli_username[:15], '127.0.0.1', 'SQL_INJECTION', eval_res['threat_score'], eval_res['risk_level'], eval_res['action'],
        'SQL Injection payload pattern detected in login credentials input.'
    ))

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'SQL Injection attack scenario generated.', 'threat': eval_res})


@ids_bp.route('/api/demo/reset', methods=['POST'])
def demo_reset():
    reset_db()
    return jsonify({'success': True, 'message': 'Demo state, traffic logs, and alerts reset successfully.'})

