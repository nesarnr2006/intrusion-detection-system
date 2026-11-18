from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.init_db import get_db_connection
from ml.feature_engineering import extract_features_for_event
from ml.predict import evaluate_threat

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@auth_bp.route('/dashboard', methods=['GET'])
def user_dashboard():
    username = session.get('username', 'demo1')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    # Fake account info
    account_info = {
        'username': username,
        'email': user['email'] if user else f'{username}@bankguard.local',
        'account_number': 'BG-8849-2094-1102',
        'balance': '$45,280.50' if username == 'demo1' else '$12,850.00',
        'last_login': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'transactions': [
            {'date': '2026-09-10', 'desc': 'Online Transfer - Salary', 'amount': '+$4,500.00', 'status': 'Completed'},
            {'date': '2026-09-09', 'desc': 'Merchant Payment - Tech Store', 'amount': '-$120.50', 'status': 'Completed'},
            {'date': '2026-09-08', 'desc': 'ATM Cash Withdrawal', 'amount': '-$200.00', 'status': 'Completed'}
        ]
    }
    return render_template('dashboard.html', account=account_info)

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    device_id = data.get('device_id', request.headers.get('User-Agent', 'unknown_device'))

    req_size = len(request.data) if request.data else 250
    now = time.time()
    now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

    # Authenticate credentials against SQLite
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    auth_success = 1 if (user and user['password'] == password) else 0

    # Prepare event data for feature extraction
    event_data = {
        'timestamp': now,
        'username': username,
        'payload_str': f"{username} {password}",
        'ip': request.remote_addr or '127.0.0.1',
        'endpoint': '/api/login',
        'method': 'POST',
        'req_size': req_size,
        'user_agent': request.headers.get('User-Agent', 'Flask Client'),
        'success': auth_success,
        'device_id': device_id
    }


    # Extract Features & ML Evaluation
    feature_dict, feature_vector = extract_features_for_event(event_data)
    threat_result = evaluate_threat(feature_dict, feature_vector)

    status_code = 200 if auth_success else 401
    if threat_result['risk_level'] in ['VERY HIGH', 'CRITICAL']:
        status_code = 403

    # Log event into SQLite
    cursor.execute('''
        INSERT INTO login_events 
        (timestamp, datetime_str, username, ip, endpoint, method, req_size, user_agent, success, status_code, session_id, device_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now, now_str, username, event_data['ip'], event_data['endpoint'], event_data['method'],
        req_size, event_data['user_agent'], auth_success, status_code, session.get('session_id', 'sess_demo'), device_id
    ))

    # If high/critical threat score, record alert
    if threat_result['threat_score'] >= 0.60:
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, datetime_str, username, ip, attack_type, threat_score, risk_level, action_taken, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            now, now_str, username or 'unknown', event_data['ip'],
            threat_result['predicted_category'], threat_result['threat_score'],
            threat_result['risk_level'], threat_result['action'],
            "; ".join(threat_result['explanations'])
        ))

    conn.commit()
    conn.close()

    # Security Response Action
    action = threat_result['action']

    if action in ['TEMPORARY LOCK', 'BLOCK + SECURITY ALERT']:
        return jsonify({
            'success': False,
            'blocked': True,
            'message': f"SECURITY ALERT: Account access locked due to {threat_result['predicted_category']} activity.",
            'threat_result': threat_result
        }), 403

    if action == 'STEP-UP VERIFICATION':
        return jsonify({
            'success': False,
            'step_up_required': True,
            'message': "Unusual activity detected. Step-up 2FA OTP verification required.",
            'threat_result': threat_result
        }), 200

    if not auth_success:
        return jsonify({
            'success': False,
            'message': "Invalid username or password.",
            'threat_result': threat_result
        }), 401

    # Login Success
    session['username'] = username
    return jsonify({
        'success': True,
        'message': "Authentication successful.",
        'redirect': '/dashboard',
        'threat_result': threat_result
    }), 200

@auth_bp.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.get_json() or {}
    otp = data.get('otp', '')
    username = data.get('username', 'demo1')

    # Demo mode accepts OTP 123456
    if otp == '123456':
        session['username'] = username
        return jsonify({'success': True, 'redirect': '/dashboard', 'message': 'OTP Verified successfully.'})
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP code. Try 123456.'}), 400

@auth_bp.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    session.clear()
    return redirect('/login')

@auth_bp.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.get_json() or {}
    username = data.get('username', 'demo1')
    return jsonify({
        'success': True,
        'message': f"Security verification code sent to registered contact details for user {username}. Use OTP 123456 for demo reset."
    })
