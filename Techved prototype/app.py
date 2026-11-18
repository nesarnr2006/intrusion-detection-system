from flask import Flask, request, redirect, render_template
from flask_cors import CORS
import time
from datetime import datetime
import os
import sys

from database.init_db import init_db, get_db_connection
from routes.auth import auth_bp
from routes.traffic import traffic_bp
from routes.ids import ids_bp
from ml.predict import get_models

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'sih_ids_prototype_super_secret_key_2026'
CORS(app)

# Initialize DB and pre-load ML models
init_db()
get_models()

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(traffic_bp)
app.register_blueprint(ids_bp)

@app.before_request
def log_general_traffic():
    # Ignore static file requests for traffic logging count
    if request.path.startswith('/static'):
        return

    now = time.time()
    now_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
    req_size = len(request.data) if request.data else 180

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic_events 
            (timestamp, datetime_str, ip, endpoint, method, req_size, user_agent, status_code, port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            now, now_str, request.remote_addr or '127.0.0.1', request.path,
            request.method, req_size, request.headers.get('User-Agent', 'browser'), 200, 5000
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Traffic logging warning: {e}")

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    print("==================================================")
    print("    SMART INDIA HACKATHON (SIH) IDS PROTOTYPE    ")
    print("==================================================")
    print("[+] Server started on http://127.0.0.1:5000")
    print("[+] Login Page: http://127.0.0.1:5000/login")
    print("[+] IDS Dashboard: http://127.0.0.1:5000/ids")
    print("==================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
