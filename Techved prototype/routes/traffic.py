from flask import Blueprint, jsonify, request
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.init_db import get_db_connection

traffic_bp = Blueprint('traffic', __name__)

@traffic_bp.route('/api/traffic', methods=['GET'])
def get_traffic_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Retrieve last 30 login events
    cursor.execute('''
        SELECT * FROM login_events ORDER BY id DESC LIMIT 30
    ''')
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'datetime_str': row['datetime_str'],
            'username': row['username'] or 'anonymous',
            'ip': row['ip'],
            'endpoint': row['endpoint'],
            'method': row['method'],
            'req_size': row['req_size'],
            'success': bool(row['success']),
            'status_code': row['status_code'],
            'device_id': row['device_id']
        })

    return jsonify({'success': True, 'count': len(logs), 'events': logs})
