import requests

BASE_URL = "http://127.0.0.1:5000"

def test_all():
    print("[1] Testing Reset -> Normal Login...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/normal")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Normal threat:", dash['threat_summary']['threat_score'], "| Category:", dash['threat_summary']['predicted_category'], "| Action:", dash['threat_summary']['action'])
    assert dash['threat_summary']['action'] == 'ALLOW'

    print("[2] Testing Reset -> Genuine Forgotten Password...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/forgot-password")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Forgotten Pass threat:", dash['threat_summary']['threat_score'], "| Action:", dash['threat_summary']['action'])
    assert dash['threat_summary']['action'] in ['ALLOW', 'MONITOR']

    print("[3] Testing Reset -> Brute Force Attack...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/bruteforce")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Brute Force threat:", dash['threat_summary']['threat_score'], "| Category:", dash['threat_summary']['predicted_category'], "| Action:", dash['threat_summary']['action'])
    assert dash['threat_summary']['predicted_category'] == 'BRUTE_FORCE'

    print("[4] Testing Reset -> Low-and-Slow Attack...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/slow")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Low-and-Slow threat:", dash['threat_summary']['threat_score'], "| Action:", dash['threat_summary']['action'])

    print("[5] Testing Reset -> Credential Stuffing...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/credential-stuffing")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Credential Stuffing threat:", dash['threat_summary']['threat_score'], "| Category:", dash['threat_summary']['predicted_category'], "| Action:", dash['threat_summary']['action'])
    assert dash['threat_summary']['predicted_category'] == 'CREDENTIAL_STUFFING'

    print("[6] Testing Reset -> SQL Injection Attack...")
    requests.post(f"{BASE_URL}/api/demo/reset")
    r = requests.post(f"{BASE_URL}/api/demo/sqli")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    SQL Injection threat:", dash['threat_summary']['threat_score'], "| Category:", dash['threat_summary']['predicted_category'], "| Action:", dash['threat_summary']['action'])
    assert dash['threat_summary']['predicted_category'] == 'SQL_INJECTION'

    print("[7] Testing Previous Attack followed by Normal Login...")
    # Trigger brute force first
    requests.post(f"{BASE_URL}/api/demo/bruteforce")
    # Now user logs in normally with correct password from known device
    r_norm = requests.post(f"{BASE_URL}/api/login", json={
        "username": "demo1",
        "password": "password123",
        "device_id": "device_mac_demo1_legit"
    })
    dash_norm = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Post-Attack Normal Login threat:", dash_norm['threat_summary']['threat_score'], "| Category:", dash_norm['threat_summary']['predicted_category'], "| Action:", dash_norm['threat_summary']['action'])
    assert dash_norm['threat_summary']['action'] == 'ALLOW'
    assert dash_norm['threat_summary']['predicted_category'] == 'NORMAL'

    print("[8] Testing Reset Demo State...")
    r = requests.post(f"{BASE_URL}/api/demo/reset")
    assert r.status_code == 200
    dash = requests.get(f"{BASE_URL}/api/dashboard").json()
    print("    Reset threat:", dash['threat_summary']['threat_score'], "| Status:", dash['system_status'])

    print("\n[OK] ALL 8 CLEAN DEMO WORKFLOW & STATE AUDIT TESTS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    test_all()
