import requests
import time
import random
import sys

BASE_URL = "http://127.0.0.1:5000"

def check_server():
    try:
        r = requests.get(f"{BASE_URL}/api/traffic", timeout=2.0)
        return True
    except Exception:
        return False

def print_banner():
    print("""
==================================================
   SIH IDS DEMO — LOCAL ATTACK SIMULATOR HARNESS   
==================================================
Target: http://127.0.0.1:5000
Note: All simulations target ONLY localhost.
--------------------------------------------------""")

def run_normal_login():
    reset_demo()
    print("\n[+] Running Normal Login Simulation...")
    payload = {
        "username": "demo1",
        "password": "password123",
        "device_id": "device_mac_demo1_legit"
    }
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
        data = r.json()
        print(f"[*] Response Status: {r.status_code}")
        print(f"[*] Result Message:  {data.get('message')}")
        print(f"[*] Threat Score:    {data.get('threat_result', {}).get('threat_score')} ({data.get('threat_result', {}).get('risk_level')} RISK)")
        print(f"[*] Response Action: {data.get('threat_result', {}).get('action')}")
    except Exception as e:
        print(f"[!] Error sending request: {e}")

def run_forgotten_password():
    reset_demo()
    print("\n[+] Running Genuine Forgotten Password Simulation...")
    print("    Context: Legitimate user 'demo1' on known device makes 3 failed attempts, then remembers password.")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    
    wrong_passwords = ["pass1234", "password12", "mysecretpass"]
    for i, w_pass in enumerate(wrong_passwords, 1):
        payload = {
            "username": "demo1",
            "password": w_pass,
            "device_id": "device_mac_demo1_legit"
        }
        try:
            r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
            data = r.json()
            score = data.get('threat_result', {}).get('threat_score', 0.0)
            risk = data.get('threat_result', {}).get('risk_level', 'LOW')
            action = data.get('threat_result', {}).get('action', 'ALLOW')
            print(f"  - Attempt {i}/3 (Failed Password): Status={r.status_code} | Threat={score} ({risk}) | Action={action}")
        except Exception as e:
            print(f"[!] Error: {e}")
        time.sleep(0.5)

    print("\n    - Attempt 4/4 (Correct Password entered):")
    payload = {
        "username": "demo1",
        "password": "password123",
        "device_id": "device_mac_demo1_legit"
    }
    try:
        r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
        data = r.json()
        score = data.get('threat_result', {}).get('threat_score', 0.0)
        risk = data.get('threat_result', {}).get('risk_level', 'LOW')
        action = data.get('threat_result', {}).get('action', 'ALLOW')
        print(f"  - Attempt 4/4 (Success): Status={r.status_code} | Threat={score} ({risk}) | Action={action}")
        print("\n[✔] Conclusion: User NOT hard-blocked! System identified genuine user error / low-risk behavior.")
    except Exception as e:
        print(f"[!] Error: {e}")

def run_brute_force(total_reqs=100):
    reset_demo()
    print(f"\n[+] Running Rapid Brute Force Attack Simulation ({total_reqs} requests)...")
    headers = {"User-Agent": "Python-attack-simulator/1.0"}
    device_id = f"attacker_device_{random.randint(1000, 9999)}"

    for i in range(1, total_reqs + 1):
        payload = {
            "username": "demo1",
            "password": f"wrongpass_{i}_{random.randint(100, 999)}",
            "device_id": device_id
        }
        try:
            r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
            if i % 10 == 0 or i == total_reqs or r.status_code == 403:
                data = r.json()
                score = data.get('threat_result', {}).get('threat_score', 'N/A')
                risk = data.get('threat_result', {}).get('risk_level', 'N/A')
                action = data.get('threat_result', {}).get('action', 'N/A')
                print(f"  Progress: Request {i}/{total_reqs} | HTTP Status: {r.status_code} | Threat Score: {score} ({risk}) | Action: {action}")
                if r.status_code == 403:
                    print(f"\n[🚨] LOCKOUT ACTIVATED at request {i}/{total_reqs}! Threat score reached {score}.")
                    break
        except Exception as e:
            print(f"[!] Error on req {i}: {e}")
            break
        time.sleep(0.05)

def run_credential_stuffing():
    reset_demo()
    print("\n[+] Running Credential Stuffing Attack Simulation...")
    print("    Targeting multiple demo accounts rapidly...")
    target_accounts = ["demo1", "demo2", "demo3", "admin_account", "root_user", "bank_manager"]
    headers = {"User-Agent": "BotnetClient/2.4"}
    device_id = "botnet_cluster_node_77"

    for i, uname in enumerate(target_accounts, 1):
        payload = {
            "username": uname,
            "password": f"stuffed_pass_{random.randint(1000, 9999)}",
            "device_id": device_id
        }
        try:
            r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
            data = r.json()
            score = data.get('threat_result', {}).get('threat_score', 'N/A')
            risk = data.get('threat_result', {}).get('risk_level', 'N/A')
            print(f"  - Account [{uname}]: HTTP {r.status_code} | Threat: {score} ({risk})")
        except Exception as e:
            print(f"[!] Error: {e}")
        time.sleep(0.3)

def run_low_and_slow(delay=2.0):
    reset_demo()
    print(f"\n[+] Running Stealthy Low-and-Slow Attack Simulation...")
    print(f"    Sending requests spaced by {delay}s delay (configurable) using anomalous device/time...")
    headers = {"User-Agent": "StealthBrowser/9.0"}
    device_id = "unrecognized_device_stealth_x99"

    for i in range(1, 5):
        payload = {
            "username": "demo1",
            "password": f"stealth_guess_{i}",
            "device_id": device_id
        }
        try:
            r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
            data = r.json()
            score = data.get('threat_result', {}).get('threat_score', 'N/A')
            risk = data.get('threat_result', {}).get('risk_level', 'N/A')
            action = data.get('threat_result', {}).get('action', 'N/A')
            exps = data.get('threat_result', {}).get('explanations', [])
            print(f"  - Step {i}/4: HTTP {r.status_code} | Threat: {score} ({risk}) | Action: {action}")
            if exps:
                print(f"    Reason: {exps[0]}")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        if i < 4:
            print(f"    ... waiting {delay} seconds ...")
            time.sleep(delay)

def run_sql_injection():
    reset_demo()
    print("\n[+] Running SQL Injection Attack Simulation...")

    print("    Payload: admin' OR '1'='1 -- UNION SELECT NULL, username, password FROM users")
    headers = {"User-Agent": "SQLiHunter/3.1"}
    payload = {
        "username": "admin' OR '1'='1",
        "password": "' OR '1'='1",
        "device_id": "suspicious_scanner_device"
    }
    try:
        r = requests.post(f"{BASE_URL}/api/login", json=payload, headers=headers)
        data = r.json()
        score = data.get('threat_result', {}).get('threat_score', 'N/A')
        risk = data.get('threat_result', {}).get('risk_level', 'N/A')
        action = data.get('threat_result', {}).get('action', 'N/A')
        exps = data.get('threat_result', {}).get('explanations', [])
        print(f"  - HTTP Status: {r.status_code} | Threat Score: {score} ({risk}) | Action: {action}")
        if exps:
            print(f"    Detection Reason: {exps[0]}")
    except Exception as e:
        print(f"[!] Error sending SQLi request: {e}")

def reset_demo():
    print("\n[+] Resetting Demo State...")
    try:
        r = requests.post(f"{BASE_URL}/api/demo/reset")
        if r.status_code == 200:
            print("[✔] Demo state, database logs, and alerts reset successfully.")
        else:
            print("[!] Reset failed.")
    except Exception as e:
        print(f"[!] Error sending reset: {e}")

def main():
    print_banner()
    if not check_server():
        print(f"[!] Server at {BASE_URL} is NOT reachable!")
        print("    Please run 'python app.py' in another terminal first.")
        sys.exit(1)

    while True:
        print("\nSELECT SIMULATION OPTION:")
        print("  1. Normal Login (Allowed / Low Risk)")
        print("  2. Genuine Forgotten Password (3 Fails + 1 Success -> Monitor)")
        print("  3. Brute Force Attack (100 Rapid Requests -> Temporary Lockout)")
        print("  4. Credential Stuffing (Multiple Accounts Targeted)")
        print("  5. Low-and-Slow Attack (Low Rate, High Behavioral Anomaly)")
        print("  6. SQL Injection Attack (Payload Pattern Anomaly Detected)")
        print("  7. Reset Demo State & Database")
        print("  8. Exit Simulator")
        
        choice = input("\nEnter choice (1-8): ").strip()
        
        if choice == '1':
            run_normal_login()
        elif choice == '2':
            run_forgotten_password()
        elif choice == '3':
            run_brute_force(100)
        elif choice == '4':
            run_credential_stuffing()
        elif choice == '5':
            try:
                d_str = input("Enter request delay in seconds (default 2.0): ").strip()
                delay = float(d_str) if d_str else 2.0
            except ValueError:
                delay = 2.0
            run_low_and_slow(delay)
        elif choice == '6':
            run_sql_injection()
        elif choice == '7':
            reset_demo()
        elif choice == '8':
            print("Exiting simulator.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == '__main__':
    main()

