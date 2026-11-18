import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix
import joblib
import os
import sys

# Set random seed for reproducibility
np.random.seed(42)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
RF_MODEL_PATH = os.path.join(ML_DIR, 'random_forest.pkl')
IF_MODEL_PATH = os.path.join(ML_DIR, 'isolation_forest.pkl')

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

def generate_synthetic_dataset(n_samples=2800):
    """
    Generates synthetic dataset simulating 7 behavioral traffic categories:
    0: NORMAL
    1: BRUTE_FORCE
    2: CREDENTIAL_STUFFING
    3: DOS
    4: PORT_SCAN
    5: LOW_AND_SLOW
    6: SQL_INJECTION
    """
    samples_per_class = n_samples // 7
    data = []
    labels = []

    # 1. NORMAL TRAFFIC (class 0)
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(1, 3)
        reqs_60s = np.random.randint(1, 5)
        failed_60s = np.random.choice([0, 1], p=[0.90, 0.10])
        success_60s = 1 if failed_60s == 0 else 0
        avg_int = np.random.uniform(10.0, 40.0)
        unique_acc = 1
        req_sz = np.random.randint(200, 600)
        new_dev = np.random.choice([0, 1], p=[0.92, 0.08])
        t_dev = np.random.choice([0, 1], p=[0.85, 0.15])
        beh_dev = min(1.0, 0.3 * new_dev + 0.25 * t_dev + np.random.uniform(0.0, 0.1))
        sql_score = 0.0
        
        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('NORMAL')

    # 2. BRUTE FORCE (class 1)
    # High frequency, high failed logins, single username, rapid intervals
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(15, 45)
        reqs_60s = np.random.randint(60, 150)
        failed_60s = np.random.randint(40, 140)
        success_60s = np.random.choice([0, 1], p=[0.95, 0.05])
        avg_int = np.random.uniform(0.1, 1.2)
        unique_acc = 1
        req_sz = np.random.randint(250, 450)
        new_dev = np.random.choice([0, 1], p=[0.6, 0.4])
        t_dev = np.random.choice([0, 1], p=[0.5, 0.5])
        beh_dev = min(1.0, 0.3 * new_dev + 0.25 * t_dev + 0.4)
        sql_score = 0.0

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('BRUTE_FORCE')

    # 3. CREDENTIAL STUFFING (class 2)
    # High failed logins across MULTIPLE accounts
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(10, 30)
        reqs_60s = np.random.randint(40, 100)
        failed_60s = np.random.randint(30, 90)
        success_60s = np.random.randint(0, 3)
        avg_int = np.random.uniform(0.5, 2.5)
        unique_acc = np.random.randint(4, 15)
        req_sz = np.random.randint(250, 500)
        new_dev = 1
        t_dev = np.random.choice([0, 1], p=[0.4, 0.6])
        beh_dev = min(1.0, 0.3 * new_dev + 0.25 * t_dev + 0.35 + (unique_acc / 20.0))
        sql_score = 0.0

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('CREDENTIAL_STUFFING')

    # 4. DOS / HIGH TRAFFIC (class 3)
    # Extremely high request count, mixed success/failed, large volume
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(50, 120)
        reqs_60s = np.random.randint(200, 500)
        failed_60s = np.random.randint(10, 100)
        success_60s = np.random.randint(10, 100)
        avg_int = np.random.uniform(0.01, 0.3)
        unique_acc = np.random.randint(1, 5)
        req_sz = np.random.randint(100, 2000)
        new_dev = 1
        t_dev = np.random.choice([0, 1], p=[0.5, 0.5])
        beh_dev = min(1.0, 0.5 + np.random.uniform(0.1, 0.4))
        sql_score = 0.0

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('DOS')

    # 5. PORT SCAN / RECON (class 4)
    # Distinct payload size patterns, small quick connection probing
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(8, 25)
        reqs_60s = np.random.randint(20, 70)
        failed_60s = np.random.randint(5, 25)
        success_60s = 0
        avg_int = np.random.uniform(0.2, 1.5)
        unique_acc = 1
        req_sz = np.random.randint(40, 120) # abnormally small packets
        new_dev = 1
        t_dev = np.random.choice([0, 1], p=[0.3, 0.7])
        beh_dev = min(1.0, 0.4 + np.random.uniform(0.1, 0.3))
        sql_score = 0.0

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('PORT_SCAN')

    # 6. LOW AND SLOW (class 5)
    # Low request rate (reqs_10s is low), but high behavioral deviation, unusual device, off-hours, steady failed logins
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(1, 3) # LOW rate!
        reqs_60s = np.random.randint(3, 8) # LOW rate!
        failed_60s = np.random.randint(3, 7) # Mostly failed
        success_60s = 0
        avg_int = np.random.uniform(8.0, 25.0) # Slow intervals!
        unique_acc = np.random.choice([1, 2], p=[0.7, 0.3])
        req_sz = np.random.randint(250, 450)
        new_dev = 1 # Unusual device
        t_dev = 1 # Off hours!
        beh_dev = min(1.0, 0.35 * new_dev + 0.30 * t_dev + 0.20) # High behavioral anomaly score!
        sql_score = 0.0

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('LOW_AND_SLOW')

    # 7. SQL INJECTION (class 6)
    for _ in range(samples_per_class):
        reqs_10s = np.random.randint(1, 4)
        reqs_60s = np.random.randint(1, 10)
        failed_60s = np.random.randint(1, 8)
        success_60s = 0
        avg_int = np.random.uniform(2.0, 15.0)
        unique_acc = 1
        req_sz = np.random.randint(450, 900) # larger request size due to payload
        new_dev = np.random.choice([0, 1], p=[0.4, 0.6])
        t_dev = np.random.choice([0, 1], p=[0.5, 0.5])
        beh_dev = min(1.0, 0.3 * new_dev + 0.2 * t_dev + 0.3)
        sql_score = np.random.uniform(0.50, 1.0) # High SQL injection pattern score!

        data.append([reqs_10s, reqs_60s, failed_60s, success_60s, avg_int, unique_acc, req_sz, new_dev, t_dev, beh_dev, sql_score])
        labels.append('SQL_INJECTION')

    df = pd.DataFrame(data, columns=FEATURE_NAMES)
    df['label'] = labels
    return df

def train_and_save():
    print("==================================================")
    print("      TRAINING ML MODELS FOR IDS PROTOTYPE       ")
    print("==================================================")
    print("[+] Generating synthetic training dataset (2,500 samples)...")
    df = generate_synthetic_dataset(2500)
    print("[+] Dataset distribution:")
    print(df['label'].value_counts())
    print("\n--------------------------------------------------")

    X = df[FEATURE_NAMES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    # 1. Train Random Forest Classifier
    print("[+] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n[+] Random Forest Test Accuracy: {accuracy * 100:.2f}%\n")
    print("--- Classification Report ---")
    print(classification_report(y_test, y_pred))

    print("--- Confusion Matrix ---")
    cm = confusion_matrix(y_test, y_pred, labels=rf_model.classes_)
    cm_df = pd.DataFrame(cm, index=rf_model.classes_, columns=rf_model.classes_)
    print(cm_df)

    # 2. Train Isolation Forest on NORMAL behavior only
    print("\n--------------------------------------------------")
    print("[+] Training Isolation Forest on Normal Behavior Data...")
    normal_X = X[y == 'NORMAL']
    iso_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso_model.fit(normal_X)

    # Test Isolation Forest anomaly scoring
    scores = iso_model.decision_function(X_test)
    # Decision function returns positive for inliers, negative for outliers
    # We invert & normalize to [0, 1] range: higher value = more anomalous
    min_score, max_score = scores.min(), scores.max()
    normalized_anom = 1.0 - ((scores - min_score) / (max_score - min_score + 1e-6))
    print(f"[+] Isolation Forest fitted. Test anomaly score range: [{normalized_anom.min():.2f}, {normalized_anom.max():.2f}]")

    # 3. Save Models
    os.makedirs(ML_DIR, exist_ok=True)
    joblib.dump(rf_model, RF_MODEL_PATH)
    joblib.dump(iso_model, IF_MODEL_PATH)

    print("\n[+] ML Models successfully trained and saved!")
    print(f"    - Random Forest: {RF_MODEL_PATH}")
    print(f"    - Isolation Forest: {IF_MODEL_PATH}")
    print("==================================================")

if __name__ == '__main__':
    train_and_save()
