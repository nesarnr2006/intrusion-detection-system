import os
import joblib
import pandas as pd
import numpy as np
import sys

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

# Lazy-loaded model instances
_rf_model = None
_iso_model = None

def get_models(reload=False):
    global _rf_model, _iso_model
    if _rf_model is None or _iso_model is None or reload:
        if os.path.exists(RF_MODEL_PATH) and os.path.exists(IF_MODEL_PATH):
            _rf_model = joblib.load(RF_MODEL_PATH)
            _iso_model = joblib.load(IF_MODEL_PATH)
        else:
            from ml.train_model import train_and_save
            train_and_save()
            _rf_model = joblib.load(RF_MODEL_PATH)
            _iso_model = joblib.load(IF_MODEL_PATH)
    return _rf_model, _iso_model

def evaluate_threat(feature_dict, feature_vector):
    """
    Evaluates threat score using RF, Isolation Forest, and Behavioral Baseline.
    Applies contextual logic to distinguish legitimate user logins from attack patterns.
    """
    rf_model, iso_model = get_models()

    df_feat = pd.DataFrame([feature_vector], columns=FEATURE_NAMES)

    # 1. Random Forest prediction & probability
    try:
        probs = rf_model.predict_proba(df_feat)[0]
    except Exception:
        # Auto-reload models from disk if shape or features updated
        rf_model, iso_model = get_models(reload=True)
        probs = rf_model.predict_proba(df_feat)[0]

    classes = rf_model.classes_
    prob_dict = dict(zip(classes, probs))
    
    predicted_category = rf_model.predict(df_feat)[0]

    # Supervised score is the sum of probabilities of ALL non-NORMAL attack classes
    normal_prob = prob_dict.get('NORMAL', 0.0)
    rf_score = float(1.0 - normal_prob)

    # 2. Isolation Forest anomaly score
    raw_iso_score = iso_model.decision_function(df_feat)[0]
    scaled_anomaly = min(1.0, max(0.0, (0.15 - raw_iso_score) / 0.35))
    anomaly_score = float(round(scaled_anomaly, 4))

    # 3. Behavioral deviation score
    behavioral_dev = float(feature_dict.get('behavioral_deviation', 0.0))

    # 4. Combined Threat Score Formula
    raw_threat = (0.50 * rf_score) + (0.30 * anomaly_score) + (0.20 * behavioral_dev)
    threat_score = float(round(min(1.0, max(0.0, raw_threat)), 4))

    # CONTEXTUAL ADJUSTMENTS & GUARANTEES:

    # A. Legitimate Successful Login on Verified Baseline Device
    # If the current request is a successful login (success_logins > 0 / auth success),
    # from a known device (is_new_device == 0) without SQLi payload:
    if feature_dict.get('success_logins_60s', 0) > 0 and feature_dict.get('is_new_device') == 0:
        if feature_dict.get('sql_injection_score', 0) < 0.30:
            predicted_category = 'NORMAL'
            rf_score = 0.02
            behavioral_dev = min(0.10, behavioral_dev)
            threat_score = 0.12
            risk_level = 'LOW'
            action = 'ALLOW'

    # B. Successful Login on UNKNOWN/NEW Device -> Trigger Step-Up 2FA OTP
    elif feature_dict.get('success_logins_60s', 0) > 0 and feature_dict.get('is_new_device') == 1:
        if feature_dict.get('sql_injection_score', 0) < 0.30 and threat_score < 0.80:
            predicted_category = 'NORMAL'
            threat_score = 0.65
            risk_level = 'HIGH'
            action = 'STEP-UP VERIFICATION'

    # C. SQL Injection Payload Detected
    elif feature_dict.get('sql_injection_score', 0) >= 0.30:
        predicted_category = 'SQL_INJECTION'
        threat_score = max(0.85, threat_score)

    # D. Credential Stuffing (Multiple Accounts Targeted)
    elif feature_dict.get('unique_accounts_targeted', 1) >= 3 and feature_dict.get('failed_logins_60s', 0) >= 4:
        predicted_category = 'CREDENTIAL_STUFFING'
        threat_score = max(0.82, threat_score)

    # E. Rapid Brute Force (High failures & rapid frequency)
    elif feature_dict.get('failed_logins_60s', 0) >= 8 or feature_dict.get('reqs_last_10s', 0) >= 8:
        predicted_category = 'BRUTE_FORCE'
        threat_score = max(0.85, threat_score)

    # F. Genuine Forgotten Password (2-4 failures on known device)
    elif feature_dict.get('is_new_device') == 0 and feature_dict.get('failed_logins_60s', 0) <= 4:
        if feature_dict.get('reqs_last_10s', 0) <= 3 and feature_dict.get('sql_injection_score', 0) < 0.30:
            predicted_category = 'NORMAL'
            threat_score = 0.38
            risk_level = 'MEDIUM'
            action = 'MONITOR'

    # Determine Risk Level & Action based on final Threat Score
    if threat_score < 0.30:
        risk_level = 'LOW'
        action = 'ALLOW'
    elif threat_score < 0.60:
        risk_level = 'MEDIUM'
        action = 'MONITOR'
    elif threat_score < 0.80:
        risk_level = 'HIGH'
        action = 'STEP-UP VERIFICATION'
    elif threat_score < 0.95:
        risk_level = 'VERY HIGH'
        action = 'TEMPORARY LOCK'
    else:
        risk_level = 'CRITICAL'
        action = 'BLOCK + SECURITY ALERT'

    # 6. Model Explanations matching actual features
    explanations = []
    
    if feature_dict.get('sql_injection_score', 0) >= 0.30:
        explanations.append("SQL Injection payload syntax pattern detected in request data")

    if feature_dict.get('unique_accounts_targeted', 1) >= 3:
        explanations.append(f"Credential stuffing indicator: {int(feature_dict['unique_accounts_targeted'])} distinct accounts targeted")

    if feature_dict.get('failed_logins_60s', 0) >= 10:
        explanations.append(f"High failed login rate detected ({int(feature_dict['failed_logins_60s'])} failures in 60s)")
    elif feature_dict.get('failed_logins_60s', 0) >= 2 and feature_dict.get('success_logins_60s', 0) == 0:
        explanations.append(f"Multiple password failures ({int(feature_dict['failed_logins_60s'])} in 60s) - Possible password user error")

    if feature_dict.get('reqs_last_10s', 0) >= 8:
        explanations.append(f"Abnormally high request frequency ({int(feature_dict['reqs_last_10s'])} reqs in 10s)")
    elif feature_dict.get('reqs_last_10s', 0) <= 2 and feature_dict.get('failed_logins_60s', 0) >= 3:
        explanations.append("Low request rate detected (Stealthy brute force pattern)")

    if feature_dict.get('is_new_device') == 1:
        explanations.append("Unrecognized/New device identifier compared to user baseline")

    if feature_dict.get('time_deviation') == 1:
        explanations.append("Unusual login hour outside user's historical baseline window")

    if behavioral_dev >= 0.40:
        explanations.append("Behavioral deviation detected from baseline profile")

    if not explanations:
        explanations.append("Traffic pattern matches normal user behavior baseline")



    return {
        'threat_score': threat_score,
        'risk_level': risk_level,
        'action': action,
        'rf_score': round(rf_score, 4),
        'predicted_category': predicted_category,
        'anomaly_score': round(anomaly_score, 4),
        'behavioral_deviation': round(behavioral_dev, 4),
        'explanations': explanations
    }
