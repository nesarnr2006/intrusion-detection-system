# ML-Based Behavioral Intrusion Detection System (IDS)
> **Smart India Hackathon (SIH) Prototype Demonstration**

This project is a complete, working local prototype of a **Machine Learning-Based Behavioral Intrusion Detection System (IDS)** designed for modern web applications and financial portals.

---

## 🌟 Key Problem & Solution

### The Problem
Traditional firewalls and web application firewalls (WAFs) rely heavily on known signatures, static IP blacklists, and rigid rate limits (e.g. 5 failed logins = block). Attackers easily bypass these using:
- IP rotation & botnets
- Stealthy **Low-and-Slow** brute-force attacks that stay under rate limits
- Zero-day attack techniques with no existing signatures

### Our Solution
Our system continuously analyzes **10 real-time behavioral features** using a dual ML pipeline:
1. **Supervised Random Forest Classifier**: Detects known attack signatures (Brute Force, Credential Stuffing, DoS, Port Scan).
2. **Unsupervised Isolation Forest**: Learns normal user traffic patterns and flags unknown / zero-day anomalies.
3. **User Behavioral Baselines**: Compares logins against user-specific historical baselines (usual device ID, expected operating hours, request intervals).
4. **Tiered Security Response**: Replaces blind blocking with proportional risk-based responses (`ALLOW`, `MONITOR`, `STEP-UP 2FA OTP`, `TEMPORARY LOCK`, `BLOCK + ALERT`).

---

## 🏗️ Tech Stack

- **Backend**: Python 3, Flask, Flask-CORS
- **Machine Learning**: `scikit-learn`, `pandas`, `numpy`, `joblib`
- **Database**: SQLite3
- **Frontend**: HTML5, CSS3 (Custom Dark Security Theme), Vanilla JavaScript
- **Simulator**: Python `requests` harness targeting `http://127.0.0.1:5000`

---

## 📁 Project Architecture

```
ids-prototype/
│
├── app.py                     # Main Flask Application & Traffic Logger Middleware
├── requirements.txt           # Python Dependencies
├── README.md                  # System Documentation & Security Disclaimers
├── DEMO_GUIDE.md              # 7-Phase SIH Presentation Guide for Judges
│
├── database/
│   ├── init_db.py             # SQLite Schema Setup & Seed Data
│   └── ids.db                 # SQLite Local Database (Created on initialization)
│
├── ml/
│   ├── feature_engineering.py # Extracts 10 Behavioral Rolling Window Features
│   ├── train_model.py         # Trains RF & Isolation Forest Models + Evaluation
│   ├── predict.py             # Multi-Model Threat Scoring Engine & Explanations
│   ├── random_forest.pkl      # Serialized Supervised Random Forest Model
│   └── isolation_forest.pkl   # Serialized Unsupervised Isolation Forest Model
│
├── simulator/
│   └── attack_simulator.py    # Localhost Attack Simulator CLI Harness
│
├── templates/
│   ├── login.html             # BankGuard Financial Portal Login UI
│   ├── dashboard.html         # User Financial Account Dashboard
│   └── ids_dashboard.html     # Real-Time SOC Security IDS Monitoring Dashboard
│
├── static/
│   ├── css/
│   │   └── style.css          # Modern Cyber Dark Theme Styling
│   └── js/
│       ├── login.js           # Client Authentication & 2FA Handler
│       └── ids_dashboard.js   # Real-Time SOC Dashboard Polling (1.5s)
│
└── routes/
    ├── auth.py                # Authentication & Step-Up OTP API Endpoints
    ├── traffic.py             # Traffic Logging APIs
    └── ids.py                 # IDS Aggregation & Interactive Demo Triggers
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites & Environment Setup
Open a terminal in the project directory:

```bash
# Create Python virtual environment
python -m venv venv

# Activate Virtual Environment
# Windows PowerShell / CMD:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Model Training
Pre-trained models are automatically generated on initial startup, but you can manually train and inspect the ML performance metrics at any time:

```bash
python ml/train_model.py
```

### 3. Run the Local Server
Start the Flask application server:

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`.

### 4. Access URLs in Browser
- **Bank Portal Login**: `http://127.0.0.1:5000/login`
- **SOC IDS Monitoring Console**: `http://127.0.0.1:5000/ids`

---

## 🎯 Running Attack Simulations

Start the interactive CLI simulator in a **new terminal window** (keep `python app.py` running):

```bash
python simulator/attack_simulator.py
```

Select any menu option:
1. **Normal Login**: Simulates legitimate user logging in. (`Threat: ~0.05` -> `ALLOW`)
2. **Genuine Forgotten Password**: 3 failed attempts + 1 successful attempt on legitimate device. (`Threat: ~0.38` -> `ALLOW / MONITOR`)
3. **Brute Force Attack**: 100 rapid requests. (`Threat: >0.85` -> `TEMPORARY LOCK / BLOCK`)
4. **Credential Stuffing**: Targets multiple demo accounts rapidly. (`Threat: >0.80` -> `HIGH RISK`)
5. **Low-and-Slow Attack**: Spaced requests with anomalous device/time. (`Threat: ~0.68` -> `STEP-UP VERIFICATION`)
6. **Reset Demo State**: Resets SQLite database and event logs.

Alternatively, use the **Interactive Demo Trigger Buttons** directly at the top of the SOC IDS Dashboard (`http://127.0.0.1:5000/ids`).

---

## 📊 Combined Threat Score Formula

The IDS evaluates each event against a weighted formula:

$$\text{Threat Score} = (0.50 \times \text{RF Score}) + (0.30 \times \text{Anomaly Score}) + (0.20 \times \text{Behavioral Deviation})$$

### Risk Tiers & Actions

| Score Range | Risk Level | Action Taken |
| :--- | :--- | :--- |
| `0.00 – 0.30` | **LOW** | `ALLOW` |
| `0.30 – 0.60` | **MEDIUM** | `MONITOR` |
| `0.60 – 0.80` | **HIGH** | `STEP-UP VERIFICATION (2FA OTP)` |
| `0.80 – 0.95` | **VERY HIGH** | `TEMPORARY LOCK` |
| `0.95 – 1.00` | **CRITICAL** | `BLOCK + SECURITY ALERT` |

---

## ⚠️ Security Disclaimers

1. **Hackathon Demonstration Prototype**: This project is built strictly as a local demonstration prototype for hackathons.
2. **Localhost Execution**: All simulation tools target `http://127.0.0.1:5000` (localhost). No real external websites, public IPs, or third-party servers are probed or targeted.
3. **Synthetic Dataset**: Models in this prototype are trained on a reproducible synthetic dataset designed around behavioral features. (Not CICIDS2017).
4. **No Guaranteed Zero-Day Protection**: Behavioral ML reduces risk, but no anomaly detection system guarantees 100% detection of zero-day threats.
5. **Production Requirements**: Full enterprise deployment would require network TAP integration, hardware WAFs, TLS termination, distributed logging, encrypted session storage, and rate limiting.
