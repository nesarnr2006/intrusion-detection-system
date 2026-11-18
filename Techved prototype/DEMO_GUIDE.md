# 🏆 SIH Judge Presentation & Demonstration Script

Follow this step-by-step 3-5 minute presentation flow during the Smart India Hackathon (SIH) judging round.

---

## 📍 PHASE 1: System Startup & Dashboard Walkthrough
1. Start the Flask application (`python app.py`).
2. Open `http://127.0.0.1:5000/ids` on a browser tab or secondary monitor.
3. Open `http://127.0.0.1:5000/login` on another tab.

> **What to tell Judges:**
> *"Respected Judges, traditional security systems rely on static IP blacklists and fixed rules (like blocking after 5 failed passwords). Attackers easily bypass these with IP rotation or slow brute forcing. Our solution uses Machine Learning to establish user behavioral baselines, combine supervised and unsupervised models, and apply a tiered risk response."*

---

## 📍 PHASE 2: Normal User Login
1. On the Bank Login page (`/login`), sign in with demo credentials:
   - **Username**: `demo1`
   - **Password**: `password123`
2. Click **Authenticate & Sign In**. User is redirected to the Financial Dashboard.
3. Switch to the SOC IDS Dashboard tab.

> **What to show on Dashboard:**
> - System Status: `PROTECTED`
> - Threat Score: ~`0.05`
> - Risk Level: `LOW RISK`
> - Action: `ALLOW`
>
> **What to tell Judges:**
> *"Notice that for a normal login from a known device at expected hours, the threat score remains very low (~0.05) and access is allowed seamlessly."*

---

## 📍 PHASE 3: Genuine Forgotten Password Scenario
1. Click the **[ 🟡 2. Genuine Forgotten Password ]** button on the IDS Dashboard (or run Option 2 in `attack_simulator.py`).
2. Watch the dashboard update live.

> **What to show on Dashboard:**
> - 3 failed attempts + 1 success on the same known device.
> - Threat Score: ~`0.38`
> - Risk Level: `MEDIUM RISK`
> - Action: `ALLOW / MONITOR`
> - Explanation: *"Multiple login failures - Possible password user error"*.
>
> **What to tell Judges:**
> *"Crucially, our system does NOT blindly block a user who simply forgot their password. Because the request originates from a verified device during normal hours, the system recognizes it as human error, assigning a MEDIUM risk tier (MONITOR) rather than locking the user out."*

---

## 📍 PHASE 4: Rapid Brute Force Attack
1. Click the **[ 🔴 3. Brute Force Attack ]** button on the IDS Dashboard (or run Option 3 in `attack_simulator.py`).
2. Watch the real-time traffic stream and threat gauge.

> **What to show on Dashboard:**
> - Request count & failure rate spike rapidly (25+ requests in 4 seconds).
> - System Status: `🚨 ATTACK DETECTED`
> - Threat Score: `> 0.85`
> - Risk Level: `VERY HIGH / CRITICAL`
> - Action: `TEMPORARY LOCK` or `BLOCK + SECURITY ALERT`
> - Random Forest Score: `> 0.90` (Category: `BRUTE_FORCE`)
>
> **What to tell Judges:**
> *"When a rapid brute-force burst occurs from an unknown device, the supervised Random Forest model immediately classifies the high frequency and failure rate as a known attack, automatically locking out the session."*

---

## 📍 PHASE 5: Stealthy Low-and-Slow Attack (Key Differentiator)
1. Click **[ 🔄 Reset Demo State ]** first to clear alerts.
2. Click **[ ⚠️ 4. Low-and-Slow Attack ]** button (or run Option 5 in `attack_simulator.py`).

> **What to show on Dashboard:**
> - Request rate feature remains LOW (only 1 request every 15s - looks normal to simple firewalls!).
> - However, Behavioral Baseline Deviation = `0.65` (New device ID + off-hours login + interval anomaly).
> - Isolation Forest Anomaly Score = `0.72`.
> - Combined Threat Score: ~`0.68`
> - Risk Level: `HIGH RISK`
> - Action: `STEP-UP VERIFICATION (2FA OTP)`
>
> **What to tell Judges:**
> *"This is our core innovation. In a Low-and-Slow attack, request rates remain low, so standard rate limiters fail to detect it. But our system evaluates behavioral context—unrecognized device MAC, off-hours timing, and anomaly deviation. Instead of ignoring it or blocking outright, it triggers a Step-Up 2FA Challenge."*

---

## 📍 PHASE 6: Multi-Model Architecture Overview
Point to the **Judge Explanation Card** at the bottom of the IDS Dashboard:
- **Random Forest**: Handles known attack patterns (Brute Force, Credential Stuffing, DoS, Port Scans).
- **Isolation Forest**: Handles unknown / zero-day behavioral anomalies.
- **Behavioral Baselines**: Tracks user-specific normal operating parameters.
- **Combined Threat Formula**:
  $$\text{Threat Score} = (0.50 \times \text{RF}) + (0.30 \times \text{Isolation Forest}) + (0.20 \times \text{Baseline Deviation})$$

---

## 📍 PHASE 7: ML Evaluation Metrics
Run `python ml/train_model.py` to display the ML model evaluation report:
- **Test Accuracy**: > 98%
- **Precision / Recall / F1 Score**: Displayed per attack category.

> **What to tell Judges:**
> *"Our ML models are evaluated with confusion matrices and standard classification reports. The prototype uses a reproducible synthetic training pipeline designed specifically around these behavioral feature vectors."*
