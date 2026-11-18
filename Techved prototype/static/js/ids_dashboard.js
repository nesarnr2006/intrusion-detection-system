document.addEventListener('DOMContentLoaded', () => {
    // Theme Switcher Logic
    const themeBtn = document.getElementById('theme-toggle');
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        if (themeBtn) {
            themeBtn.textContent = theme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
        }
    }

    const savedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(savedTheme);

    if (themeBtn) {
        themeBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            applyTheme(newTheme);
        });
    }

    // Elements
    const systemStatusEl = document.getElementById('system-status');

    const threatScoreNumEl = document.getElementById('threat-score-num');
    const threatLevelBadgeEl = document.getElementById('threat-level-badge');
    const actionTextEl = document.getElementById('action-text');

    const scoreRfEl = document.getElementById('score-rf');
    const predictedCatEl = document.getElementById('predicted-category');
    const scoreIsoEl = document.getElementById('score-iso');
    const scoreDevEl = document.getElementById('score-dev');

    const featReqs10 = document.getElementById('feat-reqs10');
    const featReqs60 = document.getElementById('feat-reqs60');
    const featFailed60 = document.getElementById('feat-failed60');
    const featInterval = document.getElementById('feat-interval');
    const featAccounts = document.getElementById('feat-accounts');
    const featDevice = document.getElementById('feat-device');

    const trafficTableBody = document.getElementById('traffic-table-body');
    const explanationList = document.getElementById('explanation-list');
    const alertsFeed = document.getElementById('alerts-feed');

    // Fetch Dashboard State from Backend
    async function updateDashboard() {
        try {
            const resp = await fetch('/api/dashboard');
            if (!resp.ok) return;
            const data = await resp.json();
            if (!data.success) return;

            // 1. System Status
            if (data.system_status === 'ATTACK DETECTED') {
                systemStatusEl.className = 'status-badge attack';
                systemStatusEl.textContent = '🚨 ATTACK DETECTED';
            } else {
                systemStatusEl.className = 'status-badge protected';
                systemStatusEl.textContent = '🛡️ SYSTEM PROTECTED';
            }

            // 2. Threat Score Gauge
            const summary = data.threat_summary;
            const score = summary.threat_score;
            threatScoreNumEl.textContent = score.toFixed(2);

            let riskClass = 'risk-low';
            let bgRiskClass = 'bg-risk-low';
            if (summary.risk_level === 'MEDIUM') {
                riskClass = 'risk-medium';
                bgRiskClass = 'bg-risk-medium';
            } else if (summary.risk_level === 'HIGH') {
                riskClass = 'risk-high';
                bgRiskClass = 'bg-risk-high';
            } else if (summary.risk_level === 'VERY HIGH' || summary.risk_level === 'CRITICAL') {
                riskClass = 'risk-critical';
                bgRiskClass = 'bg-risk-critical';
            }

            threatScoreNumEl.className = `threat-score-num ${riskClass}`;
            threatLevelBadgeEl.className = `threat-level-badge ${bgRiskClass}`;
            threatLevelBadgeEl.textContent = summary.risk_level + ' RISK';
            actionTextEl.textContent = summary.action;
            actionTextEl.style.color = (summary.risk_level === 'LOW' || summary.risk_level === 'MEDIUM') ? 'var(--accent-green)' : 'var(--accent-red)';

            // 3. Model Breakdown Scores
            scoreRfEl.textContent = summary.rf_score.toFixed(2);
            predictedCatEl.textContent = summary.predicted_category;
            scoreIsoEl.textContent = summary.anomaly_score.toFixed(2);
            scoreDevEl.textContent = summary.behavioral_deviation.toFixed(2);

            // 4. Feature Metrics
            const feat = data.features;
            featReqs10.textContent = feat.reqs_last_10s;
            featReqs60.textContent = feat.reqs_last_60s;
            featFailed60.textContent = feat.failed_logins_60s;
            featInterval.textContent = feat.avg_interval_sec.toFixed(1) + 's';
            featAccounts.textContent = feat.unique_accounts_targeted;

            if (feat.is_new_device === 1) {
                featDevice.textContent = 'NEW / UNKNOWN';
                featDevice.style.color = 'var(--accent-orange)';
            } else {
                featDevice.textContent = 'VERIFIED BASELINE';
                featDevice.style.color = 'var(--accent-green)';
            }

            // 5. Live Traffic Table
            if (data.recent_events && data.recent_events.length > 0) {
                let html = '';
                data.recent_events.forEach(ev => {
                    const statusBadge = ev.success === 'SUCCESS' 
                        ? '<span class="badge badge-success">200 OK</span>'
                        : '<span class="badge badge-danger">' + ev.status_code + ' FAIL</span>';

                    html += `
                        <tr>
                            <td style="font-family: var(--font-code); font-size: 0.8rem;">${ev.time_str}</td>
                            <td style="font-weight: 600;">${ev.username}</td>
                            <td style="font-family: var(--font-code); font-size: 0.8rem; color: var(--text-secondary);">${ev.endpoint}</td>
                            <td>${statusBadge}</td>
                            <td style="font-family: var(--font-code); font-size: 0.75rem; color: var(--text-muted);">${ev.device_id.substring(0, 16)}</td>
                        </tr>
                    `;
                });
                trafficTableBody.innerHTML = html;
            } else {
                trafficTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No traffic logged yet. Trigger demo events above.</td></tr>';
            }

            // 6. Model Decision Explanations
            if (summary.explanations && summary.explanations.length > 0) {
                let expHtml = '';
                summary.explanations.forEach(exp => {
                    expHtml += `<li>${exp}</li>`;
                });
                explanationList.innerHTML = expHtml;
            }

            // 7. Security Alerts Feed
            if (data.recent_alerts && data.recent_alerts.length > 0) {
                let alertHtml = '';
                data.recent_alerts.forEach(alt => {
                    alertHtml += `
                        <div style="padding: 0.65rem; background: var(--bg-dark); border-left: 3px solid var(--accent-red); border-radius: 4px; margin-bottom: 0.5rem;">
                            <div style="display: flex; justify-content: space-between; font-size: 0.8rem; font-weight: 700; color: var(--accent-red);">
                                <span>🚨 ${alt.attack_type}</span>
                                <span>${alt.time_str}</span>
                            </div>
                            <div style="font-size: 0.8rem; color: var(--text-primary); margin-top: 0.2rem;">${alt.details}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.2rem;">
                                Score: ${alt.threat_score} | Action: <strong>${alt.action_taken}</strong>
                            </div>
                        </div>
                    `;
                });
                alertsFeed.innerHTML = alertHtml;
            } else {
                alertsFeed.innerHTML = '<div style="font-size: 0.85rem; color: var(--text-muted); padding: 0.5rem 0;">No active security alerts logged.</div>';
            }

        } catch (err) {
            console.error('Dashboard polling error:', err);
        }
    }

    // Demo Button Click Handlers
    async function triggerDemo(endpoint) {
        try {
            const resp = await fetch(endpoint, { method: 'POST' });
            const data = await resp.json();
            updateDashboard();
        } catch (err) {
            console.error('Demo trigger error:', err);
        }
    }

    document.getElementById('btn-demo-normal').addEventListener('click', () => triggerDemo('/api/demo/normal'));
    document.getElementById('btn-demo-forgot').addEventListener('click', () => triggerDemo('/api/demo/forgot-password'));
    document.getElementById('btn-demo-bf').addEventListener('click', () => triggerDemo('/api/demo/bruteforce'));
    document.getElementById('btn-demo-slow').addEventListener('click', () => triggerDemo('/api/demo/slow'));
    document.getElementById('btn-demo-cs').addEventListener('click', () => triggerDemo('/api/demo/credential-stuffing'));
    const btnSqli = document.getElementById('btn-demo-sqli');
    if (btnSqli) btnSqli.addEventListener('click', () => triggerDemo('/api/demo/sqli'));
    const btnReset = document.getElementById('btn-demo-reset');
    if (btnReset) {
        btnReset.addEventListener('click', async () => {
            // Immediate client-side DOM reset
            systemStatusEl.className = 'status-badge protected';
            systemStatusEl.textContent = '🛡️ SYSTEM PROTECTED';
            threatScoreNumEl.textContent = '0.05';
            threatScoreNumEl.className = 'threat-score-num risk-low';
            threatLevelBadgeEl.className = 'threat-level-badge bg-risk-low';
            threatLevelBadgeEl.textContent = 'LOW RISK';
            actionTextEl.textContent = 'ALLOW';
            actionTextEl.style.color = 'var(--accent-green)';
            
            scoreRfEl.textContent = '0.02';
            predictedCatEl.textContent = 'NORMAL';
            scoreIsoEl.textContent = '0.05';
            scoreDevEl.textContent = '0.02';

            featReqs10.textContent = '0';
            featReqs60.textContent = '0';
            featFailed60.textContent = '0';
            featInterval.textContent = '60s';
            featAccounts.textContent = '1';
            featDevice.textContent = 'VERIFIED BASELINE';
            featDevice.style.color = 'var(--accent-green)';

            trafficTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No traffic logged yet. Trigger demo events above.</td></tr>';
            explanationList.innerHTML = '<li>System operating normally. No active threats detected.</li>';
            alertsFeed.innerHTML = '<div style="font-size: 0.85rem; color: var(--text-muted); padding: 0.5rem 0;">No active security alerts logged.</div>';

            await triggerDemo('/api/demo/reset');
        });
    }



    // Start auto polling every 1.5 seconds
    updateDashboard();
    setInterval(updateDashboard, 1500);
});
