document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const alertBox = document.getElementById('alert-box');
    const otpSection = document.getElementById('otp-section');
    const btnVerifyOtp = document.getElementById('btn-verify-otp');

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

    let currentUsername = '';


    function showAlert(msg, type = 'error') {
        alertBox.className = `alert-box alert-${type}`;
        alertBox.innerHTML = msg;
        alertBox.style.display = 'block';
    }

    function hideAlert() {
        alertBox.style.display = 'none';
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        currentUsername = username;

        // Generate synthetic client device fingerprint
        let deviceId = localStorage.getItem('device_mac_id');
        if (!deviceId) {
            deviceId = username === 'demo1' ? 'device_mac_demo1_legit' : 'device_mac_' + Math.random().toString(36).substring(2, 10);
            localStorage.setItem('device_mac_id', deviceId);
        }

        try {
            const resp = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    device_id: deviceId
                })
            });

            const contentType = resp.headers.get('content-type') || '';
            let data = {};
            if (contentType.includes('application/json')) {
                data = await resp.json();
            } else {
                showAlert(`Server error (${resp.status}): Unexpected response format. Please refresh the page.`, 'error');
                return;
            }

            if (resp.status === 403 || data.blocked) {

                showAlert(`🛑 <strong>ACCESS BLOCKED:</strong> ${data.message}`, 'error');
                return;
            }

            if (data.step_up_required) {
                showAlert(`⚠️ <strong>STEP-UP 2FA CHALLENGE:</strong> ${data.message}`, 'warning');
                otpSection.style.display = 'block';
                return;
            }

            if (data.success) {
                showAlert(`✅ Authentication successful. Redirecting...`, 'success');
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 800);
            } else {
                showAlert(`❌ ${data.message || 'Login failed.'}`, 'error');
            }
        } catch (err) {
            showAlert(`Connection error: ${err.message}`, 'error');
        }
    });

    btnVerifyOtp.addEventListener('click', async () => {
        const otp = document.getElementById('otp').value.trim();
        try {
            const resp = await fetch('/api/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUsername, otp: otp })
            });
            const data = await resp.json();

            if (data.success) {
                showAlert(`✅ 2FA Verification successful! Redirecting...`, 'success');
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 800);
            } else {
                showAlert(`❌ ${data.message}`, 'error');
            }
        } catch (err) {
            showAlert(`OTP Error: ${err.message}`, 'error');
        }
    });
});
