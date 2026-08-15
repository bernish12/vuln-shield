// login.js - Handles authentication for BernishVuln_Shield
document.getElementById('loginBtn').addEventListener('click', async () => {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('errorMsg');
    errorMsg.textContent = '';
    if (!username || !password) {
        errorMsg.textContent = 'Please enter both username and password.';
        return;
    }
    try {
        const resp = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            // Save token (simple store in localStorage)
            localStorage.setItem('vulnshield_token', data.token);
            // Redirect to dashboard
            window.location.href = '/#dashboard';
        } else {
            errorMsg.textContent = data.error || 'Login failed.';
        }
    } catch (e) {
        console.error('Login error:', e);
        errorMsg.textContent = 'Network error.';
    }
});
