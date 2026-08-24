// login.js - Handles authentication for BernishVuln_Shield
async function performLogin(e) {
    if (e) e.preventDefault();
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
            // Save token in localStorage
            localStorage.setItem('vulnshield_token', data.token);
            // Redirect to dashboard
            window.location.href = '/index.html';
        } else {
            errorMsg.textContent = data.error || 'Invalid username or password.';
        }
    } catch (e) {
        console.error('Login error:', e);
        errorMsg.textContent = 'Network error. Please try again.';
    }
}

const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', performLogin);
} else {
    document.getElementById('loginBtn').addEventListener('click', performLogin);
}
