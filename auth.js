(async function () {
    const token = localStorage.getItem('vulnshield_token');

    // No token stored — go to login immediately
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    // Validate the token with the server (handles server restarts clearing in-memory tokens)
    try {
        const resp = await fetch('/api/verify', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!resp.ok) {
            // Token rejected — clear it and redirect to login
            localStorage.removeItem('vulnshield_token');
            window.location.href = '/login.html';
        }
        // Token is valid — allow the page to load normally
    } catch (e) {
        // Network error — still allow through (server may be starting up)
        console.warn('[VulnShield] Token verification failed due to network error:', e.message);
    }
})();
