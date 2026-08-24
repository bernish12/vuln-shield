(async function () {
    const isLoginPage = window.location.pathname.endsWith('login.html');

    // Handle cross-tab storage changes (logging out or logging in on another tab)
    window.addEventListener('storage', (e) => {
        if (e.key === 'vulnshield_token') {
            if (!e.newValue && !isLoginPage) {
                window.location.href = '/login.html';
            } else if (e.newValue && isLoginPage) {
                window.location.href = '/index.html';
            }
        }
    });

    // Expose global Logout function
    window.logout = function () {
        localStorage.removeItem('vulnshield_token');
        sessionStorage.removeItem('vulnshield_token');
        window.location.href = '/login.html';
    };

    const token = localStorage.getItem('vulnshield_token');

    if (isLoginPage) {
        // On login page: if token exists, verify and redirect to main app if valid
        if (token) {
            try {
                const resp = await fetch('/api/verify', {
                    method: 'GET',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (resp.ok) {
                    window.location.href = '/index.html';
                } else {
                    localStorage.removeItem('vulnshield_token');
                }
            } catch (e) {
                console.warn('[VulnShield] Login page token check network error:', e.message);
            }
        }
        return;
    }

    // On protected page: no token stored -> go to login immediately
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    // Validate token with server
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
    } catch (e) {
        console.warn('[VulnShield] Token verification failed due to network error:', e.message);
    }
})();
