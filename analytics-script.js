function parseUserAgent(ua) {
            let os = "Unknown OS";
            let browser = "Unknown Browser";

            if (ua.includes('Windows')) os = 'Windows';
            else if (ua.includes('Mac OS')) os = 'macOS';
            else if (ua.includes('Linux')) os = 'Linux';
            else if (ua.includes('Android')) os = 'Android';
            else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

            if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'Chrome';
            else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
            else if (ua.includes('Firefox')) browser = 'Firefox';
            else if (ua.includes('Edg')) browser = 'Edge';

            return `${os} | ${browser}`;
        }

        async function fetchDashboardData() {
            const token = sessionStorage.getItem('vulnshield_token') || localStorage.getItem('vulnshield_token') || localStorage.getItem('vuln_token');
            if (!token) { window.location.href = '/login.html'; return; }

            try {
                const decodedPayload = atob(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'));
                const username = decodedPayload.split(':')[0];
                if (username !== 'bernish2004cyber') {
                    window.location.href = '/index.html';
                    return;
                }
            } catch(e) {}

            try {
                const res = await fetch('/api/analytics/dashboard', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                if (res.status === 401) { logout(); return; }
                if (!res.ok) throw new Error('Failed to fetch data');

                const data = await res.json();
                renderDashboard(data);
            } catch (err) {
                console.error(err);
                alert('Error loading dashboard data.');
            }
        }

        async function kickSession(sessionId) {
            if (!confirm('Are you sure you want to kick this device? They will be logged out immediately.')) return;
            
            const token = sessionStorage.getItem('vulnshield_token') || localStorage.getItem('vulnshield_token') || localStorage.getItem('vuln_token');
            try {
                const res = await fetch('/api/analytics/kick', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ sessionId })
                });
                
                if (res.ok) {
                    try {
                        const decodedPayload = atob(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'));
                        const currentSessionId = decodedPayload.split(':')[1];
                        if (sessionId === currentSessionId) {
                            logout();
                            return;
                        }
                    } catch(e){}
                    fetchDashboardData();
                } else {
                    alert('Failed to kick session.');
                }
            } catch(e) {
                alert('Error kicking session.');
            }
        }

        function renderDashboard(data) {
            const { activeSessions, loginHistory, visitorLogs } = data;

            // Stats
            document.getElementById('stat-active').innerText = Object.keys(activeSessions).length;
            document.getElementById('stat-visits').innerText = visitorLogs.length;
            
            let failedCount = 0;
            loginHistory.forEach(l => { if(l.status === 'failed') failedCount++; });
            document.getElementById('stat-failed').innerText = failedCount;

            const uniqueIps = new Set();
            visitorLogs.forEach(v => uniqueIps.add(v.ip));
            document.getElementById('stat-ips').innerText = uniqueIps.size;

            // Current Session ID and Role
            let currentSessionId = '';
            let currentUserRole = 'user';
            try {
                const token = sessionStorage.getItem('vulnshield_token') || localStorage.getItem('vulnshield_token') || localStorage.getItem('vuln_token');
                if (token) {
                    const decodedPayload = atob(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'));
                    const parts = decodedPayload.split(':');
                    const username = parts[0];
                    currentSessionId = parts[1];
                    if (username === 'bernish2004cyber') {
                        currentUserRole = 'admin';
                    }
                }
            } catch(e) {}

            // Render Active Sessions
            const sessionsBody = document.getElementById('sessions-tbody');
            sessionsBody.innerHTML = '';
            if (Object.keys(activeSessions).length === 0) {
                sessionsBody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No active sessions.</td></tr>';
            } else {
                for (const [id, session] of Object.entries(activeSessions)) {
                    const isCurrent = id === currentSessionId;
                    const tr = document.createElement('tr');
                    
                    let actionHtml = '';
                    if (isCurrent) {
                        actionHtml = '<span class="text-muted">Current Session</span>';
                    } else if (currentUserRole === 'admin') {
                        actionHtml = `<button class="btn-kick" onclick="kickSession('${id}')"><i class="fa-solid fa-user-xmark"></i> Kick</button>`;
                    } else {
                        actionHtml = '<span class="text-muted" style="font-size:0.8rem;">No Permission</span>';
                    }

                    tr.innerHTML = `
                        <td><span class="badge-device">${parseUserAgent(session.userAgent)}</span><br><small class="text-muted" style="color:#64ffda;">User: ${session.username}</small></td>
                        <td><span class="badge-ip">${session.ip}</span></td>
                        <td>${new Date(session.loginTime).toLocaleString()}</td>
                        <td>${new Date(session.lastActive).toLocaleString()}</td>
                        <td>${actionHtml}</td>
                    `;
                    sessionsBody.appendChild(tr);
                }
            }

            // Render Login History
            const loginBody = document.getElementById('login-tbody');
            loginBody.innerHTML = '';
            if (loginHistory.length === 0) {
                loginBody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No login history.</td></tr>';
            } else {
                loginHistory.forEach(log => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td><span class="badge-${log.status}">${log.status.toUpperCase()}</span></td>
                        <td>${log.username}</td>
                        <td><span class="badge-ip">${log.ip}</span></td>
                        <td><span class="badge-device">${parseUserAgent(log.userAgent)}</span></td>
                    `;
                    loginBody.appendChild(tr);
                });
            }

            // Render Visitor Logs
            const logsBody = document.getElementById('logs-tbody');
            logsBody.innerHTML = '';
            if (visitorLogs.length === 0) {
                logsBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No logs found.</td></tr>';
            } else {
                visitorLogs.forEach(log => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td><span class="badge-ip">${log.ip}</span></td>
                        <td><span class="badge-device" title="${log.userAgent}">${parseUserAgent(log.userAgent)}</span></td>
                        <td><span class="badge-url">${log.url}</span></td>
                    `;
                    logsBody.appendChild(tr);
                });
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', fetchDashboardData);