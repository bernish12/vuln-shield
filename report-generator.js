/* ==========================================================================
   VulnShield - Integrated Security Reporting & Executive PDF Compilation Engine
   ========================================================================== */

const ReportGenerator = {
    calculateGrade: function (score) {
        if (score === null || score === undefined) return { grade: 'N/A', label: 'UNAUDITED', color: '#a8b2d1' };
        if (score >= 95) return { grade: 'A+', label: 'EXCELLENT POSTURE', color: '#00e676' };
        if (score >= 90) return { grade: 'A', label: 'STRONG POSTURE', color: '#64ffda' };
        if (score >= 80) return { grade: 'B', label: 'GOOD POSTURE', color: '#82aaff' };
        if (score >= 70) return { grade: 'C', label: 'ATTENTION NEEDED', color: '#ffd700' };
        if (score >= 60) return { grade: 'D', label: 'ELEVATED RISK', color: '#ff9100' };
        return { grade: 'F', label: 'CRITICAL RISK', color: '#ff5252' };
    },

    getRemediation: function (findingTitle, severity) {
        const titleLower = (findingTitle || '').toLowerCase();
        if (titleLower.includes('ssl') || titleLower.includes('tls') || titleLower.includes('https')) {
            return 'Enforce HTTPS redirect and configure TLS 1.3 with strong cipher suites. Install valid SSL certificate via Let\'s Encrypt.';
        }
        if (titleLower.includes('csp') || titleLower.includes('content security policy')) {
            return 'Implement a strict Content-Security-Policy header (default-src \'self\') to mitigate XSS and unauthorized data injection.';
        }
        if (titleLower.includes('xss') || titleLower.includes('cross-site scripting')) {
            return 'Sanitize all user-controlled input on server & client side using DOMPurify and encode HTML output parameters.';
        }
        if (titleLower.includes('bitlocker') || titleLower.includes('encryption')) {
            return 'Enable BitLocker Volume Encryption via Control Panel or PowerShell (Enable-BitLocker -MountPoint "C:").';
        }
        if (titleLower.includes('antivirus') || titleLower.includes('defender')) {
            return 'Ensure Microsoft Defender / Real-time Protection is active in Windows Security settings.';
        }
        if (titleLower.includes('secret') || titleLower.includes('api key') || titleLower.includes('credential')) {
            return 'Revoke exposed API keys immediately. Store secrets in environment variables or cloud secret managers (AWS Secrets Manager / Vault).';
        }
        if (titleLower.includes('hsts') || titleLower.includes('strict-transport')) {
            return 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header to all web responses.';
        }
        if (severity === 'high') {
            return 'Immediate remediation required: Apply security patch, enforce access control policies, and re-audit.';
        }
        if (severity === 'warning' || severity === 'medium') {
            return 'Review configuration parameters and apply recommended security hardening guidelines.';
        }
        return 'Control parameter is verified active. Maintain current security baseline.';
    },

    // Generate full summary data structure
    compileReport: function () {
        const state = {
            timestamp: new Date().toISOString(),
            webScan: this.getSavedWebScan(),
            appScan: this.getSavedAppScan(),
            owaspScan: this.getSavedOwaspScan(),
            deviceAudit: this.getSavedDeviceAudit(),
            summary: {
                high: 0,
                medium: 0,
                low: 0,
                passed: 0,
                totalScore: 0
            }
        };

        // Calculate counts
        if (state.webScan && state.webScan.findings) {
            state.webScan.findings.forEach(f => {
                if (f.severity === 'high') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        if (state.appScan && state.appScan.findings) {
            state.appScan.findings.forEach(f => {
                if (f.severity === 'high') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        if (state.deviceAudit) {
            const os = state.deviceAudit.os;
            const checklists = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            checklists.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                if (passed) {
                    state.summary.passed++;
                } else {
                    state.summary.medium++;
                }
            });
        }

        if (state.owaspScan && state.owaspScan.findings) {
            state.owaspScan.findings.forEach(f => {
                if (f.severity === 'high') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        // Global Score Algorithm
        const scores = [];
        if (state.webScan && state.webScan.findings) {
            const bad = state.webScan.findings.filter(f => f.severity === 'high').length * 25 +
                        state.webScan.findings.filter(f => f.severity === 'warning').length * 10;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.appScan && state.appScan.findings) {
            const bad = state.appScan.findings.filter(f => f.severity === 'high').length * 30 +
                        state.appScan.findings.filter(f => f.severity === 'warning').length * 15;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.deviceAudit && state.deviceAudit.score !== undefined) {
            scores.push(state.deviceAudit.score);
        }
        if (state.owaspScan && state.owaspScan.findings) {
            const bad = state.owaspScan.findings.filter(f => f.severity === 'high').length * 20 +
                        state.owaspScan.findings.filter(f => f.severity === 'warning').length * 8;
            scores.push(Math.max(100 - bad, 0));
        }

        if (scores.length > 0) {
            const sum = scores.reduce((a, b) => a + b, 0);
            state.summary.totalScore = Math.round(sum / scores.length);
        } else {
            state.summary.totalScore = null;
        }

        return state;
    },

    getSavedWebScan: function () {
        const raw = localStorage.getItem('vulnshield_web_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedAppScan: function () {
        const raw = localStorage.getItem('vulnshield_app_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedOwaspScan: function () {
        const raw = localStorage.getItem('vulnshield_owasp_scan');
        return raw ? JSON.parse(raw) : null;
    },

    getSavedDeviceAudit: function () {
        const activeOS = localStorage.getItem('vulnshield_device_active_os') || 'windows';
        const score = (typeof DeviceScanner !== 'undefined') ? DeviceScanner.calculateScore(activeOS) : 0;
        return { os: activeOS, score: score, timestamp: new Date().toISOString() };
    },

    exportJson: function () {
        const data = this.compileReport();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 4));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `vulnshield_security_report_${new Date().getTime()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    },

    exportPdf: function () {
        const report = this.compileReport();
        const gradeInfo = this.calculateGrade(report.summary.totalScore);
        const printWin = window.open('', '_blank');
        
        if (!printWin) {
            alert('Please allow popups to generate the Executive PDF report.');
            return;
        }

        const dateStr = new Date().toLocaleString();

        const allFindings = [];
        if (report.webScan && report.webScan.findings) {
            report.webScan.findings.forEach(f => allFindings.push({ title: `[Web Scan] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.appScan && report.appScan.findings) {
            report.appScan.findings.forEach(f => allFindings.push({ title: `[Static Code Audit] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.owaspScan && report.owaspScan.findings) {
            report.owaspScan.findings.forEach(f => allFindings.push({ title: `[OWASP Top 10] ${f.title}`, severity: f.severity, desc: f.desc }));
        }
        if (report.deviceAudit) {
            const os = report.deviceAudit.os;
            const items = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            items.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                allFindings.push({
                    title: `[Host OS] ${item.title}`,
                    severity: passed ? 'passed' : 'warning',
                    desc: passed ? 'Control parameter is verified active.' : 'Security standard is unverified or disabled.'
                });
            });
        }

        let tableRowsHtml = '';
        if (allFindings.length === 0) {
            tableRowsHtml = `<tr><td colspan="4" style="text-align:center; padding: 2rem; color: #777;">No audit scans recorded yet. Run a scan from the main dashboard to generate report data.</td></tr>`;
        } else {
            allFindings.forEach(f => {
                const sevColor = f.severity === 'high' ? '#ff5252' : (f.severity === 'passed' ? '#00e676' : '#ffd700');
                const remediation = this.getRemediation(f.title, f.severity);
                tableRowsHtml += `
                    <tr>
                        <td style="font-weight:700; color: #fff;">${f.title}</td>
                        <td><span style="color:${sevColor}; font-weight:800; font-family:'JetBrains Mono', monospace;">${(f.severity || '').toUpperCase()}</span></td>
                        <td style="color:#aaa;">${f.desc}</td>
                        <td style="color:#82aaff; font-family:'JetBrains Mono', monospace; font-size: 0.8rem;">🛠️ ${remediation}</td>
                    </tr>
                `;
            });
        }

        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>BernishVuln_Shield – Executive Security Scorecard</title>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
            <style>
                body { font-family: 'Plus Jakarta Sans', sans-serif; margin: 0; padding: 2.5rem; background: #0a0a0e; color: #e0e0e0; }
                .header-flex { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #64ffda; padding-bottom: 1.5rem; margin-bottom: 2rem; }
                .brand-title { font-size: 2.2rem; font-weight: 900; color: #64ffda; letter-spacing: 1.5px; }
                .brand-sub { font-size: 0.95rem; color: #a8b2d1; margin-top: 4px; }
                .grade-badge-box { font-size: 4rem; font-weight: 900; color: ${gradeInfo.color}; text-align: center; border: 3px solid ${gradeInfo.color}; border-radius: 20px; padding: 0.2rem 2rem; background: rgba(0,0,0,0.5); box-shadow: 0 0 30px ${gradeInfo.color}33; }
                .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.2rem; margin-bottom: 2.5rem; }
                .stat-card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 1.2rem; text-align: center; }
                .stat-card .lbl { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #888; margin-bottom: 0.5rem; }
                .stat-card .val { font-size: 2.2rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; margin: 0; }
                table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
                th, td { padding: 1rem 0.8rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 0.85rem; }
                th { background: rgba(100,255,218,0.08); color: #64ffda; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 1px; }
                .btn-print { background: #64ffda; color: #0a0a0e; border: none; padding: 0.8rem 1.8rem; font-weight: 800; border-radius: 8px; cursor: pointer; font-size: 0.95rem; box-shadow: 0 4px 15px rgba(100,255,218,0.4); }
                .btn-print:hover { background: #00e676; }
                @media print {
                    .no-print { display: none !important; }
                    body { background: #ffffff !important; color: #111111 !important; padding: 1rem !important; }
                    .header-flex { border-bottom-color: #111 !important; }
                    .brand-title { color: #111 !important; }
                    .brand-sub { color: #555 !important; }
                    .grade-badge-box { border-color: #111 !important; color: #111 !important; background: none !important; box-shadow: none !important; }
                    .stat-card { background: #f5f5f7 !important; border-color: #ddd !important; }
                    .stat-card .val { color: #111 !important; }
                    th { background: #eaeaea !important; color: #111 !important; }
                    td { border-bottom-color: #ddd !important; color: #222 !important; }
                    td span { color: #111 !important; }
                    td[style*="color: #fff"] { color: #111 !important; }
                    td[style*="color:#aaa"] { color: #444 !important; }
                    .remediation { color: #0044cc !important; }
                }
            </style>
        </head>
        <body>
            <div class="no-print" style="margin-bottom: 2rem; text-align: right;">
                <button class="btn-print" onclick="window.print()">🖨️ Print / Export to PDF</button>
            </div>
            
            <div class="header-flex">
                <div>
                    <div class="brand-title">BERNISH VULNSHIELD</div>
                    <div class="brand-sub">Executive Security Audit & Vulnerability Scorecard</div>
                    <div style="font-size: 0.8rem; color: #777; margin-top: 6px;">Audit Date: ${dateStr}</div>
                </div>
                <div style="text-align: center;">
                    <div class="grade-badge-box">${gradeInfo.grade}</div>
                    <div style="font-size: 0.85rem; font-weight: 800; color: ${gradeInfo.color}; margin-top: 6px;">${gradeInfo.label}</div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="lbl">Overall Security Score</div>
                    <div class="val" style="color: ${gradeInfo.color};">${report.summary.totalScore !== null ? report.summary.totalScore + '/100' : 'N/A'}</div>
                </div>
                <div class="stat-card">
                    <div class="lbl">High Critical Risks</div>
                    <div class="val" style="color: #ff5252;">${report.summary.high}</div>
                </div>
                <div class="stat-card">
                    <div class="lbl">Medium Warnings</div>
                    <div class="val" style="color: #ffd700;">${report.summary.medium}</div>
                </div>
                <div class="stat-card">
                    <div class="lbl">Passed Controls</div>
                    <div class="val" style="color: #64ffda;">${report.summary.passed}</div>
                </div>
            </div>

            <h3 style="font-size: 1.3rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.6rem; color: #fff; margin-top: 2.5rem;">
                Detailed Findings & Remediation Roadmap
            </h3>
            
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Audit Vector / Finding</th>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 28%;">Diagnostic Details</th>
                        <th style="width: 35%;">Actionable Remediation Guidance</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRowsHtml}
                </tbody>
            </table>

            <div style="margin-top: 4rem; text-align: center; font-size: 0.75rem; color: #777; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 1.2rem;">
                Confidential Security Report — Compiled automatically by BernishVuln_Shield v1.2.0 Executive Security Engine
            </div>
        </body>
        </html>
        `;

        printWin.document.write(html);
        printWin.document.close();
    },

    renderReportLogs: function (containerId) {
        const report = this.compileReport();
        const container = document.getElementById(containerId);
        if (!container) return;

        // Update overall counters
        const globalScoreVal = document.getElementById('report-global-score');
        const highCountVal = document.getElementById('report-high-count');
        const medCountVal = document.getElementById('report-med-count');
        const passedCountVal = document.getElementById('report-passed-count');
        
        const gradeBadgeVal = document.getElementById('report-executive-grade');
        const gradeLabelVal = document.getElementById('report-executive-label');

        const gradeInfo = this.calculateGrade(report.summary.totalScore);

        if (gradeBadgeVal) {
            gradeBadgeVal.innerText = gradeInfo.grade;
            gradeBadgeVal.style.color = gradeInfo.color;
        }
        if (gradeLabelVal) {
            gradeLabelVal.innerText = gradeInfo.label;
            gradeLabelVal.style.color = gradeInfo.color;
        }

        if (report.summary.totalScore !== null) {
            globalScoreVal.innerText = `${report.summary.totalScore}/100`;
            globalScoreVal.className = 'num ' + (report.summary.totalScore >= 80 ? 'text-green' : (report.summary.totalScore >= 50 ? 'text-yellow' : 'text-red'));
        } else {
            globalScoreVal.innerText = '--';
            globalScoreVal.className = 'num text-accent';
        }

        highCountVal.innerText = report.summary.high;
        medCountVal.innerText = report.summary.medium;
        passedCountVal.innerText = report.summary.passed;

        // Render detailed findings tables with Remediation column
        container.innerHTML = '';
        let html = '';
        let hasContent = false;

        if (report.webScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-blue" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-globe"></i> Website Scan Summary (${report.webScan.domain})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Finding</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.webScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.appScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-purple" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-mobile-screen-button"></i> Static Code Scanner Summary (${report.appScan.filename})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Vulnerability</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.appScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.owaspScan) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-accent" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-bug-slash"></i> OWASP Top 10 Scanner Summary (${report.owaspScan.url})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Category / Vulnerability</th>
                                <th>Severity</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.owaspScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">[${f.category}] ${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${this.getRemediation(f.title, f.severity)}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (report.deviceAudit) {
            hasContent = true;
            html += `
                <div class="report-section-log mb-4">
                    <h5 class="text-green" style="font-size: 15px; margin-bottom: 8px;"><i class="fa-solid fa-laptop-shield"></i> Local Host OS Compliance (${report.deviceAudit.os.toUpperCase()})</h5>
                    <table class="summary-log-table">
                        <thead>
                            <tr>
                                <th>Audit Control Item</th>
                                <th>Status</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            const os = report.deviceAudit.os;
            const items = (typeof DeviceScanner !== 'undefined' && DeviceScanner.checklists) ? DeviceScanner.checklists[os] : [];
            items.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                html += `
                    <tr>
                        <td style="font-weight: 600;">${item.title}</td>
                        <td><span class="severity-label ${passed ? 'passed' : 'warning'}">${passed ? 'passed' : 'warning'}</span></td>
                        <td class="text-muted small">${passed ? 'Control parameter is verified active.' : this.getRemediation(item.title, 'warning')}</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        if (!hasContent) {
            container.innerHTML = `<div class="empty-state">No security audits committed. Please scan a website, run static file scanner, or update device profiles.</div>`;
        } else {
            container.innerHTML = html;
        }
    }
};
