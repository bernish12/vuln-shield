/* ==========================================================================
   VulnShield - Integrated Security Reporting & PDF Compilation Engine
   ========================================================================== */

const ReportGenerator = {
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
        // 1. Web count
        if (state.webScan && state.webScan.findings) {
            state.webScan.findings.forEach(f => {
                if (f.severity === 'high') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        // 2. App count
        if (state.appScan && state.appScan.findings) {
            state.appScan.findings.forEach(f => {
                if (f.severity === 'high') state.summary.high++;
                else if (f.severity === 'warning') state.summary.medium++;
                else if (f.severity === 'info') state.summary.low++;
                else if (f.severity === 'passed') state.summary.passed++;
            });
        }

        // 3. Device count
        if (state.deviceAudit) {
            const os = state.deviceAudit.os;
            const checklists = DeviceScanner.checklists[os];
            checklists.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                if (passed) {
                    state.summary.passed++;
                } else {
                    // Failures in device checklist are marked as warnings
                    state.summary.medium++;
                }
            });
        }

        // 4. OWASP count
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
            const total = state.webScan.findings.length;
            const bad = state.webScan.findings.filter(f => f.severity === 'high').length * 25 +
                        state.webScan.findings.filter(f => f.severity === 'warning').length * 10;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.appScan && state.appScan.findings) {
            const bad = state.appScan.findings.filter(f => f.severity === 'high').length * 30 +
                        state.appScan.findings.filter(f => f.severity === 'warning').length * 15;
            scores.push(Math.max(100 - bad, 0));
        }
        if (state.deviceAudit) {
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
        const score = DeviceScanner.calculateScore(activeOS);
        
        return {
            os: activeOS,
            score: score,
            timestamp: new Date().toISOString()
        };
    },

    // Save report to disk as JSON configuration file
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

    // Populate Report Pane details in DOM
    renderReportLogs: function (containerId) {
        const report = this.compileReport();
        const container = document.getElementById(containerId);
        if (!container) return;

        // Update overall counters
        const globalScoreVal = document.getElementById('report-global-score');
        const highCountVal = document.getElementById('report-high-count');
        const medCountVal = document.getElementById('report-med-count');
        const passedCountVal = document.getElementById('report-passed-count');

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

        // Render detailed findings tables
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
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.webScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${f.desc.substring(0, 80)}...</td>
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
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.appScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${f.desc.substring(0, 80)}...</td>
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
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            report.owaspScan.findings.forEach(f => {
                html += `
                    <tr>
                        <td style="font-weight: 600;">[${f.category}] ${f.title}</td>
                        <td><span class="severity-label ${f.severity === 'warning' ? 'warning' : f.severity}">${f.severity}</span></td>
                        <td class="text-muted small">${f.desc.substring(0, 80)}...</td>
                    </tr>
                `;
            });
            html += `</tbody></table></div>`;
        }

        // Device Check
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
                                <th>Vulnerability Profile</th>
                            </tr>
                        </thead>
                        <tbody>
            `;
            const os = report.deviceAudit.os;
            const items = DeviceScanner.checklists[os];
            items.forEach(item => {
                const passed = localStorage.getItem(`vulnshield_audit_${os}_${item.id}`) === 'true';
                html += `
                    <tr>
                        <td style="font-weight: 600;">${item.title}</td>
                        <td><span class="severity-label ${passed ? 'passed' : 'warning'}">${passed ? 'passed' : 'warning'}</span></td>
                        <td class="text-muted small">${passed ? 'Control parameter is verified active.' : 'Security standard is unverified or disabled.'}</td>
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
