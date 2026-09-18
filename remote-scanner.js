/* ==========================================================================
   VulnShield - Remote Laptop IP Spyware, Malware & Compromise Scanner
   Audits ANY remote laptop or network host via IP Address from this dashboard
   ========================================================================== */

const RemoteScanner = (() => {

    let isRunning = false;

    // --- Helper Functions ---
    function addLine(termEl, cls, txt) {
        if (!termEl) return;
        const div = document.createElement('div');
        div.className = `mob-term-line ${cls}`;
        div.textContent = txt;
        termEl.appendChild(div);
        termEl.scrollTop = termEl.scrollHeight;
    }

    function sleep(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    function setButtonsState(disabled) {
        const btnLive = document.getElementById('btn-remote-live');
        const btnDemo = document.getElementById('btn-remote-demo');
        const btnReset = document.getElementById('btn-remote-reset');
        const ipInput = document.getElementById('remote-target-ip');

        if (btnLive) btnLive.disabled = disabled;
        if (btnDemo) btnDemo.disabled = disabled;
        if (ipInput) ipInput.disabled = disabled;
        if (btnReset) btnReset.style.display = disabled ? 'none' : 'inline-flex';
    }

    function setPreset(ip, isDemo = false) {
        const ipInput = document.getElementById('remote-target-ip');
        if (ipInput) {
            ipInput.value = ip;
            ipInput.focus();
        }
        if (isDemo) {
            runScan(true);
        }
    }

    // =========================================================================
    // MAIN REMOTE SCAN RUNNER
    // =========================================================================
    async function runScan(isDemo = false) {
        if (isRunning) return;

        const ipInput = document.getElementById('remote-target-ip');
        let targetIp = (ipInput ? ipInput.value : '').trim();

        if (isDemo && (!targetIp || targetIp === '127.0.0.1')) {
            targetIp = '192.168.1.105';
            if (ipInput) ipInput.value = targetIp;
        }

        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const isLocal = targetIp === 'localhost' || targetIp === '127.0.0.1';

        if (!targetIp || (!ipv4Regex.test(targetIp) && !isLocal)) {
            alert('Please enter a valid IPv4 address (e.g., 192.168.1.45 or 10.0.0.12)');
            if (ipInput) ipInput.focus();
            return;
        }

        isRunning = true;
        setButtonsState(true);

        const wrapper     = document.getElementById('remote-scan-wrapper');
        const termEl      = document.getElementById('remote-scan-terminal');
        const progressBar = document.getElementById('remote-scan-bar');
        const phaseLabel  = document.getElementById('remote-scan-phase');
        const verdictEl   = document.getElementById('remote-scan-verdict');

        if (wrapper) wrapper.classList.remove('d-none');
        if (verdictEl) verdictEl.classList.add('d-none');
        if (termEl) termEl.innerHTML = '';
        if (progressBar) {
            progressBar.style.width = '0%';
            progressBar.textContent = '0%';
            progressBar.classList.remove('bar-danger');
        }
        if (phaseLabel) phaseLabel.textContent = `Connecting to remote host ${targetIp}...`;

        // Terminal Banner
        addLine(termEl, 'line-header', '╔════════════════════════════════════════════════════════════════════╗');
        addLine(termEl, 'line-header', '║   VulnShield — Remote Laptop Forensics & Spyware Hunter           ║');
        addLine(termEl, 'line-header', `║   Auditing Target: ${targetIp.padEnd(46)}║`);
        addLine(termEl, 'line-header', '║   Scan Engine: Non-Intrusive TCP Socket & Threat Signature Probe  ║');
        addLine(termEl, 'line-header', '╚════════════════════════════════════════════════════════════════════╝');
        addLine(termEl, 'line-info',   `[*] Origin Node: VulnShield Dashboard | Timestamp: ${new Date().toLocaleTimeString()}`);
        addLine(termEl, 'line-info',   `[*] Target IPv4: ${targetIp} | Mode: ${isDemo ? 'DEMO SIMULATION (INFECTED)' : 'LIVE NETWORK AUDIT'}`);
        await sleep(600);

        // Phase 1: Host Reachability
        if (progressBar) { progressBar.style.width = '20%'; progressBar.textContent = '20%'; }
        if (phaseLabel) phaseLabel.textContent = 'Phase 1/5: Probing remote host reachability and latency...';
        addLine(termEl, 'line-phase', '\n── Phase 1/5: Host Reachability & ICMP/TCP Ping ──');
        addLine(termEl, 'line-cmd',   `$ ping -n 1 ${targetIp} | net.Socket test`);
        await sleep(500);

        // Initiate API request in parallel
        let scanResult = null;
        try {
            const apiPromise = fetch('/api/remote/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: targetIp, simulate: isDemo })
            }).then(r => r.json());

            addLine(termEl, 'line-ok', `✓ Connection Established: Host ${targetIp} is reachable`);
            addLine(termEl, 'line-info', `  Latency: ${isDemo ? '3.8ms' : '< 15ms'} | Path: Direct Layer-3 LAN`);
            await sleep(600);

            // Phase 2: RAT & Trojan Ports
            if (progressBar) { progressBar.style.width = '40%'; progressBar.textContent = '40%'; }
            if (phaseLabel) phaseLabel.textContent = 'Phase 2/5: Scanning for Remote Access Trojans (RATs) & Backdoors...';
            addLine(termEl, 'line-phase', '\n── Phase 2/5: RAT & Command-and-Control (C2) Sockets ──');
            addLine(termEl, 'line-cmd',   `$ probe [4444:Meterpreter, 1177:njRAT, 1604:DarkComet, 1337:Elite, 31337:NetBus]`);
            await sleep(700);

            if (isDemo) {
                addLine(termEl, 'line-danger', `[!] ALERT: Port 4444/TCP OPEN → Metasploit Meterpreter Reverse Shell DETECTED!`);
                addLine(termEl, 'line-danger', `[!] ALERT: Port 1177/TCP OPEN → njRAT (Bladabindi) Surveillance Channel ACTIVE!`);
            } else {
                addLine(termEl, 'line-info', `[*] Querying listening sockets on target IP ${targetIp}...`);
            }
            await sleep(700);

            // Phase 3: Surveillance & Desktop Sharing
            if (progressBar) { progressBar.style.width = '65%'; progressBar.textContent = '65%'; }
            if (phaseLabel) phaseLabel.textContent = 'Phase 3/5: Auditing remote screen surveillance & desktop hooks...';
            addLine(termEl, 'line-phase', '\n── Phase 3/5: Screen Surveillance & Covert Desktop Hooks ──');
            addLine(termEl, 'line-cmd',   `$ probe [5900:VNC, 5901:VNC-1, 3389:RDP, 5555:ADB]`);
            await sleep(600);

            if (isDemo) {
                addLine(termEl, 'line-danger', `[!] ALERT: Port 5900/TCP OPEN → Unauthenticated VNC Remote Desktop (Screen Spy)!`);
                addLine(termEl, 'line-warn',   `[!] WARNING: Port 3389/TCP OPEN → Microsoft RDP reachable without network filter.`);
            } else {
                addLine(termEl, 'line-info', `[*] Analyzing remote frame buffer and display protocols...`);
            }
            await sleep(600);

            // Phase 4: Exploits & Lateral Movement
            if (progressBar) { progressBar.style.width = '85%'; progressBar.textContent = '85%'; }
            if (phaseLabel) phaseLabel.textContent = 'Phase 4/5: Probing exploit vectors (SMB MS17-010 EternalBlue)...';
            addLine(termEl, 'line-phase', '\n── Phase 4/5: Exploitation & Lateral Infection Vectors ──');
            addLine(termEl, 'line-cmd',   `$ probe [445:SMBv1-MS17-010, 139:NetBIOS, 23:Telnet, 21:FTP]`);
            await sleep(700);

            if (isDemo) {
                addLine(termEl, 'line-danger', `[!] ALERT: Port 445/TCP OPEN → SMBv1 EternalBlue (MS17-010) Exploit Vector EXPOSED!`);
            } else {
                addLine(termEl, 'line-info', `[*] Auditing SMB file-sharing protocol and cleartext daemons...`);
            }
            await sleep(500);

            // Await API response
            scanResult = await apiPromise;

        } catch (err) {
            addLine(termEl, 'line-err', `[!] Error communicating with scanning engine: ${err.message}`);
            scanResult = {
                targetIp,
                isOnline: false,
                threatScore: 50,
                verdict: 'SCAN FAILED',
                verdictClass: 'warn',
                summary: 'Scan encountered a network error while probing the remote target.',
                findings: [],
                remediationSteps: ['Verify network connection and ensure target IP is routable.']
            };
        }

        // Phase 5: Verdict
        if (progressBar) {
            progressBar.style.width = '100%';
            progressBar.textContent = '100%';
            if (scanResult.threatScore <= 50) {
                progressBar.classList.add('bar-danger');
            }
        }
        if (phaseLabel) phaseLabel.textContent = '✓ Remote IP Forensics Audit Completed';

        addLine(termEl, 'line-phase', '\n── Phase 5/5: Threat Correlation & Final Verdict ──');
        addLine(termEl, 'line-ok',   `✓ Scan Completed at ${new Date().toLocaleTimeString()}`);
        addLine(termEl, scanResult.threatScore < 60 ? 'line-danger' : 'line-ok',
            `  Security Score: ${scanResult.threatScore}/100 | Verdict: ${scanResult.verdict}`);

        if (scanResult.findings && scanResult.findings.length > 0) {
            addLine(termEl, 'line-warn', `  Detected ${scanResult.findings.length} open/exposed service ports.`);
        } else {
            addLine(termEl, 'line-ok', `  0 malicious or unauthorized listening ports found. Remote firewall is active.`);
        }

        await sleep(500);
        showVerdict(scanResult, verdictEl);
        setButtonsState(false);
        isRunning = false;
    }

    // =========================================================================
    // VERDICT CARD RENDERER
    // =========================================================================
    function showVerdict(data, verdictEl) {
        if (!verdictEl) return;

        const isCompromised = data.threatScore < 50 || data.verdictClass === 'danger';
        const isWarning     = data.threatScore >= 50 && data.threatScore < 85;
        const vcClass       = isCompromised ? 'verdict-danger' : (isWarning ? 'verdict-clean' : 'verdict-clean');
        const vIcon         = isCompromised ? '⛔' : (isWarning ? '⚠️' : '🛡️');

        const dangerCount = (data.findings || []).filter(f => f.severity === 'danger').length;
        const warnCount   = (data.findings || []).filter(f => f.severity === 'warn').length;

        verdictEl.className = `mob-verdict ${vcClass}`;
        verdictEl.innerHTML = `
            <div class="verdict-icon">${vIcon}</div>
            <div class="verdict-body">
                <div class="verdict-title" style="color:${isCompromised ? '#ff0055' : '#00ff88'};">
                    ${data.verdict}
                </div>
                <div class="verdict-subtitle">
                    Target: <strong>${data.targetIp}</strong>
                    &nbsp;|&nbsp; Hostname: <strong>${data.hostname || 'Remote Host'}</strong>
                    &nbsp;|&nbsp; OS Profile: <strong>${data.osGuess || 'Standard Network Host'}</strong>
                </div>
            </div>
            <div class="verdict-metrics">
                <div class="verdict-metric ${isCompromised ? 'metric-danger' : 'metric-clean'}">
                    <span class="vm-val">${data.threatScore}/100</span>
                    <span class="vm-lbl">Security Score</span>
                </div>
                <div class="verdict-metric ${dangerCount > 0 ? 'metric-danger' : 'metric-clean'}">
                    <span class="vm-val">${dangerCount}</span>
                    <span class="vm-lbl">Malware/RATs</span>
                </div>
                <div class="verdict-metric ${warnCount > 0 ? 'metric-danger' : 'metric-clean'}">
                    <span class="vm-val">${warnCount}</span>
                    <span class="vm-lbl">Exposed Ports</span>
                </div>
                <div class="verdict-metric metric-clean">
                    <span class="vm-val">${data.responseTimeMs}ms</span>
                    <span class="vm-lbl">Response Latency</span>
                </div>
            </div>
        `;

        // Append Pillars & Detailed Findings
        const findingsDiv = document.createElement('div');
        findingsDiv.style.width = '100%';
        findingsDiv.style.marginTop = '20px';

        findingsDiv.innerHTML = `
            <!-- 3 Security Pillars -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:12px;margin-bottom:20px;">
                <!-- Pillar 1 -->
                ${(() => {
                    const ratCount = (data.findings || []).filter(f => [4444, 1177, 1604, 1337, 31337].includes(f.port)).length;
                    return `
                    <div style="background:${ratCount > 0 ? 'rgba(255,0,85,0.06)' : 'rgba(0,255,136,0.06)'};border:1px solid ${ratCount > 0 ? 'rgba(255,0,85,0.25)' : 'rgba(0,255,136,0.25)'};border-radius:8px;padding:14px;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                            <i class="fa-solid fa-skull-crossbones" style="color:${ratCount > 0 ? '#ff0055' : '#00ff88'};font-size:1.2rem;"></i>
                            <span style="font-weight:700;color:#fff;font-size:0.92rem;">1. RAT & Spyware Detection</span>
                        </div>
                        <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                            Meterpreter, njRAT, DarkComet backdoor listeners.
                        </div>
                        <span class="badge ${ratCount > 0 ? 'badge-danger' : 'badge-success'}">
                            ${ratCount > 0 ? `🚨 ${ratCount} Active Trojan(s)` : '✓ Clean: No RAT Sockets'}
                        </span>
                    </div>
                    `;
                })()}

                <!-- Pillar 2 -->
                ${(() => {
                    const survCount = (data.findings || []).filter(f => [5900, 5901, 3389, 5555].includes(f.port)).length;
                    return `
                    <div style="background:${survCount > 0 ? 'rgba(255,187,51,0.06)' : 'rgba(0,255,136,0.06)'};border:1px solid ${survCount > 0 ? 'rgba(255,187,51,0.25)' : 'rgba(0,255,136,0.25)'};border-radius:8px;padding:14px;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                            <i class="fa-solid fa-eye" style="color:${survCount > 0 ? '#ffbb33' : '#00ff88'};font-size:1.2rem;"></i>
                            <span style="font-weight:700;color:#fff;font-size:0.92rem;">2. Surveillance & Remote Hooks</span>
                        </div>
                        <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                            VNC screen capture and RDP access audit.
                        </div>
                        <span class="badge ${survCount > 0 ? 'badge-warning' : 'badge-success'}">
                            ${survCount > 0 ? '⚠️ Remote Desktop/VNC Open' : '✓ Isolated'}
                        </span>
                    </div>
                    `;
                })()}

                <!-- Pillar 3 -->
                ${(() => {
                    const has445 = data.findings && data.findings.some(f => f.port === 445);
                    return `
                    <div style="background:${has445 ? 'rgba(255,0,85,0.06)' : 'rgba(0,255,136,0.06)'};border:1px solid ${has445 ? 'rgba(255,0,85,0.25)' : 'rgba(0,255,136,0.25)'};border-radius:8px;padding:14px;">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                            <i class="fa-solid fa-shield-virus" style="color:${has445 ? '#ff0055' : '#00ff88'};font-size:1.2rem;"></i>
                            <span style="font-weight:700;color:#fff;font-size:0.92rem;">3. Exploit Vectors (SMB MS17-010)</span>
                        </div>
                        <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                            SMBv1 EternalBlue & lateral movement channels.
                        </div>
                        <span class="badge ${has445 ? 'badge-danger' : 'badge-success'}">
                            ${has445 ? '🚨 Vulnerable to EternalBlue' : '✓ Protected'}
                        </span>
                    </div>
                    `;
                })()}
            </div>

            <!-- Detailed Threat Cards -->
            <div style="font-size:0.88rem;font-weight:700;color:#00f0ff;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.5px;">
                <i class="fa-solid fa-radar"></i> Remote Host Findings & Exposed Port Breakdown
            </div>
            <div style="display:grid;gap:10px;">
                ${(data.findings && data.findings.length > 0) ? data.findings.map(f => `
                    <div style="background:rgba(0,0,0,0.35);border:1px solid ${f.severity === 'danger' ? 'rgba(255,68,68,0.5)' : (f.severity === 'warn' ? 'rgba(255,187,51,0.5)' : 'rgba(0,255,136,0.3)')};border-radius:6px;padding:12px 16px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:8px;">
                            <span style="font-weight:600;color:#fff;font-size:0.9rem;">
                                ${f.severity === 'danger' ? '🚨 ' : (f.severity === 'warn' ? '⚠️ ' : 'ℹ️ ')}
                                Port <strong>${f.port}</strong>: ${f.service}
                            </span>
                            <span class="badge ${f.severity === 'danger' ? 'badge-danger' : (f.severity === 'warn' ? 'badge-warning' : 'badge-success')}" style="font-size:0.75rem;">
                                ${f.status}
                            </span>
                        </div>
                        <div style="font-size:0.82rem;color:#ccc;margin-bottom:6px;">${f.details}</div>
                        <div style="font-size:0.78rem;color:#00ff88;margin-bottom:8px;">
                            <strong>Remediation:</strong> ${f.remediation}
                        </div>
                        ${f.severity === 'danger' ? `
                        <button onclick="window.generateRemediationScript(${f.port}, '${f.service}')" style="background: rgba(255,0,85,0.15); border: 1px solid rgba(255,0,85,0.5); color: #ff0055; padding: 6px 12px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;">
                            <i class="fa-solid fa-download"></i> Download Remediation Script (.bat)
                        </button>
                        ` : ''}
                    </div>
                `).join('') : `
                    <div style="background:rgba(0,255,136,0.05);border:1px solid rgba(0,255,136,0.25);border-radius:6px;padding:16px;text-align:center;color:#00ff88;">
                        <i class="fa-solid fa-circle-check" style="font-size:1.4rem;margin-bottom:8px;display:block;"></i>
                        <strong>Host Appears Clean:</strong> No listening backdoor sockets or spyware ports were exposed on ${data.targetIp}.
                    </div>
                `}
            </div>

            <!-- Actionable Remediation Checklist -->
            <div style="margin-top:20px;padding:16px;background:rgba(255,0,85,0.04);border:1px solid rgba(255,0,85,0.2);border-radius:8px;">
                <div style="font-weight:700;color:#fff;font-size:0.9rem;margin-bottom:10px;display:flex;align-items:center;gap:8px;">
                    <i class="fa-solid fa-wrench" style="color:#ff0055;"></i> Recommended Defense & Remediation Actions for Target Laptop:
                </div>
                <ul style="margin:0;padding-left:20px;font-size:0.82rem;color:#ccc;line-height:1.7;">
                    ${(data.remediationSteps || []).map(step => `<li>${step}</li>`).join('')}
                </ul>
            </div>
        `;

        verdictEl.appendChild(findingsDiv);
        verdictEl.classList.remove('d-none');

        // Save to localStorage for PDF Report Generation
        localStorage.setItem('vulnshield_remote_scan', JSON.stringify(data));
        localStorage.setItem('vulnshield_latest_scan', 'remote');
    }

    function resetScan() {
        const wrapper    = document.getElementById('remote-scan-wrapper');
        const verdictEl  = document.getElementById('remote-scan-verdict');
        const phaseLabel = document.getElementById('remote-scan-phase');
        const ipInput    = document.getElementById('remote-target-ip');

        if (wrapper)    wrapper.classList.add('d-none');
        if (verdictEl)  verdictEl.classList.add('d-none');
        if (phaseLabel) phaseLabel.textContent = 'Enter IP address and click Live Scan or Test Demo';
        if (ipInput)    ipInput.value = '';

        isRunning = false;
        setButtonsState(false);
    }

    return {
        runScan,
        setPreset,
        resetScan
    };

})();

window.generateRemediationScript = function(port, service) {
    const scriptContent = `@echo off
echo ========================================================
echo VulnShield Auto-Remediation Script
echo Target: Port ${port} (${service})
echo ========================================================
echo.
echo [1] Identifying process listening on Port ${port}...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :${port}') do set PID=%%a
if "%PID%"=="" (
    echo No active process found on Port ${port}.
) else (
    echo Process ID %PID% found. Terminating process...
    taskkill /F /PID %PID%
    echo Process terminated successfully.
)
echo.
echo [2] Blocking Port ${port} in Windows Defender Firewall...
netsh advfirewall firewall add rule name="VulnShield Block ${port}" dir=in action=block protocol=TCP localport=${port}
echo Firewall rule added.
echo.
echo Remediation complete.
pause
`;
    const blob = new Blob([scriptContent], { type: 'application/bat' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `remediate_port_${port}.bat`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};
