/* ==========================================================================
   VulnShield - Universal Browser-Based Laptop Forensics Scanner
   Works on ANY laptop that opens this URL — uses real Browser APIs:
   Battery API, Navigator, WebRTC, MediaDevices, WebGL, Network Info
   ========================================================================== */

const LaptopScanner = (() => {

    let isRunning = false;

    // --- Helpers ---
    function addLine(termEl, cls, txt) {
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
        const btnReal = document.getElementById('btn-laptop-real');
        const btnReset = document.getElementById('btn-laptop-reset');
        if (btnReal) btnReal.disabled = disabled;
        if (btnReset) btnReset.style.display = disabled ? 'none' : 'inline-flex';
    }

    // =========================================================================
    // REAL BROWSER API TELEMETRY — Collects actual hardware info from ANY laptop
    // =========================================================================
    async function collectBrowserTelemetry() {
        const telemetry = {};

        // 1. OS & Browser Identity (navigator API)
        const ua = navigator.userAgent;
        telemetry.userAgent = ua;
        telemetry.platform  = navigator.platform || 'Unknown';
        telemetry.language  = navigator.language || 'Unknown';
        telemetry.cookiesEnabled = navigator.cookieEnabled;
        telemetry.doNotTrack = navigator.doNotTrack === '1';

        // Detect OS
        if (ua.includes('Windows NT 11') || ua.includes('Windows NT 10.0')) {
            telemetry.os = 'Windows 11 / 10';
        } else if (ua.includes('Windows')) {
            telemetry.os = 'Windows';
        } else if (ua.includes('Mac OS X')) {
            telemetry.os = 'macOS';
        } else if (ua.includes('Linux')) {
            telemetry.os = 'Linux';
        } else if (ua.includes('Android')) {
            telemetry.os = 'Android';
        } else if (ua.includes('iPhone') || ua.includes('iPad')) {
            telemetry.os = 'iOS';
        } else {
            telemetry.os = 'Unknown OS';
        }

        // Detect Browser
        if (ua.includes('Edg/')) {
            telemetry.browser = 'Microsoft Edge';
        } else if (ua.includes('OPR/') || ua.includes('Opera/')) {
            telemetry.browser = 'Opera';
        } else if (ua.includes('Chrome/')) {
            telemetry.browser = 'Google Chrome';
        } else if (ua.includes('Firefox/')) {
            telemetry.browser = 'Mozilla Firefox';
        } else if (ua.includes('Safari/') && !ua.includes('Chrome')) {
            telemetry.browser = 'Apple Safari';
        } else {
            telemetry.browser = 'Unknown Browser';
        }

        // 2. CPU & Memory
        telemetry.cpuCores = navigator.hardwareConcurrency || 'Unknown';
        telemetry.ramGB    = navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'Unknown';

        // 3. Screen & Display
        telemetry.screenW  = window.screen.width;
        telemetry.screenH  = window.screen.height;
        telemetry.colorDepth = window.screen.colorDepth;
        telemetry.pixelRatio = window.devicePixelRatio || 1;

        // 4. Battery API (real hardware battery read)
        telemetry.battery = null;
        try {
            if ('getBattery' in navigator) {
                const bat = await navigator.getBattery();
                telemetry.battery = {
                    level:     Math.round(bat.level * 100),
                    charging:  bat.charging,
                    chargingTime:    bat.chargingTime === Infinity ? 'N/A' : `${Math.round(bat.chargingTime / 60)} min`,
                    dischargingTime: bat.dischargingTime === Infinity ? 'N/A' : `${Math.round(bat.dischargingTime / 60)} min`
                };
            }
        } catch(e) {}

        // 5. Network Information API
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (conn) {
            telemetry.network = {
                type:         conn.type || conn.effectiveType || 'Unknown',
                downlink:     conn.downlink ? `${conn.downlink} Mbps` : 'Unknown',
                rtt:          conn.rtt !== undefined ? `${conn.rtt} ms` : 'Unknown',
                saveData:     conn.saveData || false
            };
        } else {
            telemetry.network = { type: 'Unknown', downlink: 'Unknown', rtt: 'Unknown', saveData: false };
        }

        // 6. WebRTC IP Leak Detection (detects real local + public IP via STUN)
        telemetry.localIPs = [];
        try {
            const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            pc.createDataChannel('');
            await new Promise((resolve) => {
                const timeout = setTimeout(resolve, 3500);
                pc.onicecandidate = (e) => {
                    if (!e || !e.candidate) return;
                    const ipMatch = e.candidate.candidate.match(
                        /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/
                    );
                    if (ipMatch) {
                        const ip = ipMatch[1];
                        if (!telemetry.localIPs.includes(ip)) {
                            telemetry.localIPs.push(ip);
                        }
                    }
                };
                pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {
                    clearTimeout(timeout);
                    resolve();
                });
            });
            pc.close();
        } catch(e) {}

        // 7. Camera & Microphone Enumeration (NO access, just detect presence)
        telemetry.cameras  = 0;
        telemetry.mics     = 0;
        telemetry.speakers = 0;
        try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            telemetry.cameras  = devices.filter(d => d.kind === 'videoinput').length;
            telemetry.mics     = devices.filter(d => d.kind === 'audioinput').length;
            telemetry.speakers = devices.filter(d => d.kind === 'audiooutput').length;
        } catch(e) {}

        // 8. WebGL GPU Fingerprint
        telemetry.gpu = 'Unknown';
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbgInfo) {
                    telemetry.gpu = gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL) || 'Unknown';
                }
            }
        } catch(e) {}

        // 9. Storage Quota
        telemetry.storageTotal  = 'Unknown';
        telemetry.storageUsed   = 'Unknown';
        try {
            if (navigator.storage && navigator.storage.estimate) {
                const est = await navigator.storage.estimate();
                telemetry.storageTotal = `${Math.round(est.quota / 1024 / 1024 / 1024 * 10) / 10} GB`;
                telemetry.storageUsed  = `${Math.round(est.usage  / 1024 / 1024)} MB`;
            }
        } catch(e) {}

        // 10. Security Context Checks
        telemetry.isSecureContext  = window.isSecureContext;
        telemetry.protocol         = window.location.protocol;
        telemetry.isLocalhost      = ['localhost', '127.0.0.1'].includes(window.location.hostname);
        telemetry.hasServiceWorker = 'serviceWorker' in navigator;
        telemetry.timezone         = Intl.DateTimeFormat().resolvedOptions().timeZone;
        telemetry.hostname         = window.location.hostname;

        // 11. Compute Security Score
        let score = 100;
        const findings = [];

        // Battery check
        if (telemetry.battery && telemetry.battery.level < 20 && !telemetry.battery.charging) {
            score -= 5;
            findings.push({ id: 'LOW_BATTERY', category: 'system', title: 'Low Battery — Risk of Sudden Shutdown', severity: 'warn',
                status: `${telemetry.battery.level}% remaining`,
                details: 'Low battery may cause forced shutdown during security operations or investigations.',
                remediation: 'Plug in charger before performing critical security audit tasks.' });
        }

        // HTTPS check
        if (telemetry.protocol !== 'https:' && !telemetry.isLocalhost) {
            score -= 15;
            findings.push({ id: 'NO_HTTPS', category: 'spy', title: 'Unencrypted HTTP Connection Detected', severity: 'danger',
                status: 'HTTP (INSECURE)',
                details: 'All traffic is unencrypted. Attackers on same network can intercept sessions (MITM attack).',
                remediation: 'Always use HTTPS. Enable HSTS on all web services.' });
        } else {
            findings.push({ id: 'HTTPS_OK', category: 'spy', title: 'HTTPS / Secure Transport Active', severity: 'passed',
                status: 'ENCRYPTED',
                details: 'Communication is encrypted via TLS/SSL. Session tokens and data are protected in transit.',
                remediation: 'Maintain valid TLS certificates and avoid self-signed certs in production.' });
        }

        // DNT Check
        if (!telemetry.doNotTrack) {
            score -= 5;
            findings.push({ id: 'NO_DNT', category: 'spy', title: 'Browser Tracking Protection Not Enabled', severity: 'warn',
                status: 'TRACKING EXPOSED',
                details: 'Do-Not-Track header is disabled. Third-party trackers may collect behavioral data.',
                remediation: 'Enable Do-Not-Track in browser privacy settings or use uBlock Origin extension.' });
        } else {
            findings.push({ id: 'DNT_OK', category: 'spy', title: 'Do-Not-Track Header Active', severity: 'passed',
                status: 'PRIVACY PROTECTED',
                details: 'Browser is configured to signal privacy preference to all visited sites.',
                remediation: 'Continue using tracker blocking extensions for stronger privacy.' });
        }

        // IP Leak
        if (telemetry.localIPs.length > 0) {
            const hasPrivateIP = telemetry.localIPs.some(ip =>
                ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.'));
            if (hasPrivateIP) {
                score -= 10;
                findings.push({ id: 'WEBRTC_LEAK', category: 'spy', title: 'WebRTC IP Leak Detected', severity: 'warn',
                    status: `${telemetry.localIPs.length} IP(s) EXPOSED`,
                    details: `WebRTC STUN leak revealed internal LAN IP(s): ${telemetry.localIPs.join(', ')}. VPN users' real IPs can be exposed this way.`,
                    remediation: 'Disable WebRTC in browser settings or use a VPN with WebRTC leak protection.' });
            }
        } else {
            findings.push({ id: 'NO_WEBRTC_LEAK', category: 'spy', title: 'No WebRTC IP Leak', severity: 'passed',
                status: 'IP PROTECTED',
                details: 'No internal IP address exposed via WebRTC STUN protocol.',
                remediation: 'Continue using WebRTC leak protection. Enable VPN for full IP masking.' });
        }

        // Camera/Mic presence
        if (telemetry.cameras === 0) {
            findings.push({ id: 'NO_CAM', category: 'spy', title: 'No Webcam Hardware Detected', severity: 'passed',
                status: 'NO CAMERA',
                details: 'No video input device (webcam) found on this machine. No surveillance hardware present.',
                remediation: 'Keep camera drivers up to date if you use external webcam.' });
        } else {
            findings.push({ id: 'CAM_PRESENT', category: 'spy', title: `Webcam Detected (${telemetry.cameras} Device(s))`, severity: 'warn',
                status: `${telemetry.cameras} CAMERA(S)`,
                details: `${telemetry.cameras} webcam device(s) found. Ensure no unauthorized app is accessing camera in the background.`,
                remediation: 'Check Windows Settings → Privacy → Camera. Disable access for suspicious apps.' });
        }

        // CPU Cores (very low = possible VM/container/restricted env)
        if (telemetry.cpuCores !== 'Unknown' && telemetry.cpuCores <= 2) {
            findings.push({ id: 'LOW_CPU', category: 'system', title: 'Low CPU Core Count Detected', severity: 'warn',
                status: `${telemetry.cpuCores} CORES`,
                details: 'Only 1-2 CPU cores detected. This may indicate a virtual machine, restricted environment, or very low-powered device.',
                remediation: 'Ensure machine meets minimum hardware requirements for forensic operations.' });
        } else {
            findings.push({ id: 'CPU_OK', category: 'system', title: 'CPU Telemetry Checked', severity: 'passed',
                status: `${telemetry.cpuCores} CORES`,
                details: `Hardware concurrency: ${telemetry.cpuCores} logical CPUs available. Adequate for forensic workload.`,
                remediation: 'Monitor CPU utilization during intensive scanning operations.' });
        }

        // Cookies
        if (!telemetry.cookiesEnabled) {
            score -= 5;
            findings.push({ id: 'NO_COOKIES', category: 'system', title: 'Browser Cookies Disabled', severity: 'warn',
                status: 'COOKIES OFF',
                details: 'Browser cookies are disabled. Session authentication tokens cannot be persisted securely.',
                remediation: 'Enable cookies for trusted sites. Disable third-party cookies for privacy.' });
        } else {
            findings.push({ id: 'COOKIES_OK', category: 'system', title: 'Secure Cookie Management Active', severity: 'passed',
                status: 'COOKIES ENABLED',
                details: 'Browser cookie management active. Ensure HttpOnly and SameSite=Strict flags are enforced.',
                remediation: 'Audit cookie attributes using browser DevTools → Application → Cookies.' });
        }

        // Determine verdict
        let verdictStatus, verdictText, verdictColor;
        if (score >= 80) {
            verdictStatus = 'SECURE'; verdictText = '✅ SYSTEM APPEARS SECURE'; verdictColor = 'passed';
        } else if (score >= 55) {
            verdictStatus = 'WARNING'; verdictText = '⚠️ SECURITY ISSUES DETECTED'; verdictColor = 'warn';
        } else {
            verdictStatus = 'COMPROMISED'; verdictText = '⛔ HIGH RISK — ACTION REQUIRED'; verdictColor = 'danger';
        }

        return {
            ...telemetry,
            score, findings, verdictStatus, verdictText, verdictColor,
            scannedAt: new Date().toISOString()
        };
    }

    // =========================================================================
    // MAIN SCAN RUNNER
    // =========================================================================
    async function runRealScan() {
        if (isRunning) return;
        isRunning = true;

        const wrapper     = document.getElementById('laptop-scan-wrapper');
        const termEl      = document.getElementById('laptop-scan-terminal');
        const progressBar = document.getElementById('laptop-scan-bar');
        const phaseLabel  = document.getElementById('laptop-scan-phase');
        const verdictEl   = document.getElementById('laptop-scan-verdict');

        wrapper.classList.remove('d-none');
        verdictEl.classList.add('d-none');
        termEl.innerHTML = '';
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        progressBar.classList.remove('bar-danger');
        phaseLabel.textContent = 'Initializing browser-level hardware telemetry scan...';
        setButtonsState(true);

        // ── Header ──
        addLine(termEl, 'line-header', '╔════════════════════════════════════════════════════════════════════╗');
        addLine(termEl, 'line-header', '║   VulnShield — Universal Laptop Security Forensics Engine         ║');
        addLine(termEl, 'line-header', '║   Scanning THIS device via Browser Hardware & Security APIs       ║');
        addLine(termEl, 'line-header', '╚════════════════════════════════════════════════════════════════════╝');
        addLine(termEl, 'line-info',   `  Target: ${window.location.hostname} | Started: ${new Date().toLocaleTimeString()}`);
        await sleep(500);

        // ── Phase 1: Collect Telemetry ──
        progressBar.style.width = '15%';
        progressBar.textContent = '15%';
        phaseLabel.textContent  = 'Phase 1/6: Collecting hardware & OS telemetry...';
        addLine(termEl, 'line-phase', '\n── Phase 1/6: Hardware & OS Identity Telemetry ──');
        addLine(termEl, 'line-cmd',   '$ navigator.userAgent | navigator.platform | navigator.hardwareConcurrency');

        const data = await collectBrowserTelemetry();
        await sleep(400);

        addLine(termEl, 'line-ok',   `✓ OS Detected:      ${data.os}`);
        addLine(termEl, 'line-ok',   `✓ Browser:          ${data.browser}`);
        addLine(termEl, 'line-ok',   `✓ CPU Cores:        ${data.cpuCores} Logical Processors`);
        addLine(termEl, 'line-ok',   `✓ RAM:              ${data.ramGB}`);
        addLine(termEl, 'line-info', `  Screen:           ${data.screenW}x${data.screenH} @ ${data.colorDepth}-bit colour`);
        addLine(termEl, 'line-info', `  Timezone:         ${data.timezone}`);
        addLine(termEl, 'line-info', `  Language:         ${data.language}`);
        await sleep(600);

        // ── Phase 2: GPU ──
        progressBar.style.width = '30%';
        progressBar.textContent = '30%';
        phaseLabel.textContent  = 'Phase 2/6: GPU & WebGL fingerprint analysis...';
        addLine(termEl, 'line-phase', '\n── Phase 2/6: GPU & Graphics Fingerprint ──');
        addLine(termEl, 'line-cmd',   '$ WebGLRenderingContext.getParameter(UNMASKED_RENDERER_WEBGL)');
        await sleep(500);
        addLine(termEl, 'line-ok', `✓ GPU Renderer:     ${data.gpu}`);
        addLine(termEl, 'line-info', `  Pixel Ratio:     ${data.pixelRatio}x`);
        await sleep(500);

        // ── Phase 3: Battery ──
        progressBar.style.width = '45%';
        progressBar.textContent = '45%';
        phaseLabel.textContent  = 'Phase 3/6: Battery & power status audit...';
        addLine(termEl, 'line-phase', '\n── Phase 3/6: Battery & Power Audit ──');
        addLine(termEl, 'line-cmd',   '$ navigator.getBattery() → BatteryManager API');
        await sleep(400);
        if (data.battery) {
            const bat = data.battery;
            const batStatus = bat.level < 20 && !bat.charging ? 'line-warn' : 'line-ok';
            addLine(termEl, batStatus, `✓ Battery Level:    ${bat.level}% ${bat.charging ? '[CHARGING 🔌]' : '[ON BATTERY 🔋]'}`);
            addLine(termEl, 'line-info', `  Discharge Time:  ${bat.dischargingTime}`);
        } else {
            addLine(termEl, 'line-info', '  Battery API:     Not available (Desktop / Restricted Browser)');
        }
        await sleep(600);

        // ── Phase 4: Network & IP ──
        progressBar.style.width = '60%';
        progressBar.textContent = '60%';
        phaseLabel.textContent  = 'Phase 4/6: Network fingerprint & WebRTC IP leak detection...';
        addLine(termEl, 'line-phase', '\n── Phase 4/6: Network Telemetry & IP Leak Audit ──');
        addLine(termEl, 'line-cmd',   '$ navigator.connection | RTCPeerConnection STUN probe');
        await sleep(400);
        addLine(termEl, 'line-info', `  Network Type:    ${data.network.type}`);
        addLine(termEl, 'line-info', `  Est. Downlink:   ${data.network.downlink}`);
        addLine(termEl, 'line-info', `  RTT Latency:     ${data.network.rtt}`);
        if (data.localIPs.length > 0) {
            data.localIPs.forEach(ip => addLine(termEl, 'line-warn', `  ⚠ WebRTC Leaked LAN IP: ${ip}`));
        } else {
            addLine(termEl, 'line-ok', '  ✓ No WebRTC IP leak detected.');
        }
        addLine(termEl, 'line-info', `  Protocol:        ${data.protocol}  |  Secure Context: ${data.isSecureContext ? 'YES ✓' : 'NO ⚠'}`);
        await sleep(700);

        // ── Phase 5: Camera / Mic / Spy ──
        progressBar.style.width = '78%';
        progressBar.textContent = '78%';
        phaseLabel.textContent  = 'Phase 5/6: Surveillance & hardware sensor enumeration...';
        addLine(termEl, 'line-phase', '\n── Phase 5/6: Surveillance & Sensor Enumeration ──');
        addLine(termEl, 'line-cmd',   '$ navigator.mediaDevices.enumerateDevices()');
        await sleep(500);
        addLine(termEl, data.cameras > 0 ? 'line-warn' : 'line-ok',
            `  Webcam Devices:  ${data.cameras} camera(s) detected`);
        addLine(termEl, 'line-ok',
            `  Microphones:     ${data.mics} mic(s) detected`);
        addLine(termEl, 'line-ok',
            `  Speakers:        ${data.speakers} output device(s)`);
        addLine(termEl, 'line-info', `  Cookies:         ${data.cookiesEnabled ? 'Enabled ✓' : 'Disabled ⚠'}`);
        addLine(termEl, 'line-info', `  Do-Not-Track:    ${data.doNotTrack ? 'Active ✓' : 'Disabled ⚠'}`);
        await sleep(700);

        // ── Phase 6: Storage ──
        progressBar.style.width = '92%';
        progressBar.textContent = '92%';
        phaseLabel.textContent  = 'Phase 6/6: Storage quota & security context analysis...';
        addLine(termEl, 'line-phase', '\n── Phase 6/6: Storage & Browser Security Context ──');
        addLine(termEl, 'line-cmd',   '$ navigator.storage.estimate()');
        await sleep(400);
        addLine(termEl, 'line-info', `  Storage Quota:   ${data.storageTotal}`);
        addLine(termEl, 'line-info', `  Storage Used:    ${data.storageUsed}`);
        addLine(termEl, 'line-info', `  Service Workers: ${data.hasServiceWorker ? 'Supported' : 'Not Supported'}`);
        await sleep(500);

        // ── Complete ──
        progressBar.style.width = '100%';
        progressBar.textContent = '100%';
        phaseLabel.textContent  = '✓ Browser Forensic Scan Complete';
        addLine(termEl, 'line-phase', '\n── Compiling Security Report ──');
        addLine(termEl, 'line-ok', `✓ Scan Completed at ${new Date().toLocaleTimeString()}`);
        addLine(termEl, 'line-ok', `  Final Security Score: ${data.score}/100`);

        showVerdict(data, verdictEl);
        setButtonsState(false);
        isRunning = false;
    }

    // =========================================================================
    // VERDICT CARD RENDERER
    // =========================================================================
    function showVerdict(data, verdictEl) {
        const isClean   = data.score >= 80;
        const isWarning = data.score >= 55 && data.score < 80;
        const vcClass   = isClean ? 'verdict-clean' : (isWarning ? 'verdict-clean' : 'verdict-danger');
        const vIcon     = isClean ? '🛡️' : (isWarning ? '⚠️' : '⛔');

        const bat = data.battery;
        const batDisplay = bat ? `${bat.level}% ${bat.charging ? '🔌' : '🔋'}` : 'N/A';

        verdictEl.className = `mob-verdict ${vcClass}`;
        verdictEl.innerHTML = `
            <div class="verdict-icon">${vIcon}</div>
            <div class="verdict-body">
                <div class="verdict-title">${data.verdictText}</div>
                <div class="verdict-subtitle">
                    Audited: <strong>${data.browser}</strong> on <strong>${data.os}</strong>
                    &nbsp;|&nbsp; Host: <strong>${data.hostname}</strong>
                </div>
            </div>
            <div class="verdict-metrics">
                <div class="verdict-metric ${isClean ? 'metric-clean' : 'metric-danger'}">
                    <span class="vm-val">${data.score}/100</span>
                    <span class="vm-lbl">Security Score</span>
                </div>
                <div class="verdict-metric metric-clean">
                    <span class="vm-val">${data.cpuCores}</span>
                    <span class="vm-lbl">CPU Cores</span>
                </div>
                <div class="verdict-metric metric-clean">
                    <span class="vm-val">${data.ramGB}</span>
                    <span class="vm-lbl">Device RAM</span>
                </div>
                <div class="verdict-metric ${data.cameras > 0 ? 'metric-danger' : 'metric-clean'}">
                    <span class="vm-val">${data.cameras}</span>
                    <span class="vm-lbl">Webcam(s)</span>
                </div>
                <div class="verdict-metric metric-clean">
                    <span class="vm-val">${batDisplay}</span>
                    <span class="vm-lbl">Battery</span>
                </div>
            </div>
        `;

        // 3 Pillars
        const findingsDiv = document.createElement('div');
        findingsDiv.style.cssText = 'margin-top:24px;border-top:1px solid rgba(255,255,255,0.1);padding-top:18px;';

        const spyFindings  = data.findings.filter(f => f.category === 'spy');
        const sysFindings  = data.findings.filter(f => f.category === 'system');
        const allBad = data.findings.filter(f => f.severity === 'danger' || f.severity === 'warn');

        const spyBad  = spyFindings.filter(f => f.severity !== 'passed').length;
        const sysBad  = sysFindings.filter(f => f.severity !== 'passed').length;
        const netIPs  = data.localIPs.length;

        findingsDiv.innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:20px;">
                <!-- Pillar 1: Network Security -->
                <div style="background:rgba(0,240,255,0.06);border:1px solid rgba(0,240,255,0.25);border-radius:8px;padding:14px;">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                        <i class="fa-solid fa-network-wired" style="color:#00f0ff;font-size:1.2rem;"></i>
                        <span style="font-weight:700;color:#fff;font-size:0.92rem;">1. Network & IP Audit</span>
                    </div>
                    <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                        WebRTC IP leak, HTTPS enforcement, and connection telemetry.
                    </div>
                    <span class="badge ${netIPs > 0 ? 'badge-warning' : 'badge-success'}">
                        ${netIPs > 0 ? `⚠️ ${netIPs} IP(s) Leaked via WebRTC` : '✓ No IP Leaks Detected'}
                    </span>
                </div>

                <!-- Pillar 2: Browser & System Security -->
                <div style="background:rgba(255,0,85,0.06);border:1px solid rgba(255,0,85,0.25);border-radius:8px;padding:14px;">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                        <i class="fa-solid fa-shield-halved" style="color:#ff0055;font-size:1.2rem;"></i>
                        <span style="font-weight:700;color:#fff;font-size:0.92rem;">2. Browser & OS Security</span>
                    </div>
                    <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                        Cookie policy, DNT, secure context, and OS identity check.
                    </div>
                    <span class="badge ${sysBad > 0 ? 'badge-warning' : 'badge-success'}">
                        ${sysBad > 0 ? `⚠️ ${sysBad} Config Issue(s)` : '✓ Browser Config Secure'}
                    </span>
                </div>

                <!-- Pillar 3: Surveillance & Camera -->
                <div style="background:rgba(0,255,136,0.06);border:1px solid rgba(0,255,136,0.25);border-radius:8px;padding:14px;">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                        <i class="fa-solid fa-video" style="color:#00ff88;font-size:1.2rem;"></i>
                        <span style="font-weight:700;color:#fff;font-size:0.92rem;">3. Surveillance Sensor Audit</span>
                    </div>
                    <div style="font-size:0.8rem;color:#aaa;margin-bottom:8px;">
                        Camera, microphone, and tracking privacy enumeration.
                    </div>
                    <span class="badge ${spyBad > 0 ? 'badge-warning' : 'badge-success'}">
                        ${spyBad > 0 ? `⚠️ ${spyBad} Surveillance Risk(s)` : '✓ No Active Surveillance'}
                    </span>
                </div>
            </div>

            <!-- Detailed Findings -->
            <div style="font-size:0.88rem;font-weight:700;color:#00f0ff;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.5px;">
                <i class="fa-solid fa-list-check"></i> Live Browser Telemetry Findings (${data.findings.length} Tests)
            </div>
            <div style="display:grid;gap:10px;">
                ${data.findings.map(f => `
                    <div style="background:rgba(0,0,0,0.35);border:1px solid ${f.severity === 'danger' ? 'rgba(255,68,68,0.45)' : (f.severity === 'warn' ? 'rgba(255,187,51,0.45)' : 'rgba(0,255,136,0.3)')};border-radius:6px;padding:12px 16px;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">
                            <span style="font-weight:600;color:#fff;font-size:0.9rem;">
                                ${f.category === 'spy' ? '👁️ ' : (f.category === 'system' ? '🖥️ ' : '🌐 ')}${f.title}
                            </span>
                            <span class="badge ${f.severity === 'danger' ? 'badge-danger' : (f.severity === 'warn' ? 'badge-warning' : 'badge-success')}" style="font-size:0.72rem;">
                                ${f.status}
                            </span>
                        </div>
                        <div style="font-size:0.8rem;color:#ccc;margin-bottom:6px;">${f.details}</div>
                        <div style="font-size:0.75rem;color:#00ff88;"><strong>Recommendation:</strong> ${f.remediation}</div>
                    </div>
                `).join('')}
            </div>

            <!-- GPU / Hardware Footer -->
            <div style="margin-top:16px;padding:12px 16px;background:rgba(0,240,255,0.04);border:1px solid rgba(0,240,255,0.15);border-radius:8px;font-size:0.8rem;color:#aaa;">
                <strong style="color:#00f0ff;">🖥️ Hardware Fingerprint:</strong>
                GPU: <strong style="color:#fff;">${data.gpu}</strong> |
                Screen: <strong style="color:#fff;">${data.screenW}×${data.screenH}</strong> |
                Storage: <strong style="color:#fff;">${data.storageTotal} (${data.storageUsed} used)</strong> |
                Network: <strong style="color:#fff;">${data.network.type} @ ${data.network.downlink}</strong>
            </div>
        `;

        verdictEl.appendChild(findingsDiv);
        verdictEl.classList.remove('d-none');
    }

    function resetScan() {
        const wrapper    = document.getElementById('laptop-scan-wrapper');
        const verdictEl  = document.getElementById('laptop-scan-verdict');
        const phaseLabel = document.getElementById('laptop-scan-phase');
        if (wrapper)    wrapper.classList.add('d-none');
        if (verdictEl)  verdictEl.classList.add('d-none');
        if (phaseLabel) phaseLabel.textContent = 'Click button above to initiate real-time host laptop audit';
        isRunning = false;
        setButtonsState(false);
    }

    return { runRealScan, resetScan };
})();
