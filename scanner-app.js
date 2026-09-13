/* ===========================================================================
   VulnShield - Frontend App Scanner (Client-Side Simulation)
   =========================================================================== */

const AppScanner = {
    scan: async function (filename, content) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const findings = [];
                const code = content.toLowerCase();

                if (filename === 'AndroidManifest.xml') {
                    if (code.includes('android:debuggable="true"')) {
                        findings.push({ id: 'M3-01', title: 'Android App Debuggable in Production', severity: 'high', desc: 'android:debuggable="true" is set. Attackers can attach a debugger and extract sensitive data or bypass checks.', vulnType: 'Mobile App Misconfiguration' });
                    }
                    if (code.includes('android:usescleartexttraffic="true"')) {
                        findings.push({ id: 'M3-02', title: 'Cleartext Traffic Enabled', severity: 'critical', desc: 'The app allows non-HTTPS traffic, exposing data to Man-In-The-Middle (MITM) network attacks.', vulnType: 'Insecure Network Communication' });
                    }
                } else if (filename === '.env') {
                    if (code.includes('password') || code.includes('secret') || code.includes('key')) {
                        findings.push({ id: 'ENV-01', title: 'Hardcoded Secrets Exposed', severity: 'critical', desc: 'AWS Keys, Database Passwords, or JWT secrets found in plaintext environment file.', vulnType: 'Sensitive Data Exposure' });
                    }
                } else if (filename === 'package.json') {
                    if (code.includes('preinstall') || code.includes('postinstall') || code.includes('curl')) {
                        findings.push({ id: 'PKG-01', title: 'Suspicious Install Scripts', severity: 'high', desc: 'Found preinstall/postinstall scripts triggering external bash scripts. This is a common supply chain attack pattern.', vulnType: 'Supply Chain Risk' });
                    }
                }

                if (findings.length === 0) {
                    findings.push({ id: 'SEC-OK', title: 'No Critical Vulnerabilities Found', severity: 'low', desc: 'Static analysis completed successfully without finding any standard known vulnerability patterns.', vulnType: 'Code Audit' });
                }
                
                resolve(findings);
            }, 1000);
        });
    }
};

// Export for possible external use (e.g., testing)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AppScanner;
}
