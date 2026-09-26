/**
 * VulnShield - Hollywood Hacker Premium UI
 * Adds Matrix background, neon effects, and global threat map animations.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Matrix Background
    const canvas = document.createElement('canvas');
    canvas.id = 'matrix-canvas';
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100vw';
    canvas.style.height = '100vh';
    canvas.style.zIndex = '-10';
    canvas.style.opacity = '0.4';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%""\'#&_(),.;:?!\\|{}<>[]^~';
    const fontSize = 16;
    const columns = canvas.width / fontSize;
    const drops = [];
    for (let x = 0; x < columns; x++) drops[x] = 1;

    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 10, 5, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00ff66'; // Matrix Green
        ctx.font = fontSize + 'px "Share Tech Mono", monospace';
        
        for (let i = 0; i < drops.length; i++) {
            const text = letters.charAt(Math.floor(Math.random() * letters.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    // Animate matrix fast when "scanning"
    let matrixInterval = setInterval(drawMatrix, 50);

    // Global "Scanning" state listeners to speed up matrix and add glitch effects
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        // Speed up matrix when network activity happens
        clearInterval(matrixInterval);
        matrixInterval = setInterval(drawMatrix, 20);
        document.body.classList.add('hacker-scanning');
        
        try {
            const response = await originalFetch.apply(this, args);
            return response;
        } finally {
            setTimeout(() => {
                clearInterval(matrixInterval);
                matrixInterval = setInterval(drawMatrix, 50);
                document.body.classList.remove('hacker-scanning');
            }, 1500);
        }
    };

    // 2. Typing Effect for Terminal Backgrounds
    const terms = document.querySelectorAll('.bg-terminal-left, .bg-terminal-right');
    terms.forEach(term => {
        const textNodes = Array.from(term.childNodes).filter(node => node.nodeType === 3 && node.textContent.trim().length > 0);
        
        textNodes.forEach((node, i) => {
            const originalText = node.textContent;
            node.textContent = '';
            
            let charIdx = 0;
            setTimeout(() => {
                const typeInterval = setInterval(() => {
                    node.textContent += originalText[charIdx];
                    charIdx++;
                    if (charIdx >= originalText.length) clearInterval(typeInterval);
                }, 50);
            }, i * 1500);
        });
    });

    // 3. Add Dynamic Threat Map Overlay in Dashboard
    const dashboardTab = document.getElementById('tab-dashboard');
    if(dashboardTab) {
        const threatMapContainer = document.createElement('div');
        threatMapContainer.className = 'card card-glow border-accent-glow mt-4';
        threatMapContainer.innerHTML = `
            <h3 class="card-title"><i class="fa-solid fa-earth-americas fa-spin-pulse text-accent"></i> Global Threat Map (Live)</h3>
            <div class="threat-map-visual" style="height: 300px; position: relative; background: radial-gradient(circle at center, rgba(0, 255, 102, 0.1) 0%, transparent 70%); border: 1px dashed var(--border-color); overflow: hidden; display: flex; align-items: center; justify-content: center;">
                <div class="radar-scan"></div>
                <div id="active-threats" style="position: absolute; width: 100%; height: 100%;"></div>
                <div style="font-family: var(--font-hacker); color: var(--accent); opacity: 0.5; font-size: 2rem; letter-spacing: 10px;">MONITORING</div>
            </div>
        `;
        dashboardTab.insertBefore(threatMapContainer, dashboardTab.children[1]); // Insert after first row

        // Simulate attacks
        setInterval(() => {
            const threatsArea = document.getElementById('active-threats');
            if(!threatsArea) return;
            
            const threat = document.createElement('div');
            threat.className = 'threat-ping';
            threat.style.left = Math.random() * 90 + '%';
            threat.style.top = Math.random() * 90 + '%';
            
            threatsArea.appendChild(threat);
            setTimeout(() => threat.remove(), 2000);
        }, 800);
    }
});
