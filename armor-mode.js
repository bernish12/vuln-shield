/**
 * Armor Mode Logic for VulnShield
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnArmor = document.getElementById('btn-armor-mode');
    let isArmorActive = false;

    if (btnArmor) {
        btnArmor.addEventListener('click', () => {
            if (isArmorActive) {
                // Deactivate
                isArmorActive = false;
                btnArmor.innerHTML = '<i class="fa-solid fa-shield-virus"></i> Armor Mode';
                btnArmor.style.background = 'rgba(0, 255, 102, 0.15)';
                btnArmor.style.borderColor = 'rgba(0, 255, 102, 0.5)';
                btnArmor.style.color = 'var(--accent)';
                btnArmor.style.boxShadow = '0 0 10px rgba(0, 255, 102, 0.2)';
                document.body.classList.remove('armor-active');
                showToast('Armor Mode Deactivated', 'System returned to standard monitoring state.', 'info');
            } else {
                // Activate
                isArmorActive = true;
                btnArmor.innerHTML = '<i class="fa-solid fa-shield-halved"></i> ARMOR ACTIVE';
                btnArmor.style.background = 'rgba(0, 255, 255, 0.15)'; // Cyan
                btnArmor.style.borderColor = 'rgba(0, 255, 255, 0.8)';
                btnArmor.style.color = '#00ffff';
                btnArmor.style.boxShadow = '0 0 20px rgba(0, 255, 255, 0.6)';
                
                document.body.classList.add('armor-active');
                
                // Show glitch effect
                document.body.classList.add('hacker-scanning');
                setTimeout(() => document.body.classList.remove('hacker-scanning'), 1000);

                showToast('Armor Mode Activated', 'Strict Firewall rules applied. Inbound connections blocked. Auto-Kill switch armed.', 'success');
                
                // Log in dashboard if log exists
                const logContainer = document.getElementById('dashboard-recent-logs');
                if (logContainer) {
                    const emptyState = logContainer.querySelector('.matrix-empty');
                    if (emptyState) emptyState.remove();

                    const logItem = document.createElement('div');
                    logItem.className = 'matrix-log-item new-log';
                    logItem.innerHTML = `
                        <span class="log-time">[${new Date().toLocaleTimeString()}]</span>
                        <span class="log-level level-critical">SYS</span>
                        <span class="log-msg" style="color: #00ffff;">PROACTIVE DEFENSE: Armor Mode initialized. Network hardened.</span>
                    `;
                    logContainer.prepend(logItem);
                }
            }
        });
    }

    // Helper for Toast if doesn't exist globally
    function showToast(title, desc, type) {
        const toast = document.getElementById('toast-notif');
        if (toast) {
            toast.querySelector('.toast-title').textContent = title;
            toast.querySelector('.toast-desc').textContent = desc;
            
            const icon = toast.querySelector('.toast-icon');
            icon.className = 'fa-solid toast-icon ' + (type === 'success' ? 'fa-shield-halved text-blue' : 'fa-circle-info text-accent');
            if(type === 'success') icon.style.color = '#00ffff';
            
            toast.classList.remove('d-none');
            toast.classList.add('show');
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => toast.classList.add('d-none'), 300);
            }, 4000);
        }
    }
});
