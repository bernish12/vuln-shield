// Typing animation for the terminal path
        const path = window.location.pathname;
        const el = document.getElementById('typed-path');
        let i = 0;
        function type() {
            if (i < path.length) {
                el.textContent += path[i++];
                setTimeout(type, 60);
            }
        }
        setTimeout(type, 800);