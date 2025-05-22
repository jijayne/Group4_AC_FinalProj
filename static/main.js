function startMatrixEffect() {
    const canvas = document.getElementById("matrix");
    const ctx = canvas.getContext("2d");

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const binary = "01";
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = new Array(Math.floor(columns)).fill(1);

    function drawMatrix() {
        ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = "#0f0";
        ctx.font = fontSize + "px monospace";

        for (let i = 0; i < drops.length; i++) {
            const text = binary[Math.floor(Math.random() * binary.length)];
            const x = i * fontSize;
            const y = drops[i] * fontSize;

            ctx.fillText(text, x, y);

            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(drawMatrix, 50);

    // Resize canvas on window resize
    window.addEventListener("resize", () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

window.addEventListener("DOMContentLoaded", () => {
    applyTypingEffectToAll();
    startMatrixEffect();
});

// Helper function: type a string letter-by-letter into an element
function typeLetterByLetter(element, text, speed = 10, callback = null) {
    element.textContent = "";
    let i = 0;
    const interval = setInterval(() => {
        element.textContent += text.charAt(i);
        i++;
        if (i >= text.length) {
            clearInterval(interval);
            if (callback) callback();
        }
    }, speed);
}

// Function to recursively type through all eligible elements
function applyTypingEffectToAll() {
    // Selectors for elements with text content you want to animate
    const selectors = 'h1, h2, p, pre, .text, .pseudocode';
    const elements = document.querySelectorAll(selectors);

    let index = 0;

    function typeNext() {
        if (index >= elements.length) return;
        const el = elements[index];
        const original = el.textContent.trim();
        typeLetterByLetter(el, original, 10, () => {
            index++;
            typeNext();
        });
    }

    typeNext(); // Start typing sequence
}

window.addEventListener("DOMContentLoaded", applyTypingEffectToAll);
