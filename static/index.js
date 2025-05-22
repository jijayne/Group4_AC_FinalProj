// Matrix background effect
const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const letters = "01";
const fontSize = 12;
const columns = canvas.width / fontSize;
const drops = Array(Math.floor(columns)).fill(1);

function drawMatrix() {
  ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = "#0F0";
  ctx.font = fontSize + "px monospace";

  for (let i = 0; i < drops.length; i++) {
    const text = letters[Math.floor(Math.random() * letters.length)];
    ctx.fillText(text, i * fontSize, drops[i] * fontSize);

    if (drops[i] * fontSize > canvas.height || Math.random() > 0.975) {
      drops[i] = 0;
    }
    drops[i]++;
  }
}

setInterval(drawMatrix, 33);

// Fake log messages
const logMessages = [
  "Establishing encrypted tunnel...",
  "Bypassing firewall rule set...",
  "Injecting payload into memory...",
  "Decrypting secure block...",
  "Accessing kernel permissions...",
  "Trace suppression engaged...",
  "MAC spoofing in progress...",
  "Hash collision detected...",
  "Secure channel established.",
  "Writing output to /dev/null..."
];

function addLogEntry() {
  const logContent = document.getElementById("logContent");
  if (!logContent) return;

  const entry = document.createElement("div");
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${logMessages[Math.floor(Math.random() * logMessages.length)]}`;
  logContent.appendChild(entry);

  logContent.scrollTop = logContent.scrollHeight;
}

setInterval(addLogEntry, 1500);

function updateNetwork() {
    const net = document.getElementById('networkContent');
    const data = `↳ ${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)} → ${Math.floor(Math.random() * 9999)} bytes`;
    const entry = document.createElement('p');
    entry.textContent = data;
    net.appendChild(entry);
    net.scrollTop = net.scrollHeight;
}

setInterval(updateNetwork, 800);

const passwords = ['hunter2', 'letmein', 'admin123', 'qwerty', 'password', 'trustno1', 'root', '12345678'];
let attemptIndex = 0;

function updateCracker() {
    const cracker = document.getElementById('crackerContent');
    const pass = passwords[attemptIndex % passwords.length];
    const crackText = `Trying password: ${pass} ... ${Math.random() > 0.95 ? '✔️ Success' : '❌ Failed'}`;
    
    const line = document.createElement('p');
    line.textContent = crackText;
    cracker.appendChild(line);
    cracker.scrollTop = cracker.scrollHeight;

    attemptIndex++;
}

setInterval(updateCracker, 900);
