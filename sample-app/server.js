const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const _ = require('lodash');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory mock database for testing
const mockDatabase = {
  users: [
    { id: 1, username: 'admin', role: 'administrator' },
    { id: 2, username: 'john_doe', role: 'user' }
  ],
  // Raw SQL query executor simulator
  query: function(rawSql, callback) {
    console.log(`[DB EXECUTING SQL]: ${rawSql}`);
    // Simulate query execution
    setTimeout(() => {
      callback(null, this.users);
    }, 10);
  }
};

// ==========================================
// [SAST TRUE POSITIVES - Real Vulnerabilities]
// ==========================================

// 1. Hardcoded Secrets (Real vulnerability)
const JWT_SECRET = "production_super_secret_signing_key_987654321";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

// 2. Command Injection (True Positive)
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  // VULNERABLE: Direct string interpolation into shell command
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(`Error: ${stderr}`);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// 3. SQL Injection (True Positive)
app.get('/api/users', (req, res) => {
  const username = req.query.username;
  // VULNERABLE: Unsanitized SQL concatenation
  const sql = "SELECT * FROM users WHERE username = '" + username + "'";
  mockDatabase.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ executed_sql: sql, results: rows });
  });
});

// 4. Reflected XSS (True Positive)
app.get('/api/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // VULNERABLE: Direct reflection without encoding or template engine
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// 5. Path Traversal (True Positive)
app.get('/api/view-log', (req, res) => {
  const filename = req.query.file;
  // VULNERABLE: Attacker can supply ../../etc/passwd
  const filePath = path.join(__dirname, 'logs', filename);
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    res.send(`<pre>${data}</pre>`);
  } catch (err) {
    res.status(404).send('File not found');
  }
});

// 6. Prototype Pollution (via vulnerable lodash 4.17.15)
app.post('/api/merge', (req, res) => {
  const target = {};
  // VULNERABLE: Lodash merge with user-controlled input can pollute Object.prototype
  _.merge(target, req.body);
  res.json({ message: "Merged successfully", data: target });
});


// ==============================================================
// [SAST FALSE POSITIVES - Deliberate Triggers for Phase 2 AI Triage]
// ==============================================================

// FP 1: Test / Mock Token (Flagged by secret scanners, but is actually a harmless test dummy)
const MOCK_API_TEST_TOKEN = "test_environment_mock_token_not_a_real_secret_xyz123";

// FP 2: Static / Whitelisted command (Scanner may flag exec near req.query, but it is strictly guarded)
app.get('/api/system-status', (req, res) => {
  const requestedService = req.query.service;
  const ALLOWED_SERVICES = ['nginx', 'redis', 'postgres'];

  // SAFE: Strict whitelist check ensures no command injection can take place
  if (!ALLOWED_SERVICES.includes(requestedService)) {
    return res.status(400).send("Invalid service requested");
  }

  // Safe static execution with hardcoded verified string
  exec('uptime', (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(`Service ${requestedService} uptime: ${stdout}`);
  });
});

// FP 3: XSS Scanner heuristic trigger with safe HTML encoding
function safeEscapeHtml(unsafeStr) {
  if (!unsafeStr) return '';
  return String(unsafeStr)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

app.get('/api/safe-greet', (req, res) => {
  const user = req.query.user || 'Guest';
  // SAFE: Input is properly sanitized before HTML concatenation, but regex SAST rules may flag res.send + concatenation
  const cleanUser = safeEscapeHtml(user);
  res.send(`<h2>Welcome back, ${cleanUser}</h2>`);
});

// Auth: Simple login endpoint for Blog App
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = mockDatabase.users.find(u => u.username === username);
  if (user && (password === 'admin123' || password === 'user123' || password === 'password')) {
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    return res.json({ success: true, token, user });
  }
  res.status(401).json({ success: false, error: 'Invalid username or password' });
});

// Root endpoint - serves UI for browsers and JSON for API clients
app.get('/', (req, res) => {
  const accept = req.headers.accept || '';
  if (accept.includes('text/html') && !req.query.format) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  res.json({
    status: "online",
    message: "DevSecOps Lab Vulnerable Sample Node.js App",
    endpoints: [
      "/api/ping?host=127.0.0.1",
      "/api/users?username=admin",
      "/api/greet?name=SecurityTeam",
      "/api/view-log?file=app.log",
      "/api/system-status?service=nginx",
      "/api/safe-greet?user=Alice",
      "/api/login"
    ]
  });
});

app.listen(port, () => {
  console.log(`Vulnerable Node.js sample app listening at http://localhost:${port}`);
});

