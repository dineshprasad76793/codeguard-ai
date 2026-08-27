// SAFE SAMPLE — every classic false-positive trigger, deliberately safe.
// Expected: NO Confirmed/Critical/High vulnerability findings.

const express = require('express');
const app = express();
const DOMPurify = require('isomorphic-dompurify');

// escaped innerHTML — historically mislabeled XSS
app.get('/greet', (req, res) => {
  el.innerHTML = escapeHtml(req.query.name);
});

// parameterized SQL with the word SELECT — never SQL injection
app.get('/user', (req, res) => {
  db.all('SELECT id, name FROM users WHERE id = ?', [req.query.id], (err, rows) => {
    res.json(rows);
  });
});

// fixed-argument child process — not command injection
function reload() {
  execFile('systemctl', ['reload', 'nginx']);
}

// inline handler + generic catch — code quality at most
app.get('/page', (req, res) => {
  try {
    res.send('<button onclick="toggleMenu()">Menu</button>');
  } catch (e) {
    log.error('render failed', e.message);
  }
});

// placeholder secrets — never credential exposure
const API_KEY = 'YOUR_API_KEY';
const DB_PASSWORD = 'example';

// safe parsing — never unsafe deserialization
const cfg = JSON.parse(process.env.CONFIG_JSON || '{}');
