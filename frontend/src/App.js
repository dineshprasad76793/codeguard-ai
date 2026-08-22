import React, { useRef, useState } from 'react';

const LANGUAGES = [
  'Python', 'Java', 'C', 'C++', 'JavaScript', 'HTML', 'CSS',
];

const EXTENSION_TO_LANGUAGE = {
  py: 'Python',
  java: 'Java',
  c: 'C',
  h: 'C',
  cpp: 'C++',
  cc: 'C++',
  cxx: 'C++',
  js: 'JavaScript',
  jsx: 'JavaScript',
  mjs: 'JavaScript',
  html: 'HTML',
  htm: 'HTML',
  css: 'CSS',
};

// API calls use relative paths: same-origin in production,
// and the dev server proxies /api to the backend (see package.json "proxy").
const BACKEND_URL = '';

function parseReport(text) {
  const quality = text.match(/Code Quality:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  const security = text.match(/Security:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  const counts = text.match(
    /Critical:\s*(\d+)\s*\|\s*High:\s*(\d+)\s*\|\s*Medium:\s*(\d+)\s*\|\s*Low:\s*(\d+)/i
  );
  const cvssMatches = [...text.matchAll(/CVSS Estimate:\s*(\d+(?:\.\d+)?)/gi)];
  return {
    quality: quality ? Number(quality[1]) : null,
    security: security ? Number(security[1]) : null,
    critical: counts ? Number(counts[1]) : null,
    high: counts ? Number(counts[2]) : null,
    medium: counts ? Number(counts[3]) : null,
    low: counts ? Number(counts[4]) : null,
    cvssList: cvssMatches.map((m) => Number(m[1])),
  };
}

function cvssClass(score) {
  if (score >= 9) return 'cvss-critical';
  if (score >= 7) return 'cvss-high';
  if (score >= 4) return 'cvss-medium';
  if (score > 0) return 'cvss-low';
  return 'cvss-none';
}

function scoreClass(score) {
  if (score === null) return '';
  if (score >= 8) return 'score-green';
  if (score >= 5) return 'score-yellow';
  return 'score-red';
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function buildReportHtml(analysis) {
  const now = new Date();
  const dateStr = now.toLocaleString();
  return '<!DOCTYPE html>\n'
    + '<html>\n<head>\n<meta charset="UTF-8" />\n'
    + '<title>CodeGuard AI Report</title>\n'
    + '<style>\n'
    + 'body { font-family: Segoe UI, Arial, sans-serif; background: #f1f5f9; color: #0f172a; padding: 40px; }\n'
    + '.card { max-width: 900px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n'
    + 'h1 { color: #2563eb; margin-bottom: 4px; }\n'
    + '.meta { color: #64748b; font-size: 0.85rem; margin-bottom: 24px; }\n'
    + 'pre { white-space: pre-wrap; background: #0f172a; color: #e2e8f0; padding: 20px; border-radius: 8px; font-size: 0.85rem; line-height: 1.6; }\n'
    + '.footer { margin-top: 24px; color: #64748b; font-size: 0.75rem; text-align: center; }\n'
    + '@media print { body { background: #fff; padding: 0; } .card { box-shadow: none; } pre { background: #f8fafc; color: #0f172a; } }\n'
    + '</style>\n</head>\n<body>\n'
    + '<div class="card">\n'
    + '<h1>CodeGuard AI - Analysis Report</h1>\n'
    + '<div class="meta">Generated: ' + dateStr + '</div>\n'
    + '<pre>' + escapeHtml(analysis) + '</pre>\n'
    + '<div class="footer">Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai<br />AI-assisted analysis - verify all findings manually.</div>\n'
    + '</div>\n</body>\n</html>';
}

function App() {
  const [mode, setMode] = useState('code');
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('Python');
  const [url, setUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [analysis, setAnalysis] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  const handleAnalyze = async () => {
    if (!code.trim()) {
      setError('Please paste some code before analyzing.');
      return;
    }
    setError('');
    setAnalysis('');
    setLoading(true);

    try {
      const response = await fetch(BACKEND_URL + '/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language, code }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Analysis failed.');
      }

      setAnalysis(data.analysis);
    } catch (err) {
      setError(err.message || 'Could not connect to the backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to scan.');
      return;
    }
    if (!authorized) {
      setError('Please confirm you have authorization to test this target.');
      return;
    }
    setError('');
    setAnalysis('');
    setLoading(true);

    try {
      const response = await fetch(BACKEND_URL + '/api/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Scan failed.');
      }

      setAnalysis(data.analysis);
    } catch (err) {
      setError(err.message || 'Could not connect to the backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setCode('');
    setUrl('');
    setAnalysis('');
    setError('');
  };

  const handleUploadClick = () => {
    fileInputRef.current.click();
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const ext = file.name.split('.').pop().toLowerCase();
    const lang = EXTENSION_TO_LANGUAGE[ext];
    if (!lang) {
      setError(
        'Unsupported file type. Supported: .py, .java, .c, .cpp, .js, .html, .css'
      );
      event.target.value = '';
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      setCode(e.target.result);
      setLanguage(lang);
      setAnalysis('');
      setError('');
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const handleDownload = () => {
    const blob = new Blob([buildReportHtml(analysis)], { type: 'text/html' });
    const link = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
    link.href = URL.createObjectURL(blob);
    link.download = 'codeguard-report-' + stamp + '.html';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  };

  const report = analysis ? parseReport(analysis) : null;

  return (
    <div className="app">
      <header className="header">
        <h1 className="title">CodeGuard AI</h1>
        <p className="subtitle">by Dinesh | dinesh.ai</p>
      </header>

      <main className="main">
        <div className="input-section">
          <div className="tabs">
            <button
              className={'tab' + (mode === 'code' ? ' active' : '')}
              onClick={() => { setMode('code'); setError(''); }}
            >
              Code Analysis
            </button>
            <button
              className={'tab' + (mode === 'url' ? ' active' : '')}
              onClick={() => { setMode('url'); setError(''); }}
            >
              URL Security Check
            </button>
          </div>

          {mode === 'code' ? (
            <>
              <div className="controls">
                <select
                  className="language-select"
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                >
                  {LANGUAGES.map((lang) => (
                    <option key={lang} value={lang}>
                      {lang}
                    </option>
                  ))}
                </select>

                <button
                  className="btn btn-analyze"
                  onClick={handleAnalyze}
                  disabled={loading}
                >
                  {loading ? 'Analyzing...' : 'Analyze Code'}
                </button>

                <button
                  className="btn btn-upload"
                  onClick={handleUploadClick}
                  disabled={loading}
                >
                  Upload File
                </button>

                <button
                  className="btn btn-clear"
                  onClick={handleClear}
                  disabled={loading}
                >
                  Clear
                </button>

                <input
                  ref={fileInputRef}
                  type="file"
                  className="file-input"
                  accept=".py,.java,.c,.cpp,.cc,.cxx,.h,.js,.jsx,.mjs,.html,.htm,.css"
                  onChange={handleFileUpload}
                />
              </div>

              <textarea
                className="code-editor"
                placeholder="Paste your code here..."
                value={code}
                onChange={(e) => setCode(e.target.value)}
                spellCheck={false}
              />
            </>
          ) : (
            <>
              <div className="warning-box">
                ⚠️ <strong>Authorized testing only.</strong> Only scan websites
                you own or have written permission to test (for example, a bug
                bounty program's defined scope). Unauthorized scanning is
                illegal in many countries. This tool performs a single passive
                request and an educational assessment — it is not a penetration
                test and does not exploit anything.
              </div>

              <div className="controls">
                <input
                  className="url-input"
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  spellCheck={false}
                />

                <button
                  className="btn btn-analyze"
                  onClick={handleScan}
                  disabled={loading}
                >
                  {loading ? 'Scanning...' : 'Scan URL'}
                </button>

                <button
                  className="btn btn-clear"
                  onClick={handleClear}
                  disabled={loading}
                >
                  Clear
                </button>
              </div>

              <label className="authorize-check">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                />
                I own this website or have authorization to test it
              </label>
            </>
          )}
        </div>

        <div className="result-section">
          {loading && (
            <div className="loading">
              {mode === 'url' ? 'Scanning the URL...' : 'Analyzing your code...'}
            </div>
          )}

          {error && <div className="error-box">{error}</div>}

          {report && (
            <div className="result-box">
              <div className="result-header">
                <h2>Analysis Report</h2>
                <button className="btn btn-download" onClick={handleDownload}>
                  Download Report
                </button>
              </div>

              {(report.quality !== null || report.security !== null) && (
                <div className="score-cards">
                  {report.quality !== null && (
                    <div className={'score-card ' + scoreClass(report.quality)}>
                      <span className="score-label">Code Quality</span>
                      <span className="score-value">{report.quality}/10</span>
                    </div>
                  )}
                  {report.security !== null && (
                    <div className={'score-card ' + scoreClass(report.security)}>
                      <span className="score-label">Security</span>
                      <span className="score-value">{report.security}/10</span>
                    </div>
                  )}
                </div>
              )}

              {report.critical !== null && (
                <div className="counters">
                  <span className="chip chip-critical">
                    🔴 Critical: {report.critical}
                  </span>
                  <span className="chip chip-high">🟠 High: {report.high}</span>
                  <span className="chip chip-medium">
                    🟡 Medium: {report.medium}
                  </span>
                  <span className="chip chip-low">🔵 Low: {report.low}</span>
                </div>
              )}

              {report.cvssList.length > 0 && (
                <div className="cvss-row">
                  <span className="cvss-title">CVSS estimates:</span>
                  {report.cvssList
                    .slice()
                    .sort((a, b) => b - a)
                    .map((score, i) => (
                      <span
                        key={i}
                        className={'cvss-badge ' + cvssClass(score)}
                        title="Estimated CVSS v3.1 base score (educational estimate, requires verification)"
                      >
                        {score.toFixed(1)}
                      </span>
                    ))}
                </div>
              )}

              <pre>{analysis}</pre>
            </div>
          )}
        </div>
      </main>

      <footer className="footer">
        Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai
      </footer>
    </div>
  );
}

export default App;
