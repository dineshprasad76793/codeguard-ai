import React, { useEffect, useMemo, useRef, useState } from 'react';
import CodeEditor from './components/CodeEditor';
import ReportView from './components/ReportView';
import OptionsPanel from './components/OptionsPanel';
import HistoryPanel from './components/HistoryPanel';
import { parseReport } from './lib/parse';
import { detectLanguage, runCustomRules } from './lib/detect';
import { LANGUAGES, EXT_TO_LANG, MAX_HISTORY } from './lib/constants';

const LOADING_STEPS = [
  'Sending request…',
  'AI is reading your code…',
  'Checking for vulnerabilities…',
  'Mapping OWASP categories…',
  'Calculating CVSS scores…',
  'Writing recommendations…',
  'Almost done…',
];

function loadJSON(key, fallback) {
  try {
    const v = localStorage.getItem(key);
    return v ? JSON.parse(v) : fallback;
  } catch (e) {
    return fallback;
  }
}

function saveJSON(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    /* storage full or unavailable — non-critical */
  }
}

function App() {
  const [theme, setTheme] = useState(() => loadJSON('cg-theme', 'dark'));
  const [mode, setMode] = useState('code'); // code | url | github
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('Python');
  const [langLocked, setLangLocked] = useState(false);
  const [url, setUrl] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [options, setOptions] = useState({ owasp: false, secrets: false, deps: false });
  const [customRules, setCustomRules] = useState(() => loadJSON('cg-rules', []));
  const [analysis, setAnalysis] = useState('');
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState('');
  const [elapsed, setElapsed] = useState(0);
  const [jump, setJump] = useState(null);
  const [hiddenFps, setHiddenFps] = useState([]);
  const [history, setHistory] = useState(() => loadJSON('cg-history', []));
  const [apiKey, setApiKey] = useState(() => loadJSON('cg-api-key', ''));
  const [shareUrl, setShareUrl] = useState('');
  const [currentTarget, setCurrentTarget] = useState('');
  const fileInputRef = useRef(null);
  const streamPreRef = useRef(null);
  const inFlight = useRef(false);
  const wasAutoDetected = useRef(false);

  // Keep the live streaming report scrolled to the newest text
  useEffect(() => {
    if (streaming && streamPreRef.current) {
      streamPreRef.current.scrollTop = streamPreRef.current.scrollHeight;
    }
  }, [analysis, streaming]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    saveJSON('cg-theme', theme);
  }, [theme]);

  useEffect(() => saveJSON('cg-rules', customRules), [customRules]);
  useEffect(() => saveJSON('cg-history', history), [history]);
  useEffect(() => saveJSON('cg-api-key', apiKey), [apiKey]);

  useEffect(() => {
    if (!loading) return;
    setElapsed(0);
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, [loading]);

  // Load shared report from ?share= link on first mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('share');
    if (!token || !/^[A-Za-z0-9_-]{10,64}$/.test(token)) return;
    fetch('/api/share/' + encodeURIComponent(token))
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Share link not found or expired.'))))
      .then((d) => {
        setAnalysis(d.analysis);
        setCurrentTarget('Shared report');
        setMode('url'); // findings view; editor hidden in url mode
      })
      .catch((e) => setError(e.message));
  }, []);

  const handleCodeChange = (value) => {
    setCode(value);
    if (!langLocked) {
      const detected = detectLanguage(value);
      if (detected) {
        setLanguage(detected);
        wasAutoDetected.current = true;
      }
    }
  };

  const handleLanguageSelect = (lang) => {
    setLanguage(lang);
    setLangLocked(true);
  };

  const pushHistory = (entry) => {
    setHistory((h) => [entry, ...h.filter((x) => x.id !== entry.id)].slice(0, MAX_HISTORY));
  };

  const openHistory = (h) => {
    setAnalysis(h.analysis);
    setCurrentTarget(h.target);
    setHiddenFps(loadJSON('cg-fp-' + h.id, []));
    setShareUrl('');
    setError('');
    if (h.mode === 'code' && h.code) {
      setMode('code');
      setCode(h.code);
    }
  };

  const request = async (endpoint, body) => {
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-API-Key'] = apiKey;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
      throw new Error(
        'API key missing or invalid (401). Paste the site API key into the ' +
          '"API key" field, then try again.'
      );
    }
    if (!response.ok) throw new Error(data.detail || 'Request failed.');
    return data;
  };

  // Streams the AI answer chunk by chunk; onChunk receives the full
  // accumulated text so far.
  const requestStream = async (endpoint, body, onChunk) => {
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-API-Key'] = apiKey;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({ ...body, stream: true }),
    });
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error(
          'API key missing or invalid (401). Paste the site API key into the ' +
            '"API key" field, then try again.'
        );
      }
      if (response.status === 403) {
        throw new Error(
          'Blocked by the network firewall (403). Your code contains patterns ' +
          '(like rm -rf, /etc/passwd or ../) that the firewall mistakes for a real ' +
          'attack. Slightly change those lines and try again, or ask the site ' +
          'owner to add a firewall exception for this page.'
        );
      }
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Request failed.');
    }
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/plain')) {
      // Server answered with regular JSON (e.g. validation error shape)
      const data = await response.json().catch(() => ({}));
      return data.analysis || '';
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let acc = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      acc += decoder.decode(value, { stream: true });
      onChunk(acc);
    }
    return acc;
  };

  const runAnalysis = async () => {
    if (inFlight.current) return; // guard against double-click races
    inFlight.current = true;
    setError('');
    setAnalysis('');
    setShareUrl('');

    const enabledRules = customRules.filter((r) => r.enabled !== false).map((r) => `${r.name}: ${r.pattern}`);

    let endpoint, body, target;
    if (mode === 'code') {
      if (!code.trim()) {
        setError('Please paste some code before analyzing.');
        return;
      }
      endpoint = '/api/analyze';
      body = {
        language: language,
        code,
        options,
        custom_rules: enabledRules,
      };
      target = `${language} code (${code.split('\n').length} lines)`;
    } else if (mode === 'url') {
      if (!url.trim()) {
        setError('Please enter a URL to scan.');
        return;
      }
      if (!authorized) {
        setError('Please confirm you have authorization to test this target.');
        return;
      }
      endpoint = '/api/scan-url';
      body = { url };
      target = url;
    } else {
      if (!repoUrl.trim()) {
        setError('Please enter a GitHub repository URL.');
        return;
      }
      endpoint = '/api/scan-github';
      body = { url: repoUrl, options, custom_rules: enabledRules };
      target = repoUrl;
    }

    setLoading(true);
    setStreaming(true);
    try {
      const text = await requestStream(endpoint, body, (partial) => setAnalysis(partial));
      if (text.startsWith('ERROR:')) {
        setError(text.replace('ERROR:', '').trim());
        setAnalysis('');
      } else {
        setAnalysis(text);
        setCurrentTarget(target);
        const id = 's' + Date.now();
        setHiddenFps([]);
        pushHistory({
          id,
          ts: Date.now(),
          mode,
          target,
          analysis: text,
          code: mode === 'code' ? code.slice(0, 50_000) : '',
        });
      }
    } catch (err) {
      setError(err.message || 'Could not connect to the backend.');
    } finally {
      setLoading(false);
      setStreaming(false);
      inFlight.current = false;
    }
  };

  const handleClear = () => {
    setCode('');
    setUrl('');
    setRepoUrl('');
    setAnalysis('');
    setError('');
    setShareUrl('');
    setHiddenFps([]);
  };

  const handleUploadClick = () => fileInputRef.current && fileInputRef.current.click();

  const handleFiles = (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;
    const readers = files.map(
      (f) =>
        new Promise((resolve) => {
          const r = new FileReader();
          r.onload = (e) => resolve(`=== FILE: ${f.name} ===\n${e.target.result}`);
          r.readAsText(f);
        })
    );
    Promise.all(readers).then((parts) => {
      setCode(parts.join('\n\n'));
      setMode('code');
      const ext = files[0].name.split('.').pop().toLowerCase();
      if (EXT_TO_LANG[ext]) {
        setLanguage(EXT_TO_LANG[ext]);
        setLangLocked(true);
      }
      setAnalysis('');
      setError('');
    });
    event.target.value = '';
  };

  const createShare = async () => {
    if (shareUrl || !analysis) return;
    try {
      const d = await request('/api/share', {
        analysis: analysis.slice(0, 60_000),
        title: currentTarget,
      });
      const link = `${window.location.origin}/?share=${d.token}`;
      setShareUrl(link);
    } catch (e) {
      setError('Could not create share link: ' + e.message);
    }
  };

  const toggleFp = (id) => setHiddenFps((h) => [...h, id]);
  const showAllFps = () => setHiddenFps([]);

  const report = useMemo(() => {
    if (!analysis) return null;
    const parsed = parseReport(analysis);
    if (mode === 'code' && code) {
      const locals = runCustomRules(code, customRules);
      parsed.issues = [...parsed.issues, ...locals];
    }
    return parsed;
  }, [analysis, mode, code, customRules]);

  const loadingStep = LOADING_STEPS[Math.min(Math.floor(elapsed / 7), LOADING_STEPS.length - 1)];

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1 className="title">CodeGuard AI</h1>
          <p className="subtitle">by Dinesh | dinesh.ai</p>
        </div>
        <button
          className="theme-toggle"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          title="Toggle theme"
        >
          {theme === 'dark' ? '☀' : '☾'}
        </button>
      </header>

      <main className="main">
        <div className="input-section">
          <div className="tabs">
            <button className={'tab' + (mode === 'code' ? ' active' : '')} onClick={() => setMode('code')}>
              Code Analysis
            </button>
            <button className={'tab' + (mode === 'url' ? ' active' : '')} onClick={() => setMode('url')}>
              URL Security Check
            </button>
            <button className={'tab' + (mode === 'github' ? ' active' : '')} onClick={() => setMode('github')}>
              GitHub Repo
            </button>
          </div>

          {mode === 'code' && (
            <>
              <div className="controls">
                <select
                  className="language-select"
                  value={language}
                  onChange={(e) => handleLanguageSelect(e.target.value)}
                  title={wasAutoDetected.current ? 'Auto-detected — change if wrong' : 'Language'}
                >
                  {LANGUAGES.map((l) => (
                    <option key={l} value={l}>
                      {l}
                      {l === language && wasAutoDetected.current ? ' (auto)' : ''}
                    </option>
                  ))}
                </select>
                <button className="btn btn-analyze" onClick={runAnalysis} disabled={loading}>
                  {loading ? 'Analyzing…' : 'Analyze Code'}
                </button>
                <button className="btn btn-upload" onClick={handleUploadClick} disabled={loading}>
                  Upload Files
                </button>
                <button className="btn btn-clear" onClick={handleClear} disabled={loading}>
                  Clear
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  className="file-input"
                  multiple
                  accept=".py,.js,.mjs,.jsx,.ts,.tsx,.java,.go,.php,.c,.h,.cpp,.cc,.cxx,.hpp,.cs,.rs,.rb,.kt,.kts,.swift,.html,.htm,.css"
                  onChange={handleFiles}
                />
              </div>
              <CodeEditor value={code} onChange={handleCodeChange} jump={jump} />
              <OptionsPanel
                options={options}
                setOptions={setOptions}
                customRules={customRules}
                setCustomRules={setCustomRules}
              />
            </>
          )}

          {mode === 'url' && (
            <>
              <div className="warning-box">
                ⚠️ <strong>Authorized testing only.</strong> Only scan websites you own or
                have written permission to test (e.g. a bug bounty program's defined
                scope). One passive GET request — educational assessment, not a
                penetration test.
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
                <button className="btn btn-analyze" onClick={runAnalysis} disabled={loading}>
                  {loading ? 'Scanning…' : 'Scan URL'}
                </button>
                <button className="btn btn-clear" onClick={handleClear} disabled={loading}>
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

          {mode === 'github' && (
            <>
              <div className="warning-box">
                📁 Public repositories only. Up to 8 code files are fetched (capped
                size) and analyzed together.
              </div>
              <div className="controls">
                <input
                  className="url-input"
                  type="url"
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  spellCheck={false}
                />
                <button className="btn btn-analyze" onClick={runAnalysis} disabled={loading}>
                  {loading ? 'Scanning…' : 'Scan Repo'}
                </button>
                <button className="btn btn-clear" onClick={handleClear} disabled={loading}>
                  Clear
                </button>
              </div>
              <OptionsPanel
                options={options}
                setOptions={setOptions}
                customRules={customRules}
                setCustomRules={setCustomRules}
              />
            </>
          )}

          <div className="api-key-row">
            <label htmlFor="api-key">API key (optional)</label>
            <input
              id="api-key"
              type="password"
              placeholder="Optional — only needed for direct API calls"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              autoComplete="off"
            />
          </div>

          <HistoryPanel
            history={history}
            onOpen={openHistory}
            onClear={() => setHistory([])}
          />
        </div>

        <div className="result-section">
          {loading && (
            <div className="loading">
              <div className="loading-info">
                <div className="spinner" />
                <div>
                  <div>{loadingStep}</div>
                  <div className="elapsed">{elapsed}s elapsed</div>
                </div>
              </div>
              <div className="progress-track">
                <div
                  className="progress-bar"
                  style={{ width: `${Math.min(95, 8 + elapsed * 3)}%` }}
                />
              </div>
            </div>
          )}

          {streaming && analysis && (
            <div className="stream-box">
              <div className="stream-label">● Live — AI is writing the report…</div>
              <pre className="raw-report" ref={streamPreRef}>{analysis}</pre>
            </div>
          )}

          {error && <div className="error-box">{error}</div>}

          {report && !loading && (
            <ReportView
              report={report}
              meta={{ mode, target: currentTarget, siteUrl: window.location.origin }}
              hiddenFps={hiddenFps}
              onToggleFp={toggleFp}
              onShowAllFps={showAllFps}
              onJumpToLine={(line) => {
                if (mode !== 'code') {
                  setMode('code');
                }
                setJump({ line, ts: Date.now() });
              }}
              onCreateShare={createShare}
              shareUrl={shareUrl}
            />
          )}
        </div>
      </main>

      <footer className="footer">
        Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai — AI-assisted
        analysis; verify all findings manually. Authorized testing only.
      </footer>
    </div>
  );
}

export default App;
