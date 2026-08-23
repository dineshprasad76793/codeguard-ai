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
  const [error, setError] = useState('');
  const [elapsed, setElapsed] = useState(0);
  const [jump, setJump] = useState(null);
  const [hiddenFps, setHiddenFps] = useState([]);
  const [history, setHistory] = useState(() => loadJSON('cg-history', []));
  const [shareUrl, setShareUrl] = useState('');
  const [currentTarget, setCurrentTarget] = useState('');
  const fileInputRef = useRef(null);
  const wasAutoDetected = useRef(false);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    saveJSON('cg-theme', theme);
  }, [theme]);

  useEffect(() => saveJSON('cg-rules', customRules), [customRules]);
  useEffect(() => saveJSON('cg-history', history), [history]);

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
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Request failed.');
    return data;
  };

  const runAnalysis = async () => {
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
    try {
      const data = await request(endpoint, body);
      setAnalysis(data.analysis);
      setCurrentTarget(target);
      const id = 's' + Date.now();
      setHiddenFps([]);
      pushHistory({
        id,
        ts: Date.now(),
        mode,
        target,
        analysis: data.analysis,
        code: mode === 'code' ? code.slice(0, 50_000) : '',
      });
    } catch (err) {
      setError(err.message || 'Could not connect to the backend.');
    } finally {
      setLoading(false);
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
