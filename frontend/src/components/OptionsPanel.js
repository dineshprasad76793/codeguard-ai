import React, { useState } from 'react';

const TOGGLES = [
  { key: 'owasp', label: 'OWASP Top 10 mapping', hint: 'Map each finding to its OWASP category' },
  { key: 'secrets', label: 'Secrets detection', hint: 'Scan for API keys, passwords, tokens' },
  { key: 'deps', label: 'Dependency check', hint: 'Review package manifests for vulnerable packages' },
];

export default function OptionsPanel({ options, setOptions, customRules, setCustomRules }) {
  const [open, setOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [newPattern, setNewPattern] = useState('');

  const addRule = () => {
    if (!newName.trim() || !newPattern.trim()) return;
    let re;
    try {
      re = new RegExp(newPattern);
    } catch (e) {
      alert('Invalid regex: ' + e.message);
      return;
    }
    setCustomRules([
      ...customRules,
      { id: 'rule-' + Date.now(), name: newName.trim(), pattern: newPattern, enabled: true },
    ]);
    setNewName('');
    setNewPattern('');
  };

  const toggleRule = (id) =>
    setCustomRules(customRules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)));

  const removeRule = (id) => setCustomRules(customRules.filter((r) => r.id !== id));

  return (
    <div className="options-panel">
      <button className="options-toggle" onClick={() => setOpen(!open)}>
        {open ? '▾' : '▸'} Analysis options {options.owasp || options.secrets || options.deps ? '•' : ''}
      </button>
      {open && (
        <div className="options-body">
          {TOGGLES.map((t) => (
            <label key={t.key} className="option-row" title={t.hint}>
              <input
                type="checkbox"
                checked={!!options[t.key]}
                onChange={(e) => setOptions({ ...options, [t.key]: e.target.checked })}
              />
              <span>{t.label}</span>
            </label>
          ))}

          <div className="rules-section">
            <div className="rules-title">Custom security rules (regex)</div>
            {customRules.map((r) => (
              <div key={r.id} className="rule-row">
                <input type="checkbox" checked={r.enabled} onChange={() => toggleRule(r.id)} />
                <span className="rule-name">{r.name}</span>
                <code className="rule-pattern">{r.pattern}</code>
                <button className="btn btn-mini" onClick={() => removeRule(r.id)}>
                  Remove
                </button>
              </div>
            ))}
            <div className="rule-row add">
              <input
                type="text"
                placeholder="Rule name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
              <input
                type="text"
                placeholder="Regex pattern e.g. admin_mode\\s*=\\s*true"
                value={newPattern}
                onChange={(e) => setNewPattern(e.target.value)}
              />
              <button className="btn btn-mini" onClick={addRule}>
                Add
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
