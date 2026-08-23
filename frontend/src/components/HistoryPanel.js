import React from 'react';

const MODE_LABEL = {
  code: 'Code',
  url: 'URL',
  github: 'GitHub',
};

export default function HistoryPanel({ history, onOpen, onClear }) {
  if (!history.length) return null;
  return (
    <div className="history-panel">
      <div className="history-head">
        <span>Recent scans ({history.length})</span>
        <button className="btn btn-mini" onClick={onClear}>
          Clear
        </button>
      </div>
      <div className="history-list">
        {history.map((h) => (
          <button key={h.id} className="history-item" onClick={() => onOpen(h)}>
            <span className="history-mode">{MODE_LABEL[h.mode] || h.mode}</span>
            <span className="history-target" title={h.target}>
              {h.target}
            </span>
            <span className="history-time">
              {new Date(h.ts).toLocaleString([], {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
