import React, { useMemo, useState } from 'react';
import { cvssClass, scoreClass } from '../lib/parse';
import { SEVERITY_ORDER } from '../lib/constants';
import {
  buildJSON,
  buildMarkdown,
  copyToClipboard,
  downloadFile,
  badgeUrl,
} from '../lib/exports';
import { downloadPdfReport, sortFindings } from '../lib/pdf';

const FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Custom'];

const SEV_CHIP_CLASS = {
  Critical: 'sev-critical',
  High: 'sev-high',
  Medium: 'sev-medium',
  Low: 'sev-low',
  Info: 'sev-info',
  Custom: 'sev-custom',
};

export default function ReportView({
  report,
  meta,
  hiddenFps,
  onToggleFp,
  onShowAllFps,
  onJumpToLine,
  onCreateShare,
  shareUrl,
}) {
  const [filter, setFilter] = useState('All');
  const [showBadge, setShowBadge] = useState(false);
  const [copied, setCopied] = useState('');

  const allFindings = useMemo(() => report.issues || [], [report]);
  const visible = useMemo(
    () =>
      allFindings.filter(
        (f) => !hiddenFps.includes(f.id) && (filter === 'All' || f.severity === filter)
      ),
    [allFindings, hiddenFps, filter]
  );

  const counts = useMemo(() => {
    const c = { All: allFindings.length };
    for (const f of allFindings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [allFindings]);

  const sorted = useMemo(
    () =>
      [...visible].sort(
        (a, b) =>
          (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
          (b.cvss ?? -1) - (a.cvss ?? -1)
      ),
    [visible]
  );

  // The PDF always contains every finding except ones the user marked as
  // false positives — the on-screen filter is a viewing tool only.
  const pdfFindings = useMemo(
    () => sortFindings(allFindings.filter((f) => !hiddenFps.includes(f.id))),
    [allFindings, hiddenFps]
  );

  const cvssList = useMemo(
    () =>
      allFindings
        .map((f) => f.cvss)
        .filter((v) => v !== null && v !== undefined)
        .sort((a, b) => b - a),
    [allFindings]
  );

  const doCopy = async (text, label) => {
    const ok = await copyToClipboard(text);
    setCopied(ok ? label : '');
    setTimeout(() => setCopied(''), 2000);
  };

  const badgeColor = (score) =>
    score >= 8 ? 'brightgreen' : score >= 5 ? 'yellow' : 'red';

  return (
    <div className="result-box">
      <div className="result-header">
        <h2>Analysis Report</h2>
        <div className="export-row">
          <button
            className="btn btn-mini btn-pdf"
            onClick={() => downloadPdfReport(report, meta, pdfFindings)}
            disabled={pdfFindings.length === 0 && !report.raw}
            title="Download the full report as a PDF file"
          >
            Download PDF
          </button>
          <button
            className="btn btn-mini"
            onClick={() =>
              downloadFile(`codeguard-report-${Date.now()}.md`, buildMarkdown(report.raw, meta), 'text/markdown')
            }
          >
            Markdown
          </button>
          <button
            className="btn btn-mini"
            onClick={() =>
              downloadFile(`codeguard-report-${Date.now()}.json`, buildJSON(report.raw, meta), 'application/json')
            }
          >
            JSON
          </button>
          <button className="btn btn-mini" onClick={() => doCopy(report.raw, 'report')}>
            {copied === 'report' ? 'Copied!' : 'Copy'}
          </button>
          <button className="btn btn-mini" onClick={onCreateShare}>
            {shareUrl ? 'Link created' : 'Share'}
          </button>
          <button className="btn btn-mini" onClick={() => setShowBadge(!showBadge)}>
            Badge
          </button>
        </div>
      </div>

      {shareUrl && (
        <div className="share-box">
          <span>Temporary link (expires in 24h): </span>
          <code>{shareUrl}</code>
          <button className="btn btn-mini" onClick={() => doCopy(shareUrl, 'link')}>
            {copied === 'link' ? 'Copied!' : 'Copy link'}
          </button>
        </div>
      )}

      {showBadge && report.security !== null && (
        <div className="badge-box">
          <img
            src={badgeUrl('security', `${report.security}/10`, badgeColor(report.security))}
            alt="Security score badge"
          />
          {report.quality !== null && (
            <img
              src={badgeUrl('quality', `${report.quality}/10`, badgeColor(report.quality))}
              alt="Quality score badge"
            />
          )}
          <button
            className="btn btn-mini"
            onClick={() =>
              doCopy(
                `[![Security](${badgeUrl('security', `${report.security}/10`, badgeColor(report.security))})](${meta.siteUrl || ''})`,
                'badge'
              )
            }
          >
            {copied === 'badge' ? 'Copied!' : 'Copy markdown'}
          </button>
        </div>
      )}

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

      {cvssList.length > 0 && (
        <div className="cvss-row">
          <span className="cvss-title">CVSS estimates:</span>
          {cvssList.slice(0, 12).map((score, i) => (
            <span key={i} className={'cvss-badge ' + cvssClass(score)}>
              {score.toFixed(1)}
            </span>
          ))}
        </div>
      )}

      {allFindings.length > 0 && (
        <div className="filter-row">
          {FILTERS.filter((f) => counts[f]).map((f) => (
            <button
              key={f}
              className={'filter-chip' + (filter === f ? ' active' : '')}
              onClick={() => setFilter(f)}
            >
              {f} ({counts[f]})
            </button>
          ))}
          {hiddenFps.length > 0 && (
            <button className="filter-chip fp-restore" onClick={onShowAllFps}>
              Restore {hiddenFps.length} hidden
            </button>
          )}
        </div>
      )}

      {sorted.length > 0 ? (
        <div className="findings">
          {sorted.map((f) => (
            <div key={f.id} className={'finding ' + (SEV_CHIP_CLASS[f.severity] || '')}>
              <div className="finding-head">
                <span className={'sev-badge ' + (SEV_CHIP_CLASS[f.severity] || '')}>
                  {f.severity}
                </span>
                {f.cvss !== null && f.cvss !== undefined && (
                  <span
                    className={'cvss-badge ' + cvssClass(f.cvss)}
                    title={f.vector || 'Estimated CVSS v3.1 (verify manually)'}
                  >
                    {f.cvss.toFixed(1)}
                  </span>
                )}
                <span className="finding-title">{f.title}</span>
                {f.line && (
                  <button
                    className="line-link"
                    onClick={() => onJumpToLine && onJumpToLine(f.line)}
                    title="Jump to line"
                  >
                    Line {f.line}
                  </button>
                )}
                {f.owasp && <span className="owasp-tag">{f.owasp}</span>}
                <button
                  className="fp-btn"
                  title="Mark as false positive and hide"
                  onClick={() => onToggleFp(f.id)}
                >
                  ✕ FP
                </button>
              </div>
              {f.location && <div className="finding-location">{f.location}</div>}
              {f.explanation && <p className="finding-text">{f.explanation}</p>}
              {f.why && (
                <p className="finding-text">
                  <strong>Why it matters: </strong>
                  {f.why}
                </p>
              )}
              {f.recommendation && (
                <p className="finding-text">
                  <strong>Fix: </strong>
                  {f.recommendation}
                </p>
              )}
              {f.vulnCode && (
                <div className="code-pair">
                  <div className="code-block bad">
                    <span className="code-label">Vulnerable</span>
                    <pre>{f.vulnCode}</pre>
                  </div>
                  {f.fixedCode && (
                    <div className="code-block good">
                      <span className="code-label">Fixed</span>
                      <pre>{f.fixedCode}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <pre className="raw-report">{report.raw}</pre>
      )}
    </div>
  );
}
