import React, { useMemo, useState } from 'react';
import { cvssClass, scoreClass, CATEGORY_ORDER } from '../lib/parse';
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

const CAT_CHIP_CLASS = {
  'Confirmed Vulnerability': 'cat-confirmed',
  'Potential Vulnerability': 'cat-potential',
  'Security Hardening': 'cat-hardening',
  'Code Quality': 'cat-quality',
  Informational: 'cat-informational',
};

const CAT_SHORT = {
  'Confirmed Vulnerability': 'Confirmed',
  'Potential Vulnerability': 'Potential',
  'Security Hardening': 'Hardening',
  'Code Quality': 'Quality',
  Informational: 'Info',
};

const CONF_CHIP_CLASS = { High: 'conf-high', Medium: 'conf-medium', Low: 'conf-low' };

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
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [showBadge, setShowBadge] = useState(false);
  const [copied, setCopied] = useState('');

  const allFindings = useMemo(() => report.issues || [], [report]);
  const visible = useMemo(
    () =>
      allFindings.filter(
        (f) =>
          !hiddenFps.includes(f.id) &&
          (filter === 'All' || f.severity === filter) &&
          (categoryFilter === 'All' || f.category === categoryFilter)
      ),
    [allFindings, hiddenFps, filter, categoryFilter]
  );

  const counts = useMemo(() => {
    const c = { All: allFindings.length };
    for (const f of allFindings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [allFindings]);

  const catCounts = useMemo(() => {
    const c = { All: allFindings.length };
    for (const f of allFindings) if (f.category) c[f.category] = (c[f.category] || 0) + 1;
    return c;
  }, [allFindings]);

  const sorted = useMemo(
    () =>
      [...visible].sort(
        (a, b) =>
          (CATEGORY_ORDER.indexOf(a.category) ?? 9) - (CATEGORY_ORDER.indexOf(b.category) ?? 9) ||
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

      {report.categoryCounts && (
        <div className="category-summary">
          {CATEGORY_ORDER.filter((c) => report.categoryCounts[c] > 0).map((c) => (
            <span key={c} className={'cat-badge ' + (CAT_CHIP_CLASS[c] || '')}>
              {CAT_SHORT[c]}: {report.categoryCounts[c]}
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

      {catCounts.All > 0 && Object.keys(catCounts).length > 2 && (
        <div className="filter-row">
          {['All', ...CATEGORY_ORDER]
            .filter((c) => catCounts[c])
            .map((c) => (
              <button
                key={c}
                className={'filter-chip cat-chip' + (categoryFilter === c ? ' active' : '')}
                onClick={() => setCategoryFilter(c)}
              >
                {c === 'All' ? 'All categories' : CAT_SHORT[c] || c} ({catCounts[c]})
              </button>
            ))}
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
                {f.category && (
                  <span className={'cat-badge ' + (CAT_CHIP_CLASS[f.category] || '')}>
                    {CAT_SHORT[f.category] || f.category}
                  </span>
                )}
                {f.confidence && (
                  <span
                    className={'conf-badge ' + (CONF_CHIP_CLASS[f.confidence] || '')}
                    title="Static-analysis confidence"
                  >
                    {f.confidence} conf.
                  </span>
                )}
                {f.cvss !== null && f.cvss !== undefined && (
                  <span
                    className={'cvss-badge ' + cvssClass(f.cvss)}
                    title={f.vector || 'Estimated CVSS v3.1 (verify manually)'}
                  >
                    {f.cvss.toFixed(1)}
                  </span>
                )}
                <span className="finding-title">{f.title}</span>
                {f.file && <span className="finding-file">{f.file}</span>}
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
                {f.cwe && <span className="owasp-tag" title="CWE reference">{f.cwe}</span>}
                <button
                  className="fp-btn"
                  title="Mark as false positive and hide"
                  onClick={() => onToggleFp(f.id)}
                >
                  ✕ FP
                </button>
              </div>
              {f.location && <div className="finding-location">{f.location}</div>}
              {f.evidence && (
                <p className="finding-text">
                  <strong>Evidence: </strong>
                  {f.evidence}
                </p>
              )}
              {f.dataFlow && f.dataFlow !== 'N/A' && (
                <p className="finding-text data-flow">
                  <strong>Data flow: </strong>
                  {f.dataFlow}
                </p>
              )}
              {f.explanation && !f.evidence && (
                <p className="finding-text">{f.explanation}</p>
              )}
              {f.why && (
                <p className="finding-text">
                  <strong>Why it matters: </strong>
                  {f.why}
                </p>
              )}
              {f.whyDetected && (
                <p className="finding-text muted">
                  <strong>Why detected: </strong>
                  {f.whyDetected}
                </p>
              )}
              {f.fpAnalysis && (
                <p className="finding-text why-not-vuln">
                  <strong>False positive analysis: </strong>
                  {f.fpAnalysis}
                </p>
              )}
              {f.whyNotVuln && (
                <p className="finding-text why-not-vuln">
                  <strong>Why this is not necessarily a vulnerability: </strong>
                  {f.whyNotVuln}
                </p>
              )}
              {f.recommendation && (
                <p className="finding-text">
                  <strong>Fix: </strong>
                  {f.recommendation}
                </p>
              )}
              {f.manualVerification &&
                !/^no\b/i.test(f.manualVerification.trim()) && (
                  <p className="finding-text manual-verify">
                    <strong>Manual verification required: </strong>
                    {f.manualVerification}
                  </p>
                )}
              {f.cvssRaw && !/not enough/i.test(f.cvssRaw) && f.cvss === null && (
                <p className="finding-text muted">
                  <strong>CVSS: </strong>
                  {f.cvssRaw}
                </p>
              )}
              {f.cvssRaw && /not enough/i.test(f.cvssRaw) && (
                <p className="finding-text muted">
                  <strong>CVSS: </strong>Not enough information — severity + confidence shown above
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
