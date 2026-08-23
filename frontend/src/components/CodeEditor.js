import React, { useEffect, useMemo, useRef } from 'react';

const KEYWORDS = [
  'abstract', 'as', 'async', 'await', 'break', 'case', 'catch', 'class',
  'const', 'continue', 'def', 'default', 'delete', 'do', 'elif', 'else',
  'enum', 'except', 'export', 'extends', 'finally', 'for', 'from', 'func',
  'function', 'go', 'if', 'implements', 'import', 'in', 'instanceof',
  'interface', 'is', 'let', 'match', 'module', 'new', 'not', 'or', 'and',
  'package', 'pass', 'print', 'private', 'protected', 'public', 'raise',
  'return', 'self', 'static', 'struct', 'super', 'switch', 'template',
  'this', 'throw', 'throws', 'try', 'type', 'typedef', 'use', 'var',
  'virtual', 'void', 'while', 'with', 'yield', 'True', 'False', 'None',
  'true', 'false', 'null', 'nil', 'fn', 'let', 'mut', 'pub', 'impl',
  'trait', 'where', 'unsafe', 'extern', 'crate', 'using', 'namespace',
  'internal', 'override', 'readonly', 'string', 'int', 'float', 'double',
  'bool', 'char', 'long', 'short', 'unsigned', 'final', 'extends',
];

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function highlightCode(code) {
  const escaped = escapeHtml(code);
  const kw = KEYWORDS.join('|');
  const re = new RegExp(
    [
      '(\\/\\*[\\s\\S]*?\\*\\/|\\/\\/[^\\n]*|#[^\\n]*|--[^\\n]*|&lt;!--[\\s\\S]*?--&gt;)', // 1 comment
      '("(?:\\\\.|[^"\\\\\\n])*"|\'(?:\\\\.|[^\'\\\\\\n])*\'|`(?:\\\\.|[^`\\\\])*`)', // 2 strings
      '(\\b\\d[\\d_]*(?:\\.\\d+)?\\b)', // 3 number
      `(\\b(?:${kw})\\b)`, // 4 keyword
    ].join('|'),
    'g'
  );
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(escaped)) !== null) {
    out += escaped.slice(last, m.index);
    const cls = m[1]
      ? 'tok-comment'
      : m[2]
      ? 'tok-string'
      : m[3]
      ? 'tok-number'
      : 'tok-keyword';
    out += `<span class="${cls}">${m[0]}</span>`;
    last = m.index + m[0].length;
  }
  out += escaped.slice(last);
  return out + '\n';
}

const LINE_HEIGHT = 21;

export default function CodeEditor({
  value,
  onChange,
  jump, // { line: number, ts: number } or null
  readOnly = false,
}) {
  const textareaRef = useRef(null);
  const preRef = useRef(null);
  const gutterRef = useRef(null);
  const [flashLine, setFlashLine] = React.useState(null);

  const lineCount = useMemo(
    () => (value ? value.split('\n').length : 1),
    [value]
  );

  const syncScroll = () => {
    const ta = textareaRef.current;
    if (!ta) return;
    if (preRef.current) {
      preRef.current.scrollTop = ta.scrollTop;
      preRef.current.scrollLeft = ta.scrollLeft;
    }
    if (gutterRef.current) {
      gutterRef.current.scrollTop = ta.scrollTop;
    }
  };

  useEffect(() => {
    if (!jump || !jump.line || !textareaRef.current) return;
    const ta = textareaRef.current;
    const target = Math.max(0, (jump.line - 1) * LINE_HEIGHT - ta.clientHeight / 3);
    ta.scrollTop = target;
    syncScroll();
    setFlashLine(jump.line);
    const t = setTimeout(() => setFlashLine(null), 2000);
    // Move caret to the target line
    const lines = (value || '').split('\n');
    let pos = 0;
    for (let i = 0; i < Math.min(jump.line - 1, lines.length); i++) {
      pos += lines[i].length + 1;
    }
    if (!readOnly) {
      ta.focus({ preventScroll: true });
      ta.setSelectionRange(pos, pos + (lines[jump.line - 1] || '').length);
    }
    return () => clearTimeout(t);
  }, [jump && jump.ts]);

  return (
    <div className="editor-wrap">
      <div className="gutter" ref={gutterRef}>
        {Array.from({ length: lineCount }, (_, i) => (
          <div
            key={i}
            className={'gutter-line' + (flashLine === i + 1 ? ' flash' : '')}
          >
            {i + 1}
          </div>
        ))}
      </div>
      <div className="code-area">
        <pre className="highlight-layer" ref={preRef} aria-hidden="true">
          <code dangerouslySetInnerHTML={{ __html: highlightCode(value || '') }} />
        </pre>
        <textarea
          className="code-input"
          ref={textareaRef}
          value={value}
          readOnly={readOnly}
          onChange={(e) => onChange && onChange(e.target.value)}
          onScroll={syncScroll}
          placeholder="Paste your code here..."
          spellCheck={false}
          wrap="off"
        />
      </div>
    </div>
  );
}
