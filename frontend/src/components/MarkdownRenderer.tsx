import React, { useState } from 'react';
import { Copy, Check, Terminal, ExternalLink } from 'lucide-react';

interface MarkdownRendererProps {
  content: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content }) => {
  if (!content) return null;

  // Split by code blocks ```lang ... ```
  const codeBlockRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  let blockKey = 0;
  while ((match = codeBlockRegex.exec(content)) !== null) {
    const textBefore = content.substring(lastIndex, match.index);
    if (textBefore) {
      parts.push(<TextBlock key={`text-${blockKey++}`} text={textBefore} />);
    }

    const language = match[1]?.trim() || 'plaintext';
    const code = match[2];
    parts.push(<CodeBlock key={`code-${blockKey++}`} language={language} code={code} />);

    lastIndex = match.index + match[0].length;
  }

  const remainingText = content.substring(lastIndex);
  if (remainingText) {
    parts.push(<TextBlock key={`text-${blockKey++}`} text={remainingText} />);
  }

  return <div className="space-y-3 leading-relaxed text-sm md:text-base">{parts}</div>;
};

// Code block with Copy button and language pill
const CodeBlock: React.FC<{ language: string; code: string }> = ({ language, code }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy', err);
    }
  };

  return (
    <div className="my-3 rounded-lg overflow-hidden border border-slate-700/60 bg-[#0d131f] text-slate-100 shadow-md">
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#141d2e] border-b border-slate-700/50 text-xs">
        <div className="flex items-center space-x-2 text-cyan-400 font-mono font-medium">
          <Terminal className="w-3.5 h-3.5" />
          <span>{language.toUpperCase()}</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center space-x-1.5 px-2 py-1 rounded hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors cursor-pointer"
          title="Copy code"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-mono text-[11px]">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span className="font-mono text-[11px]">Copy</span>
            </>
          )}
        </button>
      </div>
      <div className="p-3.5 overflow-x-auto font-mono text-xs md:text-[13px] leading-relaxed text-slate-200">
        <pre className="m-0 whitespace-pre">{code}</pre>
      </div>
    </div>
  );
};

// Formats non-code markdown: headings, tables, blockquotes, lists, bold, inline code
const TextBlock: React.FC<{ text: string }> = ({ text }) => {
  const lines = text.split('\n');
  const renderedElements: React.ReactNode[] = [];
  let tableRows: string[] = [];
  let inTable = false;

  const flushTable = (key: number) => {
    if (tableRows.length > 0) {
      renderedElements.push(<MarkdownTable key={`tbl-${key}`} rows={[...tableRows]} />);
      tableRows = [];
    }
    inTable = false;
  };

  lines.forEach((line, idx) => {
    // Table detection: starts and ends with |
    const trimmed = line.trim();
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      inTable = true;
      tableRows.push(trimmed);
      return;
    } else if (inTable) {
      flushTable(idx);
    }

    // Headings
    if (trimmed.startsWith('### ')) {
      renderedElements.push(
        <h3 key={idx} className="text-base font-semibold text-app-primary mt-3 mb-1">
          {renderInline(trimmed.substring(4))}
        </h3>
      );
      return;
    }
    if (trimmed.startsWith('## ')) {
      renderedElements.push(
        <h2 key={idx} className="text-lg font-bold text-app-primary mt-4 mb-2 pb-1 border-b border-app">
          {renderInline(trimmed.substring(3))}
        </h2>
      );
      return;
    }
    if (trimmed.startsWith('# ')) {
      renderedElements.push(
        <h1 key={idx} className="text-xl font-extrabold text-app-primary mt-4 mb-2 pb-1 border-b border-app">
          {renderInline(trimmed.substring(2))}
        </h1>
      );
      return;
    }

    // Blockquote
    if (trimmed.startsWith('> ')) {
      renderedElements.push(
        <blockquote
          key={idx}
          className="border-l-3 border-cyan-500 pl-3 py-1 my-2 bg-cyan-500/5 text-app-secondary italic rounded-r text-sm"
        >
          {renderInline(trimmed.substring(2))}
        </blockquote>
      );
      return;
    }

    // Unordered List item
    if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      renderedElements.push(
        <div key={idx} className="flex items-start space-x-2 my-1 pl-2">
          <span className="text-cyan-500 mt-1.5">•</span>
          <span className="flex-1 text-app-secondary">{renderInline(trimmed.substring(2))}</span>
        </div>
      );
      return;
    }

    // Ordered List item (e.g. 1. )
    const olMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
    if (olMatch) {
      renderedElements.push(
        <div key={idx} className="flex items-start space-x-2 my-1 pl-2">
          <span className="text-cyan-500 font-mono text-xs mt-0.5">{olMatch[1]}.</span>
          <span className="flex-1 text-app-secondary">{renderInline(olMatch[2])}</span>
        </div>
      );
      return;
    }

    // Empty line
    if (!trimmed) {
      renderedElements.push(<div key={idx} className="h-2" />);
      return;
    }

    // Regular paragraph
    renderedElements.push(
      <p key={idx} className="my-1.5 text-app-secondary leading-relaxed">
        {renderInline(trimmed)}
      </p>
    );
  });

  if (inTable) {
    flushTable(lines.length);
  }

  return <>{renderedElements}</>;
};

// Render tables
const MarkdownTable: React.FC<{ rows: string[] }> = ({ rows }) => {
  if (rows.length < 2) return null;

  // Filter out divider row (e.g. |---|---|)
  const isDivider = (r: string) => /^\|(\s*:?-+:?\s*\|)+$/.test(r.trim());
  const headerRow = rows[0];
  const bodyRows = rows.slice(1).filter((r) => !isDivider(r));

  const splitCols = (r: string) =>
    r
      .split('|')
      .slice(1, -1)
      .map((c) => c.trim());

  const headers = splitCols(headerRow);

  return (
    <div className="my-3 overflow-x-auto rounded-lg border border-app shadow-xs">
      <table className="w-full text-left text-xs md:text-sm">
        <thead className="bg-surface text-app-primary border-b border-app">
          <tr>
            {headers.map((h, i) => (
              <th key={i} className="px-3 py-2 font-semibold">
                {renderInline(h)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-app">
          {bodyRows.map((r, rIdx) => {
            const cols = splitCols(r);
            return (
              <tr key={rIdx} className="hover:bg-card-hover transition-colors">
                {cols.map((c, cIdx) => (
                  <td key={cIdx} className="px-3 py-2 text-app-secondary">
                    {renderInline(c)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

// Helper for inline styles: bold, italic, inline code, links
function renderInline(text: string): React.ReactNode {
  if (!text) return '';

  // Tokenize inline code: `code`
  const codeRegex = /`([^`]+)`/g;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = codeRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(
        <span key={`txt-${key++}`}>{formatText(text.substring(lastIndex, match.index))}</span>
      );
    }
    parts.push(
      <code
        key={`code-${key++}`}
        className="px-1.5 py-0.5 rounded text-xs font-mono bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20"
      >
        {match[1]}
      </code>
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    parts.push(<span key={`txt-${key++}`}>{formatText(text.substring(lastIndex))}</span>);
  }

  return parts.length > 0 ? parts : text;
}

// Parses bold, italic, links inside text fragments
function formatText(chunk: string): React.ReactNode {
  // Bold: **text**
  // Italic: *text*
  // Link: [text](url)
  const regex = /(\*\*([^*]+)\*\*)|(\*([^*]+)\*)|(\[([^\]]+)\]\(([^)]+)\))/g;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let k = 0;

  while ((match = regex.exec(chunk)) !== null) {
    if (match.index > lastIndex) {
      parts.push(chunk.substring(lastIndex, match.index));
    }

    if (match[2]) {
      // Bold
      parts.push(
        <strong key={`b-${k++}`} className="font-semibold text-app-primary">
          {match[2]}
        </strong>
      );
    } else if (match[4]) {
      // Italic
      parts.push(
        <em key={`i-${k++}`} className="italic text-app-secondary">
          {match[4]}
        </em>
      );
    } else if (match[6] && match[7]) {
      // Link
      parts.push(
        <a
          key={`l-${k++}`}
          href={match[7]}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center space-x-0.5 text-cyan-600 dark:text-cyan-400 hover:underline"
        >
          <span>{match[6]}</span>
          <ExternalLink className="w-3 h-3 ml-0.5 inline" />
        </a>
      );
    }

    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < chunk.length) {
    parts.push(chunk.substring(lastIndex));
  }

  return parts.length > 0 ? parts : chunk;
}
