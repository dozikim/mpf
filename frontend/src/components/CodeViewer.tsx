// Read-only Monaco code viewer with MPF chrome: breadcrumb, file meta, and a
// download action. Monaco is themed to match the crimegpt palette so it never
// looks like a foreign widget dropped into MPF.
import Editor, { type OnMount } from "@monaco-editor/react";
import { useCallback } from "react";

import type { FileContent } from "../api/types";
import { formatBytes } from "./States";

// Register the MPF dark theme once, on first editor mount.
let themeDefined = false;

interface Props {
  file: FileContent | undefined;
  loading?: boolean;
  downloadHref?: string;
  line?: number;
  // Path segments to render as a breadcrumb (last one is highlighted as leaf).
  crumbs?: string[];
}

export function CodeViewer({ file, loading, downloadHref, line, crumbs }: Props) {
  const onMount: OnMount = useCallback((editor, monaco) => {
    if (!themeDefined) {
      monaco.editor.defineTheme("mpf-dark", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "", foreground: "ededed", background: "0d0d0d" },
        { token: "comment", foreground: "737373", fontStyle: "italic" },
        { token: "keyword", foreground: "e13d00" },
        { token: "string", foreground: "ff6b35" },
        { token: "number", foreground: "e0a800" },
        { token: "type", foreground: "ffb37a" },
      ],
      colors: {
        "editor.background": "#0d0d0d",
        "editor.foreground": "#ededed",
        "editorLineNumber.foreground": "#404040",
        "editorLineNumber.activeForeground": "#e13d00",
        "editor.selectionBackground": "#2a1408",
        "editor.lineHighlightBackground": "#141414",
        "editorCursor.foreground": "#e13d00",
        "editorGutter.background": "#0f0f0f",
        "editorIndentGuide.background1": "#1a1a1a",
        "editorWidget.background": "#0f0f0f",
        "editorWidget.border": "#262626",
        "input.background": "#1a1a1a",
        "focusBorder": "#e13d00",
      },
    });
      monaco.editor.setTheme("mpf-dark");
      themeDefined = true;
    }
    if (line && line > 0) {
      editor.revealLineInCenter(line);
      editor.setPosition({ lineNumber: line, column: 1 });
      editor.deltaDecorations([], [{ range: new monaco.Range(line, 1, line, 1), options: { isWholeLine: true, className: "source-line-hit" } }]);
    }
  }, [line]);

  const segs = crumbs ?? (file ? file.path.split("/") : []);

  return (
    <div className="browser" style={{ height: "100%" }}>
      <div className="code-head">
        <div className="breadcrumb">
          {segs.length === 0 && <span className="leaf">No file selected</span>}
          {segs.map((s, i) => (
            <span key={i}>
              {i > 0 && <span className="sep">/</span>}
              <span className={i === segs.length - 1 ? "leaf" : ""}>{s}</span>
            </span>
          ))}
        </div>
        {file && (
          <div className="code-meta">
            {file.language && <span>{file.language}</span>}
            {file.lines != null && <span>{file.lines} lines</span>}
            <span>{formatBytes(file.size)}</span>
            {file.truncated && <span style={{ color: "var(--high)" }}>truncated</span>}
          </div>
        )}
        {downloadHref && (
          <div className="code-actions">
            <a className="btn btn-sm" href={downloadHref} download>
              ↓ Download
            </a>
          </div>
        )}
      </div>
      <div className="code-body">
        {loading ? (
          <div className="state">Loading file…</div>
        ) : file ? (
          <Editor
            height="100%"
            theme="mpf-dark"
            path={`${file.path}:${line ?? 0}`}
            language={file.language ?? "plaintext"}
            value={file.content}
            onMount={onMount}
            options={{
              readOnly: true,
              domReadOnly: true,
              minimap: { enabled: true },
              fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
              fontSize: 12.5,
              lineHeight: 19,
              scrollBeyondLastLine: false,
              renderWhitespace: "none",
              wordWrap: "off",
              folding: true,
              smoothScrolling: true,
              cursorBlinking: "smooth",
              automaticLayout: true,
              contextmenu: false,
              renderLineHighlight: "all",
            }}
          />
        ) : (
          <div className="state state-empty" style={{ margin: 24 }}>
            Select a file from the tree to view its contents.
          </div>
        )}
      </div>
    </div>
  );
}
