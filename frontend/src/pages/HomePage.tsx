// Home / dashboard. Drag-and-drop (or click) APK upload with live progress, and
// a table of previous analyses. Uploading navigates straight to the new
// analysis's overview, where the pipeline progress bar takes over. Mirrors the
// crimegpt landing aesthetic: serif italic headline, mono labels, sharp border.
import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useAnalyses, useDeleteAnalysis, useUpload } from "../api/hooks";
import type { AnalysisSummary } from "../api/types";
import { EmptyState, ErrorState, LoadingState, formatBytes } from "../components/States";

export function HomePage() {
  const navigate = useNavigate();
  const upload = useUpload();
  const del = useDeleteAnalysis();
  const { data, isLoading, error } = useAnalyses({ page: 1, page_size: 50, sort: "created_at", order: "desc" });
  const [progress, setProgress] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const doUpload = useCallback(
    (file: File) => {
      setProgress(0);
      upload.mutate(
        { file, onProgress: setProgress },
        {
          onSuccess: (res) => {
            setProgress(null);
            navigate(`/analysis/${res.id}/overview`);
          },
          onError: () => setProgress(null),
        }
      );
    },
    [navigate, upload]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) doUpload(file);
    },
    [doUpload]
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="logo">▚ MPF</span>
          <span className="tagline">Mobile Pentest Framework · RE Console</span>
        </div>
      </header>

      <div className="content">
        <div className="content-pad" style={{ maxWidth: 1000, margin: "0 auto" }}>
          <div className="page-head" style={{ marginTop: 20 }}>
            <h1>Static Analysis</h1>
            <p>Upload an Android APK to decompile, index and inspect every artifact.</p>
          </div>

          {/* Dropzone */}
          <div
            className="card"
            style={{
              borderStyle: "dashed",
              borderColor: dragging ? "var(--accent)" : "var(--border)",
              textAlign: "center",
              padding: 48,
              cursor: "pointer",
              transition: "border-color 0.15s",
            }}
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".apk,.xapk,.apks,application/vnd.android.package-archive"
              style={{ display: "none" }}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) doUpload(f);
                e.target.value = "";
              }}
            />
            {progress !== null ? (
              <>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, marginBottom: 12 }}>
                  Uploading… {progress}%
                </div>
                <div className="progress-bar" style={{ maxWidth: 400, margin: "0 auto" }}>
                  <span style={{ width: `${progress}%` }} />
                </div>
              </>
            ) : (
              <>
                <div style={{ fontFamily: "var(--font-serif)", fontStyle: "italic", fontSize: 24, marginBottom: 8 }}>
                  Drop an APK here
                </div>
                <div style={{ color: "var(--muted)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
                  or click to browse · .apk / .xapk / .apks
                </div>
              </>
            )}
          </div>

          {upload.error && <ErrorState error={upload.error} />}

          {/* Prior analyses */}
          <div className="page-head" style={{ marginTop: 32 }}>
            <h1 style={{ fontSize: 22 }}>Recent Analyses</h1>
          </div>
          {isLoading ? (
            <LoadingState />
          ) : error ? (
            <ErrorState error={error} />
          ) : !data || data.items.length === 0 ? (
            <EmptyState>No analyses yet. Upload an APK to begin.</EmptyState>
          ) : (
            <div className="card" style={{ padding: 0 }}>
              <table>
                <thead>
                  <tr>
                    <th>App</th>
                    <th>Package</th>
                    <th>Size</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((a) => (
                    <AnalysisRow
                      key={a.id}
                      a={a}
                      onOpen={() => navigate(`/analysis/${a.id}/overview`)}
                      onDelete={() => del.mutate(a.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AnalysisRow({
  a,
  onOpen,
  onDelete,
}: {
  a: AnalysisSummary;
  onOpen: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="clickable" onClick={onOpen}>
      <td>{a.app_name ?? a.file_name}</td>
      <td className="mono" style={{ fontSize: 12 }}>{a.package_name ?? "—"}</td>
      <td className="mono">{formatBytes(a.file_size)}</td>
      <td>
        <StatusTag status={a.status} progress={a.progress} />
      </td>
      <td className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
        {new Date(a.created_at).toLocaleString()}
      </td>
      <td style={{ textAlign: "right" }}>
        <button
          className="btn btn-sm"
          onClick={(e) => {
            e.stopPropagation();
            if (confirm("Delete this analysis and all its artifacts?")) onDelete();
          }}
        >
          Delete
        </button>
      </td>
    </tr>
  );
}

function StatusTag({ status, progress }: { status: AnalysisSummary["status"]; progress: number }) {
  const map: Record<AnalysisSummary["status"], string> = {
    pending: "tag-muted",
    running: "tag-medium",
    completed: "tag-low",
    failed: "tag-critical",
  };
  return (
    <span className={`tag ${map[status]}`}>
      {status === "running" ? `${progress}%` : status.toUpperCase()}
    </span>
  );
}
