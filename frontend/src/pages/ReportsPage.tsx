// Reports page. Composes the loaded analysis data into a downloadable JSON
// report and offers an HTML/print export (browser print-to-PDF). This keeps
// reporting fully functional in the vertical slice without a dedicated report
// service; a server-side PDF renderer can slot in behind the same UI later.
import { useParams } from "react-router-dom";

import { useAnalysis, useCertificates, useManifestSummary } from "../api/hooks";
import { ErrorState, LoadingState } from "../components/States";

export function ReportsPage() {
  const { id = "" } = useParams();
  const analysisQ = useAnalysis(id);
  const manifestQ = useManifestSummary(id);
  const certsQ = useCertificates(id);

  if (analysisQ.isLoading) return <LoadingState />;
  if (analysisQ.error) return <ErrorState error={analysisQ.error} />;
  const a = analysisQ.data;
  if (!a) return null;

  const buildReport = () => ({
    generated_at: new Date().toISOString(),
    analysis: a,
    manifest: manifestQ.data ?? null,
    certificates: certsQ.data ?? [],
  });

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(buildReport(), null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `mpf-report-${a.package_name ?? a.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>REPORTS</h1>
        <p>Export the analysis findings as JSON, or print to PDF.</p>
      </div>

      <div className="card">
        <h2>Export</h2>
        <div style={{ display: "flex", gap: 12 }}>
          <button className="btn btn-primary" onClick={downloadJson}>
            ↓ Download JSON
          </button>
          <button className="btn" onClick={() => window.print()}>
            ⎙ Print / PDF
          </button>
        </div>
      </div>

      <div className="card">
        <h2>Summary</h2>
        <dl className="kv" style={{ marginTop: 0 }}>
          <dt>Package</dt>
          <dd className="mono">{a.package_name ?? "—"}</dd>
          <dt>Version</dt>
          <dd className="mono">{a.version_name ?? "—"} ({a.version_code ?? "?"})</dd>
          <dt>SHA-256</dt>
          <dd className="mono" style={{ wordBreak: "break-all" }}>{a.sha256 ?? "—"}</dd>
          <dt>Status</dt>
          <dd className="mono">{a.status.toUpperCase()}</dd>
        </dl>
      </div>

      <div className="tiles">
        {Object.entries(a.counts ?? {}).map(([k, v]) => (
          <div key={k} className="tile">
            <span className="tile-label">{k.replace(/_/g, " ")}</span>
            <span className="tile-value">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
