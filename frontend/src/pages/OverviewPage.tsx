import { Link, useParams } from "react-router-dom";

import { useAnalysis, useManifestSummary, useOverviewSecurity } from "../api/hooks";
import { BoolTag, ErrorState, LoadingState, RiskTag, formatBytes } from "../components/States";

const COUNT_TILES: { key: string; label: string; to: string }[] = [
  { key: "activities", label: "ACTIVITIES", to: "activities" },
  { key: "services", label: "SERVICES", to: "services" },
  { key: "receivers", label: "RECEIVERS", to: "receivers" },
  { key: "providers", label: "PROVIDERS", to: "providers" },
  { key: "permissions", label: "PERMISSIONS", to: "permissions" },
  { key: "libraries", label: "LIBRARIES", to: "libraries" },
  { key: "java_files", label: "JAVA FILES", to: "java" },
  { key: "smali_files", label: "SMALI FILES", to: "smali" },
  { key: "certificates", label: "CERTIFICATES", to: "certificates" },
  { key: "firebase", label: "FIREBASE", to: "firebase" },
  { key: "malware", label: "MALWARE", to: "malware" },
  { key: "files", label: "FILES", to: "files" },
];

export function OverviewPage() {
  const { id = "" } = useParams();
  const { data, isLoading, error } = useAnalysis(id);
  const manifestQ = useManifestSummary(id);
  const securityQ = useOverviewSecurity(id);

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!data) return null;

  const counts = data.counts ?? {};
  const running = data.status === "pending" || data.status === "running";
  const m = manifestQ.data;
  const sec = securityQ.data;
  const chart = sec?.static_analysis_summary ?? {};

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>OVERVIEW</h1>
        <p className="mono">{data.app_name ?? data.file_name} · {data.package_name ?? "package unknown"}</p>
      </div>

      {running && (
        <div className="card">
          <h2>ANALYZING</h2>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, fontFamily: "var(--font-mono)", fontSize: 12 }}>
            <span>{data.current_stage ?? "queued"}</span>
            <span>{data.progress}%</span>
          </div>
          <div className="progress-bar"><span style={{ width: `${data.progress}%` }} /></div>
        </div>
      )}

      {data.status === "failed" && (
        <div className="card" style={{ borderColor: "var(--critical)" }}>
          <h2 style={{ color: "var(--critical)" }}>ANALYSIS FAILED</h2>
          <div className="mono" style={{ fontSize: 12 }}>{data.error ?? "Unknown error."}</div>
        </div>
      )}

      {sec && (
        <div className="tiles">
          <div className="tile"><span className="tile-label">SECURITY SCORE</span><span className="tile-value">{sec.security_score}</span></div>
          <div className="tile"><span className="tile-label">TRACKER SCORE</span><span className="tile-value">{sec.tracker_score}</span></div>
          <div className="tile"><span className="tile-label">OVERALL RISK</span><span className="tile-value"><RiskTag value={sec.overall_risk_level} /></span></div>
          <div className="tile"><span className="tile-label">DANGEROUS PERMISSIONS</span><span className="tile-value">{sec.dangerous_permissions_count}</span></div>
        </div>
      )}

      <div className="card">
        <h2>APPLICATION</h2>
        <dl className="kv" style={{ marginTop: 0 }}>
          <dt>PACKAGE NAME</dt><dd className="mono">{data.package_name ?? "—"}</dd>
          <dt>VERSION</dt><dd className="mono">{data.version_name ?? "—"} ({data.version_code ?? "?"})</dd>
          <dt>TARGET SDK</dt><dd className="mono">{data.target_sdk ?? "—"}</dd>
          <dt>MINIMUM SDK</dt><dd className="mono">{data.min_sdk ?? "—"}</dd>
          <dt>COMPILE SDK</dt><dd className="mono">{m?.compile_sdk ?? "—"}</dd>
          <dt>FILE SIZE</dt><dd className="mono">{formatBytes(data.file_size)}</dd>
          <dt>MD5</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{data.md5 ?? "—"}</dd>
          <dt>SHA1</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{data.sha1 ?? "—"}</dd>
          <dt>SHA256</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{data.sha256 ?? "—"}</dd>
        </dl>
      </div>

      <div className="tiles">
        {COUNT_TILES.map((t) => (
          <Link key={t.key} to={`/analysis/${id}/${t.to}`} className="tile" style={{ textDecoration: "none", color: "inherit" }}>
            <span className="tile-label">{t.label}</span>
            <span className="tile-value">{counts[t.key] ?? 0}</span>
          </Link>
        ))}
      </div>

      {m && (
        <div className="card">
          <h2>SECURITY POSTURE</h2>
          <dl className="kv" style={{ marginTop: 0 }}>
            <dt>CERTIFICATE INFO</dt><dd className="mono">{counts.certificates ?? 0} signing certificate records</dd>
            <dt>SIGNATURE INFO</dt><dd className="mono"><Link to={`/analysis/${id}/certificates`}>OPEN CERTIFICATES</Link></dd>
            <dt>DEBUGGABLE</dt><dd><BoolTag value={m.debuggable} trueLabel="DEBUGGABLE" falseLabel="NO" /></dd>
            <dt>BACKUP ENABLED</dt><dd><BoolTag value={m.allow_backup} trueLabel="ALLOWED" falseLabel="NO" /></dd>
            <dt>EXPORTED COMPONENTS COUNT</dt><dd className="mono">{sec?.exported_components_count ?? "—"}</dd>
            <dt>NATIVE LIBRARIES COUNT</dt><dd className="mono">{sec?.native_libraries_count ?? counts.native_libraries ?? 0}</dd>
          </dl>
        </div>
      )}

      {sec && (
        <div className="card">
          <h2>STATIC ANALYSIS SUMMARY</h2>
          <div className="tiles" style={{ marginBottom: 16 }}>
            {(["HIGH", "WARNING", "LOW", "INFO"] as const).map((k) => (
              <div className="tile" key={k}><span className="tile-label">{k === "WARNING" ? "MEDIUM" : k}</span><span className="tile-value">{chart[k] ?? 0}</span></div>
            ))}
          </div>
          <dl className="kv" style={{ marginTop: 0 }}>
            <dt>DETECTED TRACKERS</dt><dd>{sec.detected_trackers.join(", ") || "—"}</dd>
            <dt>DETECTED THIRD-PARTY SDKS</dt><dd>{sec.detected_third_party_sdks.slice(0, 20).join(", ") || "—"}</dd>
            <dt>MALWARE INDICATORS</dt><dd>{sec.malware_indicators.join(", ") || "—"}</dd>
            <dt>SECURITY SUMMARY</dt><dd>{sec.security_summary.join(" ")}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}
