// AndroidManifest.xml viewer. Left: a summary card of the security-relevant
// manifest attributes (debuggable, backup, cleartext, SDK levels). Right: the
// pretty-printed XML in the read-only Monaco viewer with a download action.
import { useParams } from "react-router-dom";

import { api } from "../api/client";
import { useManifest, useManifestSummary } from "../api/hooks";
import { CodeViewer } from "../components/CodeViewer";
import { BoolTag } from "../components/States";
import { ErrorState, LoadingState } from "../components/States";

export function ManifestPage() {
  const { id = "" } = useParams();
  const manifestQ = useManifest(id);
  const summaryQ = useManifestSummary(id);

  if (manifestQ.isLoading) return <LoadingState label="Loading manifest…" />;
  if (manifestQ.error) return <ErrorState error={manifestQ.error} />;

  const s = summaryQ.data;
  const downloadHref = api.downloadUrl(id, "manifest", "AndroidManifest.xml");
  const line = Number(new URLSearchParams(window.location.search).get("line") ?? 0) || undefined;

  return (
    <div className="browser" style={{ height: "100%" }}>
      <div className="browser-toolbar">
        <h1>MANIFEST</h1>
        {s?.package_name && <span className="breadcrumb">{s.package_name}</span>}
      </div>
      <div className="split" style={{ flex: 1, minHeight: 0 }}>
        <div className="split-left" style={{ width: 320, overflow: "auto" }}>
          <div style={{ padding: 20 }}>
            {summaryQ.isLoading ? (
              <LoadingState />
            ) : s ? (
              <dl className="kv" style={{ marginTop: 0 }}>
                <dt>Package</dt>
                <dd className="mono">{s.package_name ?? "—"}</dd>
                <dt>Version</dt>
                <dd className="mono">
                  {s.version_name ?? "—"} ({s.version_code ?? "?"})
                </dd>
                <dt>Min SDK</dt>
                <dd className="mono">{s.min_sdk ?? "—"}</dd>
                <dt>Target SDK</dt>
                <dd className="mono">{s.target_sdk ?? "—"}</dd>
                <dt>Compile SDK</dt>
                <dd className="mono">{s.compile_sdk ?? "—"}</dd>
                <dt>Debuggable</dt>
                <dd>
                  <BoolTag value={s.debuggable} trueLabel="DEBUGGABLE" falseLabel="NO" />
                </dd>
                <dt>Allow Backup</dt>
                <dd>
                  <BoolTag value={s.allow_backup} trueLabel="ALLOWED" falseLabel="NO" />
                </dd>
                <dt>Cleartext</dt>
                <dd>
                  <BoolTag value={s.uses_cleartext_traffic} trueLabel="ALLOWED" falseLabel="NO" />
                </dd>
                <dt>Net Sec Config</dt>
                <dd className="mono">{s.network_security_config ?? "—"}</dd>
              </dl>
            ) : (
              <div className="state state-empty">No manifest summary.</div>
            )}
          </div>
        </div>
        <div className="split-right">
          <CodeViewer file={manifestQ.data} downloadHref={downloadHref} crumbs={["AndroidManifest.xml"]} line={line} />
        </div>
      </div>
    </div>
  );
}
