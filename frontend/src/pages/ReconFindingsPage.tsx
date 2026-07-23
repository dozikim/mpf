import { useParams } from "react-router-dom";

import { useReconFindings } from "../api/hooks";
import type { ReconFindingOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { RiskTag } from "../components/States";
import { SourceLink } from "../components/SourceLink";

const TITLES: Record<string, string> = { url: "URLS", email: "EMAILS", domain: "DOMAINS", ip: "IPS", firebase: "FIREBASE" };

export function ReconFindingsPage({ kind }: { kind: string }) {
  const { id = "" } = useParams();
  const columns: Column<ReconFindingOut>[] = [
    { key: "value", header: kind === "url" ? "URL" : kind.toUpperCase(), sortable: true, className: "mono", render: (r) => r.value },
    { key: "protocol", header: "PROTOCOL", render: (r) => r.protocol ?? "—" },
    { key: "indicator_type", header: "TYPE", sortable: true, render: (r) => r.indicator_type ?? r.kind },
    { key: "file_path", header: "JAVA FILE", render: (r) => <span className="mono">{r.file_path ?? "—"}</span> },
    { key: "line_number", header: "LINE NUMBER", render: (r) => r.line_number ?? "—" },
    { key: "method_name", header: "METHOD", render: (r) => <span className="mono">{r.method_name ?? "—"}</span> },
    { key: "risk", header: "RISK", render: (r) => <RiskTag value={r.risk} /> },
    { key: "context", header: "CONTEXT", render: (r) => r.context ?? "—" },
    { key: "source", header: "SOURCE", render: (r) => <SourceLink path={r.file_path} line={r.line_number} /> },
  ];
  return <DataTable title={TITLES[kind] ?? kind.toUpperCase()} subtitle="Extracted indicators with file, method, line and source navigation." columns={columns} useData={(p) => useReconFindings(id, p, kind)} defaultSort="value" rowKey={(r) => r.id} />;
}
