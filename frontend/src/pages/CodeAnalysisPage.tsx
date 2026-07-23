import { useParams } from "react-router-dom";

import { useCodeAnalysis } from "../api/hooks";
import type { CodeFindingOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { RiskTag } from "../components/States";
import { SourceLink } from "../components/SourceLink";

export function CodeAnalysisPage() {
  const { id = "" } = useParams();
  const columns: Column<CodeFindingOut>[] = [
    { key: "id", header: "#", sortable: true, render: (r) => r.id },
    { key: "issue", header: "ISSUE", sortable: true, render: (r) => r.issue },
    { key: "severity", header: "SEVERITY", sortable: true, render: (r) => <RiskTag value={r.severity} /> },
    { key: "description", header: "DESCRIPTION", render: (r) => r.description },
    { key: "cwe", header: "CWE", render: (r) => r.cwe ?? "—" },
    { key: "owasp", header: "OWASP", render: (r) => r.owasp ?? "—" },
    { key: "masvs", header: "MASVS", render: (r) => r.masvs ?? "—" },
    { key: "java_file", header: "JAVA FILE", render: (r) => <SourceLink path={r.java_file} line={r.line_number} label={r.java_file ?? "—"} /> },
    { key: "line_number", header: "LINE NUMBER", render: (r) => r.line_number ?? "—" },
    { key: "category", header: "CATEGORY", sortable: true, render: (r) => r.category },
    { key: "recommendation", header: "RECOMMENDATION", render: (r) => r.recommendation ?? "—" },
    { key: "status", header: "STATUS", sortable: true, render: (r) => r.status.toUpperCase() },
  ];
  return <DataTable title="CODE ANALYSIS" subtitle="Stored static code findings across decompiled Java and resources." columns={columns} useData={(p) => useCodeAnalysis(id, p)} defaultSort="severity" defaultOrder="desc" rowKey={(r) => r.id} />;
}
