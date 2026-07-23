import { useParams } from "react-router-dom";

import { useApkid } from "../api/hooks";
import type { ApkidOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { RiskTag } from "../components/States";
import { SourceLink } from "../components/SourceLink";

export function ApkidPage() {
  const { id = "" } = useParams();
  const columns: Column<ApkidOut>[] = [
    { key: "category", header: "CATEGORY", sortable: true, render: (r) => r.category },
    { key: "value", header: "RESULT", sortable: true, render: (r) => <span className="mono">{r.value}</span> },
    { key: "detected", header: "STATUS", render: (r) => <RiskTag value={r.detected ? r.severity ?? "INFO" : "LOW"} /> },
    { key: "evidence", header: "EVIDENCE", render: (r) => r.evidence ?? "—" },
    { key: "file_path", header: "SOURCE", render: (r) => <SourceLink path={r.file_path} line={r.line_number} /> },
  ];
  return <DataTable title="APKID ANALYSIS" subtitle="Compiler, obfuscator, packer, framework and anti-analysis signatures." columns={columns} useData={(p) => useApkid(id, p)} defaultSort="category" rowKey={(r) => r.id} />;
}
