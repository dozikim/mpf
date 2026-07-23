import { useParams } from "react-router-dom";

import { useBehaviours } from "../api/hooks";
import type { BehaviourOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { RiskTag } from "../components/States";
import { SourceLink } from "../components/SourceLink";

export function BehaviourPage() {
  const { id = "" } = useParams();
  const columns: Column<BehaviourOut>[] = [
    { key: "name", header: "BEHAVIOUR NAME", sortable: true, render: (r) => r.name },
    { key: "severity", header: "SEVERITY", sortable: true, render: (r) => <RiskTag value={r.severity} /> },
    { key: "description", header: "DESCRIPTION", render: (r) => r.description },
    { key: "java_file", header: "JAVA FILE", render: (r) => <span className="mono">{r.java_file ?? "—"}</span> },
    { key: "method_name", header: "METHOD NAME", render: (r) => <span className="mono">{r.method_name ?? "—"}</span> },
    { key: "line_number", header: "LINE NUMBER", render: (r) => r.line_number ?? "—" },
    { key: "source", header: "BUTTON", render: (r) => <SourceLink path={r.java_file} line={r.line_number} /> },
  ];
  return <DataTable title="BEHAVIOUR ANALYSIS" subtitle="Static behaviour detections stored after APK analysis." columns={columns} useData={(p) => useBehaviours(id, p)} defaultSort="severity" defaultOrder="desc" rowKey={(r) => r.id} />;
}
