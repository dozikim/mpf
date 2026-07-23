import { useParams } from "react-router-dom";

import { useAbusedPermissions } from "../api/hooks";
import type { AbusedPermissionOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { BoolTag, RiskTag } from "../components/States";
import { SourceLink } from "../components/SourceLink";

function firstFile(files: string | null): string | null {
  if (!files) return null;
  try { return JSON.parse(files)[0] ?? null; } catch { return null; }
}

export function AbusedPermissionsPage() {
  const { id = "" } = useParams();
  const columns: Column<AbusedPermissionOut>[] = [
    { key: "permission", header: "PERMISSION", sortable: true, className: "mono", render: (r) => r.permission },
    { key: "category", header: "CATEGORY", sortable: true, render: (r) => r.category },
    { key: "risk_level", header: "RISK LEVEL", sortable: true, render: (r) => <RiskTag value={r.risk_level} /> },
    { key: "description", header: "DESCRIPTION", render: (r) => r.description ?? "—" },
    { key: "dangerous_reason", header: "WHY IT IS DANGEROUS", render: (r) => r.dangerous_reason ?? "—" },
    { key: "malware_usage", header: "COMMON MALWARE USAGE", render: (r) => r.malware_usage ?? "—" },
    { key: "used_in_code", header: "USED INSIDE CODE", render: (r) => <BoolTag value={r.used_in_code} trueLabel="USED" falseLabel="NO" /> },
    { key: "files", header: "FILES USING THE PERMISSION", render: (r) => <SourceLink path={firstFile(r.files)} /> },
  ];
  return <DataTable title="ABUSED PERMISSIONS" subtitle="Permissions categorized by malware, dangerous, signature, normal and common usage." columns={columns} useData={(p) => useAbusedPermissions(id, p)} defaultSort="risk_level" defaultOrder="desc" rowKey={(r) => r.id} />;
}
