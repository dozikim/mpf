// Permissions page. Lists every requested permission with its protection level
// and flags dangerous / custom permissions using the shared risk tags.
import { useParams } from "react-router-dom";

import { usePermissions } from "../api/hooks";
import type { PermissionOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { BoolTag } from "../components/States";

export function PermissionsPage() {
  const { id = "" } = useParams();

  const columns: Column<PermissionOut>[] = [
    { key: "name", header: "Permission", sortable: true, className: "mono", render: (p) => p.name },
    {
      key: "protection_level",
      header: "Protection",
      sortable: true,
      render: (p) => p.protection_level ?? "—",
    },
    {
      key: "is_dangerous",
      header: "Dangerous",
      render: (p) => <BoolTag value={p.is_dangerous} trueLabel="DANGEROUS" falseLabel="—" />,
    },
    {
      key: "is_custom",
      header: "Custom",
      render: (p) => <BoolTag value={p.is_custom} trueLabel="CUSTOM" falseLabel="—" />,
    },
    {
      key: "description",
      header: "Description",
      render: (p) => (
        <span style={{ color: "var(--muted)", fontSize: 12 }}>{p.description ?? "—"}</span>
      ),
    },
  ];

  return (
    <DataTable<PermissionOut>
      title="PERMISSIONS"
      subtitle="Permissions requested in the manifest, with protection levels."
      columns={columns}
      useData={(p) => usePermissions(id, p)}
      defaultSort="name"
      rowKey={(p) => p.id}
    />
  );
}
