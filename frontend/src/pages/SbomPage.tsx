// SBOM page. Software bill of materials — every detected component with its
// package URL (purl), version and license, for supply-chain review.
import { useParams } from "react-router-dom";

import { useSbom } from "../api/hooks";
import type { SBOMOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";

export function SbomPage() {
  const { id = "" } = useParams();

  const columns: Column<SBOMOut>[] = [
    { key: "name", header: "Component", sortable: true, className: "mono", render: (s) => s.name },
    { key: "kind", header: "Kind", sortable: true, render: (s) => s.kind ?? "—" },
    { key: "version", header: "Version", className: "mono", render: (s) => s.version ?? "—" },
    { key: "license", header: "License", render: (s) => s.license ?? "—" },
    {
      key: "purl",
      header: "PURL",
      className: "mono",
      render: (s) => (
        <span style={{ color: "var(--muted)", fontSize: 11 }}>{s.purl ?? "—"}</span>
      ),
    },
  ];

  return (
    <DataTable<SBOMOut>
      title="SBOM"
      subtitle="Software bill of materials assembled from detected components."
      columns={columns}
      useData={(p) => useSbom(id, p)}
      defaultSort="name"
      rowKey={(s) => s.id}
    />
  );
}
