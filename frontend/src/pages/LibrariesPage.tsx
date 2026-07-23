// Libraries page. Third-party libraries detected from package paths, with the
// category (UI, networking, analytics…) and any risk classification.
import { useParams } from "react-router-dom";

import { useLibraries } from "../api/hooks";
import type { LibraryOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { RiskTag } from "../components/States";

export function LibrariesPage() {
  const { id = "" } = useParams();

  const columns: Column<LibraryOut>[] = [
    { key: "name", header: "Library", sortable: true, className: "mono", render: (l) => l.name },
    { key: "category", header: "Category", sortable: true, render: (l) => l.category ?? "—" },
    { key: "version", header: "Version", className: "mono", render: (l) => l.version ?? "—" },
    { key: "license", header: "License", render: (l) => l.license ?? "—" },
    { key: "risk", header: "Risk", sortable: true, render: (l) => <RiskTag value={l.risk} /> },
    {
      key: "evidence",
      header: "Evidence",
      className: "mono",
      render: (l) => (
        <span style={{ color: "var(--muted)", fontSize: 11 }}>{l.evidence ?? "—"}</span>
      ),
    },
  ];

  return (
    <DataTable<LibraryOut>
      title="LIBRARIES"
      subtitle="Third-party libraries detected from package signatures."
      columns={columns}
      useData={(p) => useLibraries(id, p)}
      defaultSort="name"
      rowKey={(l) => l.id}
    />
  );
}
