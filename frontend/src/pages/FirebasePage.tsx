// Firebase page. Firebase/RTDB endpoints discovered during recon, flagged for
// public-readability where the pipeline could probe them.
import { useParams } from "react-router-dom";

import { useFirebase } from "../api/hooks";
import type { FirebaseOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { BoolTag } from "../components/States";

export function FirebasePage() {
  const { id = "" } = useParams();

  const columns: Column<FirebaseOut>[] = [
    {
      key: "url",
      header: "Endpoint",
      sortable: true,
      className: "mono",
      render: (f) => (
        <a href={f.url} target="_blank" rel="noreferrer">
          {f.url}
        </a>
      ),
    },
    { key: "kind", header: "Kind", render: (f) => f.kind ?? "—" },
    {
      key: "is_public",
      header: "Public",
      render: (f) => <BoolTag value={f.is_public} trueLabel="PUBLIC" falseLabel="—" />,
    },
    {
      key: "detail",
      header: "Detail",
      render: (f) => (
        <span style={{ color: "var(--muted)", fontSize: 12 }}>{f.detail ?? "—"}</span>
      ),
    },
  ];

  return (
    <DataTable<FirebaseOut>
      title="FIREBASE"
      subtitle="Firebase / realtime-database endpoints found in the app."
      columns={columns}
      useData={(p) => useFirebase(id, p)}
      rowKey={(f) => f.id}
    />
  );
}
