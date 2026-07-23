// Components pages: Activities, Services, Receivers, Providers. All four share
// the same table shape (name / exported / risk) and a detail drawer that shows
// the full component record including intent filters. One implementation,
// parameterised by `kind` + the matching data hook.
import { useState } from "react";
import { useParams } from "react-router-dom";

import {
  useActivities,
  useProviders,
  useReceivers,
  useServices,
} from "../api/hooks";
import type { ComponentOut, Page, PageParams } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { Drawer, KV, Row } from "../components/Drawer";
import { BoolTag, RiskTag } from "../components/States";

type Hook = (id: string, p?: PageParams) => {
  data?: Page<ComponentOut>;
  isLoading: boolean;
  error: unknown;
};

const HOOKS: Record<string, { hook: Hook; title: string }> = {
  activities: { hook: useActivities, title: "Activities" },
  services: { hook: useServices, title: "Services" },
  receivers: { hook: useReceivers, title: "Receivers" },
  providers: { hook: useProviders, title: "Providers" },
};

export function ComponentsPage({ kind }: { kind: keyof typeof HOOKS }) {
  const { id = "" } = useParams();
  const [selected, setSelected] = useState<ComponentOut | null>(null);
  const { hook, title } = HOOKS[kind];

  const columns: Column<ComponentOut>[] = [
    {
      key: "name",
      header: "Name",
      sortable: true,
      className: "mono",
      render: (c) => shortName(c.name),
    },
    {
      key: "exported",
      header: "Exported",
      render: (c) => <BoolTag value={c.exported} trueLabel="EXPORTED" falseLabel="—" />,
    },
    {
      key: "permission",
      header: "Permission",
      className: "mono",
      render: (c) => (c.permission ? shortName(c.permission) : "—"),
    },
    ...(kind === "providers"
      ? [
          {
            key: "authorities",
            header: "Authorities",
            className: "mono",
            render: (c: ComponentOut) => c.authorities ?? "—",
          } as Column<ComponentOut>,
        ]
      : []),
    {
      key: "risk",
      header: "Risk",
      sortable: true,
      render: (c) => <RiskTag value={c.risk} />,
    },
  ];

  return (
    <>
      <DataTable<ComponentOut>
        title={title}
        subtitle={`Declared ${title.toLowerCase()} and their export/permission posture.`}
        columns={columns}
        useData={(p) => hook(id, p)}
        defaultSort="name"
        rowKey={(c) => c.id}
        onRowClick={setSelected}
      />
      {selected && (
        <Drawer
          title={shortName(selected.name)}
          subtitle={selected.name}
          onClose={() => setSelected(null)}
        >
          <KV>
            <Row label="Kind">{selected.kind}</Row>
            <Row label="Exported">
              <BoolTag value={selected.exported} trueLabel="EXPORTED" falseLabel="NO" />
            </Row>
            <Row label="Enabled">
              <BoolTag value={selected.enabled} />
            </Row>
            <Row label="Permission">{selected.permission ?? "—"}</Row>
            {selected.authorities && <Row label="Authorities">{selected.authorities}</Row>}
            {selected.grant_uri_permissions != null && (
              <Row label="Grant URI Perms">
                <BoolTag value={selected.grant_uri_permissions} />
              </Row>
            )}
            <Row label="Risk">
              <RiskTag value={selected.risk} />
            </Row>
            {selected.risk_reason && <Row label="Reason">{selected.risk_reason}</Row>}
          </KV>

          {selected.intent_filters && selected.intent_filters.length > 0 && (
            <>
              <h2 style={{ fontSize: 16, marginTop: 26 }}>Intent Filters</h2>
              {selected.intent_filters.map((f, i) => (
                <div key={i} className="card" style={{ marginTop: 12, padding: 14 }}>
                  {f.actions.length > 0 && (
                    <IntentRow label="Actions" values={f.actions} />
                  )}
                  {f.categories.length > 0 && (
                    <IntentRow label="Categories" values={f.categories} />
                  )}
                  {f.data.length > 0 && (
                    <div style={{ marginTop: 8 }}>
                      <div className="tile-label">Data</div>
                      {f.data.map((d, j) => (
                        <div key={j} className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                          {Object.entries(d)
                            .map(([k, v]) => `${k}=${v}`)
                            .join(" ")}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </Drawer>
      )}
    </>
  );
}

function IntentRow({ label, values }: { label: string; values: (string | null)[] }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div className="tile-label">{label}</div>
      {values.filter(Boolean).map((v, i) => (
        <div key={i} className="mono" style={{ fontSize: 11 }}>
          {v}
        </div>
      ))}
    </div>
  );
}

// Android names are fully-qualified; show the trailing segment for scanability.
function shortName(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot + 1) : name;
}
