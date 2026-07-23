// Reconnaissance page. The recon endpoint returns grouped indicator lists
// (urls / domains / ips / emails / firebase). This one component renders any
// single group, parameterised by `kind`, so the sidebar's Domains/URLs/IPs
// routes all reuse it. Client-side filter over the (already in-memory) list.
import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { useRecon } from "../api/hooks";
import type { ReconIndicators } from "../api/types";
import { SearchBar } from "../components/SearchBar";
import { EmptyState, ErrorState, LoadingState } from "../components/States";

type Kind = keyof ReconIndicators;

const META: Record<Kind, { title: string; subtitle: string }> = {
  urls: { title: "URLs", subtitle: "Absolute URLs referenced anywhere in the app." },
  domains: { title: "Domains", subtitle: "Distinct hostnames extracted from URLs and strings." },
  ips: { title: "IP Addresses", subtitle: "Hard-coded IPv4/IPv6 literals." },
  emails: { title: "Emails", subtitle: "Email addresses found in code and resources." },
  firebase: { title: "Firebase", subtitle: "Firebase endpoints referenced by the app." },
};

export function ReconPage({ kind }: { kind: Kind }) {
  const { id = "" } = useParams();
  const { data, isLoading, error } = useRecon(id);
  const [filter, setFilter] = useState("");

  const items = useMemo(() => {
    const list = data?.[kind] ?? [];
    const needle = filter.trim().toLowerCase();
    return needle ? list.filter((x) => x.toLowerCase().includes(needle)) : list;
  }, [data, kind, filter]);

  const meta = META[kind];

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>{meta.title}</h1>
        <p>{meta.subtitle}</p>
      </div>

      {isLoading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState error={error} />
      ) : (
        <>
          <div style={{ marginBottom: 16, maxWidth: 320, display: "flex", gap: 12, alignItems: "center" }}>
            <SearchBar placeholder="Filter…" onChange={setFilter} />
            <span style={{ color: "var(--muted)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
              {items.length} / {(data?.[kind] ?? []).length}
            </span>
          </div>
          {items.length === 0 ? (
            <EmptyState>No {meta.title.toLowerCase()} found.</EmptyState>
          ) : (
            <div className="card" style={{ padding: 0 }}>
              <table>
                <tbody>
                  {items.map((x, i) => (
                    <tr key={i}>
                      <td className="mono" style={{ wordBreak: "break-all" }}>
                        {isLinkable(kind) ? (
                          <a href={normalize(x)} target="_blank" rel="noreferrer">
                            {x}
                          </a>
                        ) : (
                          x
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function isLinkable(kind: Kind): boolean {
  return kind === "urls" || kind === "domains" || kind === "firebase";
}

function normalize(value: string): string {
  return /^https?:\/\//i.test(value) ? value : `https://${value}`;
}
