// Global content search across all decompiled trees. Submits the grep-backed
// search endpoint and groups hits by file; clicking a hit opens the generic
// file viewer at that path. This is the cross-tree counterpart to the in-pane
// search inside the Java/Smali browsers.
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import { useQuery } from "@tanstack/react-query";
import { SearchBar } from "../components/SearchBar";
import { EmptyState, ErrorState, LoadingState } from "../components/States";

export function SearchPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  const { data, isLoading, error, isFetched } = useQuery({
    queryKey: ["global-search", id, query],
    queryFn: () => api.search(id, query),
    enabled: query.length >= 2,
  });

  const open = (tree: string, path: string) =>
    navigate(`/analysis/${id}/file?tree=${encodeURIComponent(tree)}&path=${encodeURIComponent(path)}`);

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>GLOBAL SEARCH</h1>
        <p>Full-text search across Java, Smali and resource files.</p>
      </div>

      <div style={{ maxWidth: 480, marginBottom: 20 }}>
        <SearchBar
          placeholder="Search all files (⏎)…"
          delay={9e9}
          onChange={() => {}}
          onSubmit={setQuery}
        />
      </div>

      {query.length < 2 ? (
        <EmptyState>Type at least 2 characters and press Enter.</EmptyState>
      ) : isLoading ? (
        <LoadingState label="Searching…" />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.length === 0 ? (
        isFetched ? <EmptyState>No matches for “{query}”.</EmptyState> : null
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="search-results">
            {data.map((h, i) => (
              <div key={`${h.tree}:${h.path}:${h.line_number}:${i}`} className="search-hit" onClick={() => open(h.tree, h.path)}>
                <div className="search-hit-path">
                  <span className="tag tag-muted" style={{ marginRight: 8 }}>{h.tree}</span>
                  {h.path.split("/").slice(0, -1).join("/")}
                  {h.path.includes("/") && "/"}
                  <span className="leaf">{h.name}</span>
                </div>
                <div className="search-hit-line">
                  <span className="lineno">{h.line_number}</span>
                  {h.line.trim().slice(0, 240)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
