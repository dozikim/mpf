// Shared two-pane source browser used by the Java Source and Smali pages.
// Left: virtualized lazy tree + filename filter. Right: Monaco viewer.
// A content-search box swaps the tree for a hit list; clicking a hit opens the
// file at that line. Selected file is reflected in the URL (?path=) for deep
// linking, so a specific class is shareable/bookmarkable.
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import type { FileContent, SearchHit, TreeNode } from "../api/types";
import { CodeViewer } from "../components/CodeViewer";
import { SearchBar } from "../components/SearchBar";
import { SplitPane } from "../components/SplitPane";
import { ErrorState, LoadingState } from "../components/States";
import { TreeView, type TreeItem } from "../components/TreeView";
import { useQuery } from "@tanstack/react-query";

interface Props {
  analysisId: string;
  tree: string;
  title: string;
}

export function FileBrowser({ analysisId, tree, title }: Props) {
  const [params, setParams] = useSearchParams();
  const selectedPath = params.get("path") ?? undefined;
  const selectedLine = Number(params.get("line") ?? 0) || undefined;
  const [filter, setFilter] = useState("");
  const [query, setQuery] = useState("");

  // Root of the tree (lazy — children fetched per-directory on expand).
  const rootQ = useQuery({
    queryKey: ["browser-root", analysisId, tree],
    queryFn: () => api.tree(analysisId, tree),
  });

  // Selected file contents.
  const fileQ = useQuery({
    queryKey: ["browser-file", analysisId, tree, selectedPath],
    queryFn: () => api.file(analysisId, tree, selectedPath as string),
    enabled: !!selectedPath,
  });

  // Content search (grep) — only runs when a query is submitted.
  const searchQ = useQuery({
    queryKey: ["browser-search", analysisId, tree, query],
    queryFn: () => api.search(analysisId, query, tree),
    enabled: query.length >= 2,
  });

  const loadChildren = useCallback(
    (path: string) => api.tree(analysisId, tree, path),
    [analysisId, tree]
  );

  const selectFile = useCallback(
    (path: string, line?: number) => {
      const next = new URLSearchParams(params);
      next.set("path", path);
      if (line) next.set("line", String(line));
      else next.delete("line");
      setParams(next, { replace: true });
    },
    [params, setParams]
  );

  const onSelectFile = useCallback(
    (path: string, _node: TreeItem) => selectFile(path),
    [selectFile]
  );

  const downloadHref = selectedPath
    ? api.downloadUrl(analysisId, tree, selectedPath)
    : undefined;

  const roots: TreeNode[] = rootQ.data ?? [];

  const searching = query.length >= 2;

  const left = (
    <div className="browser">
      <div className="browser-toolbar">
        <SearchBar
          placeholder="Filter filenames…"
          onChange={setFilter}
          onSubmit={(v) => setQuery(v)}
        />
      </div>
      <div className="browser-toolbar" style={{ paddingTop: 0, borderBottom: "1px solid var(--border)" }}>
        <SearchBar
          placeholder="Search in files (⏎)…"
          delay={9e9}
          onChange={() => {}}
          onSubmit={(v) => setQuery(v)}
        />
        {searching && (
          <button className="btn btn-sm" onClick={() => setQuery("")}>
            ✕ Clear
          </button>
        )}
      </div>
      {searching ? (
        <SearchResults
          query={searchQ.data}
          loading={searchQ.isLoading}
          error={searchQ.error}
          onOpen={(hit) => selectFile(hit.path, hit.line_number)}
        />
      ) : rootQ.isLoading ? (
        <LoadingState label="Loading tree…" />
      ) : rootQ.error ? (
        <ErrorState error={rootQ.error} />
      ) : (
        <TreeView
          roots={roots}
          selectedPath={selectedPath}
          onSelectFile={onSelectFile}
          loadChildren={loadChildren}
          filter={filter}
        />
      )}
    </div>
  );

  const right = (
    <CodeViewer
      file={fileQ.data as FileContent | undefined}
      loading={fileQ.isFetching && !!selectedPath}
      downloadHref={downloadHref}
      line={selectedLine}
    />
  );

  return (
    <div className="browser" style={{ height: "100%" }}>
      <div className="browser-toolbar">
        <h1>{title}</h1>
        {selectedPath && <span className="breadcrumb">{selectedPath}</span>}
      </div>
      <SplitPane left={left} right={right} />
    </div>
  );
}

function SearchResults({
  query,
  loading,
  error,
  onOpen,
}: {
  query: SearchHit[] | undefined;
  loading: boolean;
  error: unknown;
  onOpen: (hit: SearchHit) => void;
}) {
  if (loading) return <LoadingState label="Searching…" />;
  if (error) return <ErrorState error={error} />;
  const hits = query ?? [];
  if (!hits.length) return <div className="state state-empty">No matches.</div>;
  return (
    <div className="search-results">
      {hits.map((h, i) => (
        <div key={`${h.path}:${h.line_number}:${i}`} className="search-hit" onClick={() => onOpen(h)}>
          <div className="search-hit-path">
            {h.path.split("/").slice(0, -1).join("/")}
            {h.path.includes("/") && "/"}
            <span className="leaf">{h.name}</span>
          </div>
          <div className="search-hit-line">
            <span className="lineno">{h.line_number}</span>
            {h.line.trim().slice(0, 200)}
          </div>
        </div>
      ))}
    </div>
  );
}
