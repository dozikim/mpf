// Files explorer. A flat, paginated, searchable index of every indexed file
// across all trees (java/smali/resources/root). Clicking a text file opens it
// in the generic file viewer route; any file can be downloaded. This is the
// VSCode-like "all files" view that complements the per-tree browsers.
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import { useFiles } from "../api/hooks";
import type { FileOut } from "../api/types";
import { Pager } from "../components/Pager";
import { SearchBar } from "../components/SearchBar";
import { BoolTag, EmptyState, ErrorState, LoadingState, formatBytes } from "../components/States";

const PAGE_SIZE = 100;
const TREES = ["", "java", "smali", "resources", "assets", "native", "databases"] as const;

export function FilesPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [tree, setTree] = useState<string>("");

  const { data, isLoading, error } = useFiles(id, {
    page,
    page_size: PAGE_SIZE,
    search: search || undefined,
    tree: tree || undefined,
    sort: "rel_path",
    order: "asc",
  });

  const openFile = (f: FileOut) => {
    if (f.is_text) {
      navigate(`/analysis/${id}/file?tree=${encodeURIComponent(f.tree)}&path=${encodeURIComponent(f.rel_path)}`);
    } else {
      window.open(api.downloadUrl(id, f.tree, f.rel_path), "_blank");
    }
  };

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>FILES</h1>
        <p>Every extracted and decompiled file, indexed and searchable.</p>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ maxWidth: 320, flex: 1 }}>
          <SearchBar
            placeholder="Filter by path…"
            onChange={(v) => {
              setSearch(v);
              setPage(1);
            }}
          />
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {TREES.map((t) => (
            <button
              key={t || "all"}
              className={`btn btn-sm${tree === t ? " btn-primary" : ""}`}
              onClick={() => {
                setTree(t);
                setPage(1);
              }}
            >
              {t || "all"}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState>No files match.</EmptyState>
      ) : (
        <>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Tree</th>
                  <th>Lang</th>
                  <th>Text</th>
                  <th style={{ textAlign: "right" }}>Size</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((f) => (
                  <tr key={f.id} className="clickable" onClick={() => openFile(f)}>
                    <td className="mono" style={{ wordBreak: "break-all" }}>{f.rel_path}</td>
                    <td className="mono">{f.tree}</td>
                    <td className="mono">{f.language ?? "—"}</td>
                    <td>
                      <BoolTag value={f.is_text} trueLabel="TEXT" falseLabel="BIN" />
                    </td>
                    <td className="mono" style={{ textAlign: "right" }}>{formatBytes(f.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
        </>
      )}
    </div>
  );
}
