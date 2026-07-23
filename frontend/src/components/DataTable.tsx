// Generic paginated, searchable, sortable table backed by a TanStack Query
// hook that returns a Page<T>. Keeps every list page (components, permissions,
// libraries, SBOM, firebase, malware…) consistent with one implementation.
import { useState, type ReactNode } from "react";

import type { Page, PageParams } from "../api/types";
import { Pager } from "./Pager";
import { SearchBar } from "./SearchBar";
import { EmptyState, ErrorState, LoadingState } from "./States";

export interface Column<T> {
  key: string;
  header: string;
  sortable?: boolean;
  render: (row: T) => ReactNode;
  className?: string;
}

interface Props<T> {
  title: string;
  subtitle?: string;
  columns: Column<T>[];
  // Called with current page params; must return a TanStack Query result-like.
  useData: (p: PageParams) => {
    data?: Page<T>;
    isLoading: boolean;
    error: unknown;
  };
  searchable?: boolean;
  defaultSort?: string;
  defaultOrder?: "asc" | "desc";
  pageSize?: number;
  onRowClick?: (row: T) => void;
  rowKey: (row: T) => string | number;
}

export function DataTable<T>({
  title,
  subtitle,
  columns,
  useData,
  searchable = true,
  defaultSort,
  defaultOrder = "asc",
  pageSize = 50,
  onRowClick,
  rowKey,
}: Props<T>) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<string | undefined>(defaultSort);
  const [order, setOrder] = useState<"asc" | "desc">(defaultOrder);

  const { data, isLoading, error } = useData({
    page,
    page_size: pageSize,
    search: search || undefined,
    sort,
    order,
  });

  const toggleSort = (key: string) => {
    if (sort === key) {
      setOrder((o) => (o === "asc" ? "desc" : "asc"));
    } else {
      setSort(key);
      setOrder("asc");
    }
    setPage(1);
  };

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>

      {searchable && (
        <div style={{ marginBottom: 16, maxWidth: 320 }}>
          <SearchBar
            placeholder="Filter…"
            onChange={(v) => {
              setSearch(v);
              setPage(1);
            }}
          />
        </div>
      )}

      {isLoading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState error={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState>Nothing to show here.</EmptyState>
      ) : (
        <>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  {columns.map((c) => (
                    <th
                      key={c.key}
                      className={c.sortable ? "sortable" : undefined}
                      onClick={c.sortable ? () => toggleSort(c.key) : undefined}
                    >
                      {c.header}
                      {sort === c.key && (order === "asc" ? " ▲" : " ▼")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.items.map((row) => (
                  <tr
                    key={rowKey(row)}
                    className={onRowClick ? "clickable" : undefined}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                  >
                    {columns.map((c) => (
                      <td key={c.key} className={c.className}>
                        {c.render(row)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} pageSize={pageSize} total={data.total} onPage={setPage} />
        </>
      )}
    </div>
  );
}
