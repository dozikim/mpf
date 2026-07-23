// Top bar. Same brand lockup as the Flask webapp (▚ MPF logo + tagline), plus
// contextual metadata (package name / status) when inside an analysis.
import { Link, useParams } from "react-router-dom";

import { useAnalysis } from "../api/hooks";

export function TopBar() {
  const { id } = useParams();
  const { data } = useAnalysis(id ?? "");

  return (
    <header className="topbar">
      <Link to="/" className="brand" style={{ textDecoration: "none" }}>
        <span className="logo">▚ MPF</span>
        <span className="tagline">Mobile Pentest Framework · RE Console</span>
      </Link>
      {data && (
        <div className="topbar-meta">
          {data.package_name && (
            <span>
              PKG <strong>{data.package_name}</strong>
            </span>
          )}
          {data.version_name && (
            <span>
              VER <strong>{data.version_name}</strong>
            </span>
          )}
          <span>
            STATUS <strong>{data.status.toUpperCase()}</strong>
          </span>
          {id && (
            <Link to={`/analysis/${id}/search`} className="btn btn-sm">
              ⌕ Search
            </Link>
          )}
        </div>
      )}
    </header>
  );
}
