// Left sidebar. Preserves the MPF visual language: mono uppercase group
// titles, accent left-border on the active link, live count badges.
import { NavLink, useParams } from "react-router-dom";

import { useAnalysis } from "../api/hooks";
import { NAV_GROUPS } from "./nav";

export function Sidebar() {
  const { id = "" } = useParams();
  const { data } = useAnalysis(id);
  const counts = data?.counts ?? {};

  return (
    <nav className="sidebar" aria-label="Analysis sections">
      {NAV_GROUPS.map((group) => (
        <div className="sidebar-group" key={group.title}>
          <div className="sidebar-group-title">{group.title}</div>
          {group.items.map((item) => (
            <NavLink
              key={item.to}
              to={`/analysis/${id}/${item.to}`}
              end={item.to === "overview"}
              className={({ isActive }) => `sidebar-link${isActive ? " active" : ""}`}
            >
              <span className="tree-name">{item.label}</span>
              {item.countKey && counts[item.countKey] !== undefined && (
                <span className="count">{counts[item.countKey]}</span>
              )}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}
