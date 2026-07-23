// Layout shell for all analysis pages: top bar + sidebar + routed content.
// The Outlet renders the active section. A thin progress bar surfaces pipeline
// state while an analysis is still decompiling.
import { Outlet, useParams } from "react-router-dom";

import { useAnalysis } from "../api/hooks";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AnalysisLayout() {
  const { id = "" } = useParams();
  const { data } = useAnalysis(id);
  const inProgress = data && (data.status === "pending" || data.status === "running");

  return (
    <div className="app-shell">
      <TopBar />
      {inProgress && (
        <div className="progress-bar" title={data?.current_stage ?? ""}>
          <span style={{ width: `${data?.progress ?? 0}%` }} />
        </div>
      )}
      <div className="app-body">
        <Sidebar />
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
