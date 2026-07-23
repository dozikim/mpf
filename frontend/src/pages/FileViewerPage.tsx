// Generic single-file viewer. Reached from the Files explorer and global search
// with ?tree=&path= query params. Renders the read-only Monaco viewer for any
// indexed text file, with a download action for the raw bytes.
import { useParams, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import { useQuery } from "@tanstack/react-query";
import { CodeViewer } from "../components/CodeViewer";
import { EmptyState } from "../components/States";

export function FileViewerPage() {
  const { id = "" } = useParams();
  const [params] = useSearchParams();
  const tree = params.get("tree") ?? "";
  const path = params.get("path") ?? "";

  const { data, isFetching } = useQuery({
    queryKey: ["file-view", id, tree, path],
    queryFn: () => api.file(id, tree, path),
    enabled: !!tree && !!path,
  });

  if (!tree || !path) {
    return (
      <div className="content-pad">
        <EmptyState>No file specified.</EmptyState>
      </div>
    );
  }

  return (
    <div style={{ height: "100%" }}>
      <CodeViewer
        file={data}
        loading={isFetching}
        downloadHref={api.downloadUrl(id, tree, path)}
      />
    </div>
  );
}
