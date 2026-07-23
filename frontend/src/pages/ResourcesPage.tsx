import { useParams } from "react-router-dom";

import { FileBrowser } from "./FileBrowser";

export function ResourcesPage() {
  const { id = "" } = useParams();
  return <FileBrowser analysisId={id} tree="resources" title="RESOURCES" />;
}
