import { useParams } from "react-router-dom";

import { FileBrowser } from "./FileBrowser";

export function JavaSourcePage() {
  const { id = "" } = useParams();
  return <FileBrowser analysisId={id} tree="java" title="JAVA SOURCE" />;
}
