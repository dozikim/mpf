import { useParams } from "react-router-dom";

import { FileBrowser } from "./FileBrowser";

export function SmaliPage() {
  const { id = "" } = useParams();
  return <FileBrowser analysisId={id} tree="smali" title="SMALI" />;
}
