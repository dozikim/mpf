import { Link, useParams } from "react-router-dom";

export function SourceLink({ path, line, label = "OPEN SOURCE" }: { path?: string | null; line?: number | null; label?: string }) {
  const { id = "" } = useParams();
  if (!path) return <span className="mono">—</span>;
  const tree = path === "AndroidManifest.xml" || path.endsWith(".xml") && !path.endsWith(".java") ? "manifest" : "java";
  const targetPath = path === "AndroidManifest.xml" ? "AndroidManifest.xml" : path;
  const qs = new URLSearchParams({ path: targetPath });
  if (line) qs.set("line", String(line));
  return <Link className="btn btn-sm" to={`/analysis/${id}/${tree}?${qs.toString()}`}>{label}</Link>;
}
