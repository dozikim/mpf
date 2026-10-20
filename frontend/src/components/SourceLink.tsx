import { Link, useParams } from "react-router-dom";

// Routes a source path to the right viewer:
//  - AndroidManifest.xml      -> dedicated manifest route (only it honors that view)
//  - *.java                   -> Java source browser
//  - *.smali                  -> Smali browser
//  - anything else (res/*.xml, assets/…) -> generic file viewer with the
//    "resources" tree, which is the backend tree those paths belong to.
export function SourceLink({ path, line, label = "OPEN SOURCE" }: { path?: string | null; line?: number | null; label?: string }) {
  const { id = "" } = useParams();
  if (!path) return <span className="mono">—</span>;

  let to: string;
  if (path === "AndroidManifest.xml") {
    const qs = new URLSearchParams();
    if (line) qs.set("line", String(line));
    to = `/analysis/${id}/manifest${qs.toString() ? `?${qs.toString()}` : ""}`;
  } else if (path.endsWith(".java")) {
    const qs = new URLSearchParams({ path });
    if (line) qs.set("line", String(line));
    to = `/analysis/${id}/java?${qs.toString()}`;
  } else if (path.endsWith(".smali")) {
    const qs = new URLSearchParams({ path });
    if (line) qs.set("line", String(line));
    to = `/analysis/${id}/smali?${qs.toString()}`;
  } else {
    const qs = new URLSearchParams({ tree: "resources", path });
    if (line) qs.set("line", String(line));
    to = `/analysis/${id}/file?${qs.toString()}`;
  }

  return <Link className="btn btn-sm" to={to}>{label}</Link>;
}
