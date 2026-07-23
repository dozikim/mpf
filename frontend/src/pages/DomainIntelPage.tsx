import { useParams } from "react-router-dom";

import { useDomainIntel } from "../api/hooks";
import type { DomainIntelOut } from "../api/types";
import { Column, DataTable } from "../components/DataTable";
import { SourceLink } from "../components/SourceLink";

export function DomainIntelPage() {
  const { id = "" } = useParams();
  const columns: Column<DomainIntelOut>[] = [
    { key: "domain", header: "DOMAIN", sortable: true, className: "mono", render: (r) => r.domain },
    { key: "status", header: "STATUS", sortable: true, render: (r) => r.status.toUpperCase() },
    { key: "resolved_ip", header: "RESOLVED IP", render: (r) => r.resolved_ip ?? "—" },
    { key: "country", header: "COUNTRY", render: (r) => r.country ?? "—" },
    { key: "region", header: "REGION", render: (r) => r.region ?? "—" },
    { key: "city", header: "CITY", render: (r) => r.city ?? "—" },
    { key: "isp", header: "ISP", render: (r) => r.isp ?? "—" },
    { key: "asn", header: "ASN", render: (r) => r.asn ?? "—" },
    { key: "maps", header: "GOOGLE MAPS", render: (r) => r.latitude && r.longitude ? <a className="btn btn-sm" href={`https://maps.google.com/?q=${r.latitude},${r.longitude}`} target="_blank" rel="noreferrer">MAP</a> : "—" },
    { key: "vt", header: "VIRUSTOTAL", render: (r) => <a className="btn btn-sm" href={`https://www.virustotal.com/gui/domain/${r.domain}`} target="_blank" rel="noreferrer">VT</a> },
    { key: "abuse", header: "ABUSEIPDB", render: (r) => <a className="btn btn-sm" href={`https://www.abuseipdb.com/check/${r.domain}`} target="_blank" rel="noreferrer">ABUSE</a> },
    { key: "osm", header: "OPENSTREETMAP", render: (r) => r.latitude && r.longitude ? <a className="btn btn-sm" href={`https://www.openstreetmap.org/?mlat=${r.latitude}&mlon=${r.longitude}`} target="_blank" rel="noreferrer">OSM</a> : "—" },
    { key: "source", header: "SOURCE", render: (r) => <SourceLink path={r.source_file} line={r.line_number} /> },
  ];
  return <DataTable title="DOMAIN MALWARE CHECK" subtitle="Extracted domains, hosts and report links with stored source evidence." columns={columns} useData={(p) => useDomainIntel(id, p)} defaultSort="domain" rowKey={(r) => r.id} />;
}
