// Certificates page. Signing certificates extracted via apksigner/keytool, with
// the signature-scheme coverage (v1/v2/v3) surfaced as tags. Not paginated —
// an APK has at most a handful of signers.
import { useParams } from "react-router-dom";

import { useCertificates } from "../api/hooks";
import { EmptyState, ErrorState, LoadingState } from "../components/States";

export function CertificatesPage() {
  const { id = "" } = useParams();
  const { data, isLoading, error } = useCertificates(id);

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;

  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>CERTIFICATES</h1>
        <p>Signing certificates and signature-scheme coverage.</p>
      </div>
      {!data || data.length === 0 ? (
        <EmptyState>No signing certificate recovered.</EmptyState>
      ) : (
        data.map((c) => (
          <div key={c.id} className="card">
            <h2>{c.subject ?? "Certificate"}</h2>
            <dl className="kv" style={{ marginTop: 0 }}>
              <dt>Subject</dt>
              <dd className="mono">{c.subject ?? "—"}</dd>
              <dt>Issuer</dt>
              <dd className="mono">{c.issuer ?? "—"}</dd>
              <dt>Serial</dt>
              <dd className="mono">{c.serial_number ?? "—"}</dd>
              <dt>Algorithm</dt>
              <dd className="mono">{c.signature_algorithm ?? "—"}</dd>
              <dt>SHA-256</dt>
              <dd className="mono" style={{ wordBreak: "break-all" }}>{c.sha256 ?? "—"}</dd>
              <dt>SHA-1</dt>
              <dd className="mono" style={{ wordBreak: "break-all" }}>{c.sha1 ?? "—"}</dd>
              <dt>Valid From</dt>
              <dd className="mono">{c.valid_from ?? "—"}</dd>
              <dt>Valid To</dt>
              <dd className="mono">{c.valid_to ?? "—"}</dd>
              <dt>Schemes</dt>
              <dd style={{ display: "flex", gap: 8 }}>
                <span className={`tag ${c.scheme_v1 ? "tag-low" : "tag-muted"}`}>v1</span>
                <span className={`tag ${c.scheme_v2 ? "tag-low" : "tag-muted"}`}>v2</span>
                <span className={`tag ${c.scheme_v3 ? "tag-low" : "tag-muted"}`}>v3</span>
              </dd>
            </dl>
          </div>
        ))
      )}
    </div>
  );
}
