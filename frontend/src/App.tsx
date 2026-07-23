// Application router. Deep-linkable routes for every analysis section so the
// browser back/forward, bookmarking and shareable URLs all work. The analysis
// sections render inside AnalysisLayout (top bar + sidebar + outlet); the home
// dashboard renders standalone.
import { Navigate, Route, Routes } from "react-router-dom";

import { AnalysisLayout } from "./components/AnalysisLayout";
import { AbusedPermissionsPage } from "./pages/AbusedPermissionsPage";
import { ApkidPage } from "./pages/ApkidPage";
import { BehaviourPage } from "./pages/BehaviourPage";
import { CertificatesPage } from "./pages/CertificatesPage";
import { CodeAnalysisPage } from "./pages/CodeAnalysisPage";
import { ComponentsPage } from "./pages/ComponentsPage";
import { DomainIntelPage } from "./pages/DomainIntelPage";
import { FilesPage } from "./pages/FilesPage";
import { FileViewerPage } from "./pages/FileViewerPage";
import { FirebasePage } from "./pages/FirebasePage";
import { HomePage } from "./pages/HomePage";
import { JavaSourcePage } from "./pages/JavaSourcePage";
import { LibrariesPage } from "./pages/LibrariesPage";
import { MalwarePage } from "./pages/MalwarePage";
import { MalwareLookupPage } from "./pages/MalwareLookupPage";
import { ManifestPage } from "./pages/ManifestPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PermissionsPage } from "./pages/PermissionsPage";
import { ReconFindingsPage } from "./pages/ReconFindingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ResourcesPage } from "./pages/ResourcesPage";
import { SbomPage } from "./pages/SbomPage";
import { SearchPage } from "./pages/SearchPage";
import { SmaliPage } from "./pages/SmaliPage";

export function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />

      <Route path="/analysis/:id" element={<AnalysisLayout />}>
        <Route index element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<OverviewPage />} />

        {/* Static analysis */}
        <Route path="manifest" element={<ManifestPage />} />
        <Route path="java" element={<JavaSourcePage />} />
        <Route path="smali" element={<SmaliPage />} />
        <Route path="resources" element={<ResourcesPage />} />
        <Route path="files" element={<FilesPage />} />
        <Route path="file" element={<FileViewerPage />} />
        <Route path="search" element={<SearchPage />} />
        <Route path="code-analysis" element={<CodeAnalysisPage />} />

        {/* Components */}
        <Route path="activities" element={<ComponentsPage kind="activities" />} />
        <Route path="services" element={<ComponentsPage kind="services" />} />
        <Route path="receivers" element={<ComponentsPage kind="receivers" />} />
        <Route path="providers" element={<ComponentsPage kind="providers" />} />
        <Route path="permissions" element={<PermissionsPage />} />
        <Route path="libraries" element={<LibrariesPage />} />
        <Route path="sbom" element={<SbomPage />} />

        {/* Intel / artifacts */}
        <Route path="certificates" element={<CertificatesPage />} />
        <Route path="firebase" element={<FirebasePage />} />
        <Route path="reports" element={<ReportsPage />} />

        {/* Malware analysis */}
        <Route path="malware" element={<MalwareLookupPage />} />
        <Route path="malware/findings" element={<MalwarePage title="MALWARE FINDINGS" />} />
        <Route path="malware/apkid" element={<ApkidPage />} />
        <Route path="malware/behaviour" element={<BehaviourPage />} />
        <Route path="malware/permissions" element={<AbusedPermissionsPage />} />
        <Route path="malware/servers" element={<DomainIntelPage />} />
        <Route path="malware/domains" element={<DomainIntelPage />} />

        {/* Reconnaissance */}
        <Route path="recon/domains" element={<DomainIntelPage />} />
        <Route path="recon/urls" element={<ReconFindingsPage kind="url" />} />
        <Route path="recon/ips" element={<ReconFindingsPage kind="ip" />} />
        <Route path="recon/emails" element={<ReconFindingsPage kind="email" />} />
        <Route path="recon/dns" element={<ReconFindingsPage kind="domain" />} />
        <Route path="recon/whois" element={<DomainIntelPage />} />
        <Route path="recon/geoip" element={<DomainIntelPage />} />

        {/* Dynamic (placeholder section) */}
        <Route path="dynamic" element={<DynamicPlaceholder />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function DynamicPlaceholder() {
  return (
    <div className="content-pad">
      <div className="page-head">
        <h1>DYNAMIC ANALYSIS</h1>
        <p>Runtime instrumentation is not part of the static-analysis pipeline.</p>
      </div>
      <div className="state state-empty">
        Dynamic analysis (Frida / emulator instrumentation) is planned for a future release.
      </div>
    </div>
  );
}
