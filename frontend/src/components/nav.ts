// Sidebar navigation model — mirrors the structure requested in the spec.
// Paths are relative to /analysis/:id. `countKey` maps to AnalysisDetail.counts
// so badges show live numbers.

export interface NavItem {
  label: string;
  to: string; // relative segment under /analysis/:id
  countKey?: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Static Analysis",
    items: [
      { label: "Overview", to: "overview" },
      { label: "Manifest", to: "manifest" },
      { label: "Java Source", to: "java", countKey: "java_files" },
      { label: "Smali", to: "smali", countKey: "smali_files" },
      { label: "Resources", to: "resources" },
      { label: "Code Analysis", to: "code-analysis", countKey: "code_findings" },
    ],
  },
  {
    title: "Malware Analysis",
    items: [
      { label: "Malware Lookup", to: "malware", countKey: "malware" },
      { label: "APKID Analysis", to: "malware/apkid", countKey: "apkid" },
      { label: "Behaviour Analysis", to: "malware/behaviour", countKey: "behaviours" },
      { label: "Abused Permissions", to: "malware/permissions", countKey: "abused_permissions" },
      { label: "Server Locations", to: "malware/servers", countKey: "domains" },
      { label: "Domain Malware Check", to: "malware/domains", countKey: "domains" },
    ],
  },
  {
    title: "Reconnaissance",
    items: [
      { label: "Domains", to: "recon/domains", countKey: "domains" },
      { label: "URLs", to: "recon/urls", countKey: "urls" },
      { label: "Emails", to: "recon/emails", countKey: "emails" },
      { label: "DNS", to: "recon/dns", countKey: "domains" },
      { label: "WHOIS", to: "recon/whois", countKey: "domains" },
      { label: "GeoIP", to: "recon/geoip", countKey: "domains" },
    ],
  },
  {
    title: "Components",
    items: [
      { label: "Activities", to: "activities", countKey: "activities" },
      { label: "Services", to: "services", countKey: "services" },
      { label: "Receivers", to: "receivers", countKey: "receivers" },
      { label: "Providers", to: "providers", countKey: "providers" },
      { label: "Libraries", to: "libraries", countKey: "libraries" },
      { label: "SBOM", to: "sbom" },
    ],
  },
  {
    title: "Artifacts",
    items: [
      { label: "Files", to: "files", countKey: "files" },
      { label: "Certificates", to: "certificates", countKey: "certificates" },
      { label: "Firebase", to: "firebase", countKey: "firebase" },
      { label: "Reports", to: "reports" },
    ],
  },
  {
    title: "Dynamic",
    items: [{ label: "Dynamic Analysis", to: "dynamic" }],
  },
];
