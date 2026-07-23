// Wire types mirroring the FastAPI Pydantic schemas (backend/app/schemas).

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface AnalysisSummary {
  id: string;
  file_name: string;
  file_size: number;
  package_name: string | null;
  app_name: string | null;
  version_name: string | null;
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  current_stage: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface AnalysisDetail extends AnalysisSummary {
  md5: string | null;
  sha1: string | null;
  sha256: string | null;
  version_code: string | null;
  min_sdk: string | null;
  target_sdk: string | null;
  error: string | null;
  counts: Record<string, number>;
}

export interface AnalysisStatus {
  id: string;
  status: AnalysisSummary["status"];
  progress: number;
  current_stage: string | null;
  error: string | null;
}

export interface ManifestSummary {
  package_name: string | null;
  version_name: string | null;
  version_code: string | null;
  min_sdk: string | null;
  target_sdk: string | null;
  compile_sdk: string | null;
  debuggable: boolean;
  allow_backup: boolean;
  uses_cleartext_traffic: boolean | null;
  network_security_config: string | null;
  manifest_path: string | null;
}

export interface IntentFilter {
  actions: (string | null)[];
  categories: (string | null)[];
  data: Record<string, string>[];
}

export interface ComponentOut {
  id: number;
  kind: string;
  name: string;
  exported: boolean;
  enabled: boolean;
  permission: string | null;
  authorities: string | null;
  grant_uri_permissions: boolean | null;
  intent_filters: IntentFilter[] | null;
  risk: string | null;
  risk_reason: string | null;
}

export interface PermissionOut {
  id: number;
  name: string;
  protection_level: string | null;
  is_dangerous: boolean;
  is_custom: boolean;
  description: string | null;
}

export interface LibraryOut {
  id: number;
  name: string;
  category: string | null;
  version: string | null;
  license: string | null;
  risk: string | null;
  evidence: string | null;
}

export interface SBOMOut {
  id: number;
  name: string;
  kind: string | null;
  version: string | null;
  license: string | null;
  purl: string | null;
  file_path: string | null;
  sha256: string | null;
}

export interface CertificateOut {
  id: number;
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  signature_algorithm: string | null;
  sha1: string | null;
  sha256: string | null;
  valid_from: string | null;
  valid_to: string | null;
  scheme_v1: boolean | null;
  scheme_v2: boolean | null;
  scheme_v3: boolean | null;
}

export interface FirebaseOut {
  id: number;
  url: string;
  kind: string | null;
  is_public: boolean | null;
  detail: string | null;
}

export interface MalwareOut {
  id: number;
  category: string;
  title: string;
  severity: string | null;
  detail: string | null;
  evidence: string | null;
  indicator: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
}

export interface FileOut {
  id: number;
  tree: string;
  rel_path: string;
  name: string;
  ext: string | null;
  size: number;
  is_text: boolean;
  lines: number | null;
  language: string | null;
}

export interface TreeNode {
  name: string;
  path: string;
  is_dir: boolean;
  size: number | null;
  language: string | null;
  children: TreeNode[] | null;
  has_children: boolean;
}

export interface FileContent {
  path: string;
  name: string;
  size: number;
  lines: number | null;
  language: string | null;
  encoding: string;
  truncated: boolean;
  content: string;
}

export interface SearchHit {
  tree: string;
  path: string;
  name: string;
  line_number: number;
  line: string;
  language: string | null;
}

export interface ReconIndicators {
  urls: string[];
  domains: string[];
  ips: string[];
  emails: string[];
  firebase: string[];
}

export interface MalwareLookupOut {
  analysis_status: string;
  last_scan: string | null;
  detection_ratio: string | null;
  hashes: Record<string, string | null>;
  reports: Record<string, string | null>;
}

export interface ApkidOut {
  id: number;
  category: string;
  label: string;
  value: string;
  detected: boolean;
  severity: string | null;
  file_path: string | null;
  line_number: number | null;
  evidence: string | null;
}

export interface BehaviourOut {
  id: number;
  name: string;
  severity: string;
  description: string;
  java_file: string | null;
  method_name: string | null;
  line_number: number | null;
  evidence: string | null;
}

export interface AbusedPermissionOut {
  id: number;
  permission: string;
  category: string;
  risk_level: string;
  description: string | null;
  dangerous_reason: string | null;
  malware_usage: string | null;
  used_in_code: boolean;
  files: string | null;
  methods: string | null;
}

export interface CodeFindingOut {
  id: number;
  issue: string;
  severity: string;
  description: string;
  cwe: string | null;
  owasp: string | null;
  masvs: string | null;
  java_file: string | null;
  line_number: number | null;
  category: string;
  recommendation: string | null;
  status: string;
  evidence: string | null;
}

export interface ReconFindingOut {
  id: number;
  kind: string;
  value: string;
  protocol: string | null;
  indicator_type: string | null;
  risk: string | null;
  file_path: string | null;
  line_number: number | null;
  method_name: string | null;
  context: string | null;
}

export interface DomainIntelOut {
  id: number;
  domain: string;
  status: string;
  resolved_ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  isp: string | null;
  asn: string | null;
  source_file: string | null;
  line_number: number | null;
}

export interface OverviewSecurityOut {
  security_score: number;
  tracker_score: number;
  overall_risk_level: string;
  exported_components_count: number;
  dangerous_permissions_count: number;
  native_libraries_count: number;
  detected_trackers: string[];
  detected_third_party_sdks: string[];
  malware_indicators: string[];
  security_summary: string[];
  static_analysis_summary: Record<string, number>;
}

export interface PageParams {
  page?: number;
  page_size?: number;
  search?: string;
  sort?: string;
  order?: "asc" | "desc";
}
