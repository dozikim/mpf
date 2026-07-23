// Typed API client for the MPF backend. One thin fetch wrapper + a namespaced
// surface mirroring the REST endpoints. All paths are relative so the Vite
// proxy (dev) or same-origin deploy (prod) just works.

import type {
  AnalysisDetail,
  AnalysisStatus,
  AnalysisSummary,
  ApkidOut,
  BehaviourOut,
  AbusedPermissionOut,
  CertificateOut,
  CodeFindingOut,
  ComponentOut,
  DomainIntelOut,
  FileContent,
  FileOut,
  FirebaseOut,
  LibraryOut,
  MalwareOut,
  MalwareLookupOut,
  ManifestSummary,
  OverviewSecurityOut,
  Page,
  PageParams,
  PermissionOut,
  ReconFindingOut,
  ReconIndicators,
  SBOMOut,
  SearchHit,
  TreeNode,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE_URL || "") + "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* non-json error body */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

/** Build a page-query string from optional PageParams. */
function pageQs(extra: Record<string, unknown>, p?: PageParams): string {
  return qs({ ...p, ...extra });
}

export const api = {
  // --- lifecycle ---
  async upload(file: File, onProgress?: (pct: number) => void): Promise<{ id: string; status: string }> {
    // Use XHR for upload-progress events (fetch has no upload progress).
    return new Promise((resolve, reject) => {
      const form = new FormData();
      form.append("file", file);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${BASE}/analysis`);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
        else {
          let detail = xhr.statusText;
          try {
            detail = JSON.parse(xhr.responseText).detail ?? detail;
          } catch {
            /* ignore */
          }
          reject(new ApiError(xhr.status, detail));
        }
      };
      xhr.onerror = () => reject(new ApiError(0, "network error"));
      xhr.send(form);
    });
  },

  listAnalyses: (p?: PageParams) =>
    request<Page<AnalysisSummary>>(`/analysis${pageQs({}, p)}`),
  getAnalysis: (id: string) => request<AnalysisDetail>(`/analysis/${id}`),
  getStatus: (id: string) => request<AnalysisStatus>(`/analysis/${id}/status`),
  deleteAnalysis: (id: string) => request<void>(`/analysis/${id}`, { method: "DELETE" }),

  // --- trees & files ---
  tree: (id: string, tree: string, path = "") =>
    request<TreeNode[]>(`/analysis/${id}/tree${qs({ tree, path })}`),
  javaTree: (id: string) => request<TreeNode[]>(`/analysis/${id}/java`),
  javaFile: (id: string, path: string) =>
    request<FileContent>(`/analysis/${id}/java/file${qs({ path })}`),
  smaliTree: (id: string) => request<TreeNode[]>(`/analysis/${id}/smali`),
  smaliFile: (id: string, path: string) =>
    request<FileContent>(`/analysis/${id}/smali/file${qs({ path })}`),
  manifest: (id: string) => request<FileContent>(`/analysis/${id}/manifest`),
  manifestSummary: (id: string) =>
    request<ManifestSummary>(`/analysis/${id}/manifest/summary`),
  file: (id: string, tree: string, path: string) =>
    request<FileContent>(`/analysis/${id}/file${qs({ tree, path })}`),
  listFiles: (id: string, opts: PageParams & { tree?: string; ext?: string } = {}) =>
    request<Page<FileOut>>(`/analysis/${id}/files${pageQs({ tree: opts.tree, ext: opts.ext }, opts)}`),
  downloadUrl: (id: string, tree: string, path: string) =>
    `${BASE}/analysis/${id}/download${qs({ tree, path })}`,
  search: (id: string, q: string, trees?: string) =>
    request<SearchHit[]>(`/analysis/${id}/search${qs({ q, trees })}`),

  // --- components ---
  activities: (id: string, p?: PageParams) =>
    request<Page<ComponentOut>>(`/analysis/${id}/activities${pageQs({}, p)}`),
  services: (id: string, p?: PageParams) =>
    request<Page<ComponentOut>>(`/analysis/${id}/services${pageQs({}, p)}`),
  receivers: (id: string, p?: PageParams) =>
    request<Page<ComponentOut>>(`/analysis/${id}/receivers${pageQs({}, p)}`),
  providers: (id: string, p?: PageParams) =>
    request<Page<ComponentOut>>(`/analysis/${id}/providers${pageQs({}, p)}`),
  libraries: (id: string, p?: PageParams) =>
    request<Page<LibraryOut>>(`/analysis/${id}/libraries${pageQs({}, p)}`),
  permissions: (id: string, p?: PageParams) =>
    request<Page<PermissionOut>>(`/analysis/${id}/permissions${pageQs({}, p)}`),
  sbom: (id: string, p?: PageParams) =>
    request<Page<SBOMOut>>(`/analysis/${id}/sbom${pageQs({}, p)}`),

  // --- intel ---
  certificates: (id: string) => request<CertificateOut[]>(`/analysis/${id}/certificates`),
  firebase: (id: string, p?: PageParams) =>
    request<Page<FirebaseOut>>(`/analysis/${id}/firebase${pageQs({}, p)}`),
  malware: (id: string, opts: PageParams & { category?: string } = {}) =>
    request<Page<MalwareOut>>(`/analysis/${id}/malware${pageQs({ category: opts.category }, opts)}`),
  malwareLookup: (id: string) => request<MalwareLookupOut>(`/analysis/${id}/malware/lookup`),
  overviewSecurity: (id: string) => request<OverviewSecurityOut>(`/analysis/${id}/overview/security`),
  apkid: (id: string, p?: PageParams) =>
    request<Page<ApkidOut>>(`/analysis/${id}/apkid${pageQs({}, p)}`),
  behaviours: (id: string, p?: PageParams) =>
    request<Page<BehaviourOut>>(`/analysis/${id}/behaviours${pageQs({}, p)}`),
  abusedPermissions: (id: string, opts: PageParams & { category?: string } = {}) =>
    request<Page<AbusedPermissionOut>>(`/analysis/${id}/abused-permissions${pageQs({ category: opts.category }, opts)}`),
  codeAnalysis: (id: string, opts: PageParams & { severity?: string } = {}) =>
    request<Page<CodeFindingOut>>(`/analysis/${id}/code-analysis${pageQs({ severity: opts.severity }, opts)}`),
  reconFindings: (id: string, opts: PageParams & { kind?: string } = {}) =>
    request<Page<ReconFindingOut>>(`/analysis/${id}/recon/findings${pageQs({ kind: opts.kind }, opts)}`),
  domainIntel: (id: string, p?: PageParams) =>
    request<Page<DomainIntelOut>>(`/analysis/${id}/domains/intel${pageQs({}, p)}`),
  recon: (id: string) => request<ReconIndicators>(`/analysis/${id}/recon`),
};
