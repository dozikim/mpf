// TanStack Query hooks. Centralises cache keys, polling for in-progress
// analyses, and typed access to every endpoint the UI needs.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./client";
import type { PageParams } from "./types";

export const keys = {
  analyses: (p?: PageParams) => ["analyses", p] as const,
  analysis: (id: string) => ["analysis", id] as const,
  status: (id: string) => ["status", id] as const,
  tree: (id: string, tree: string) => ["tree", id, tree] as const,
  file: (id: string, tree: string, path: string) => ["file", id, tree, path] as const,
  manifest: (id: string) => ["manifest", id] as const,
  manifestSummary: (id: string) => ["manifest-summary", id] as const,
  activities: (id: string, p?: PageParams) => ["activities", id, p] as const,
  services: (id: string, p?: PageParams) => ["services", id, p] as const,
  receivers: (id: string, p?: PageParams) => ["receivers", id, p] as const,
  providers: (id: string, p?: PageParams) => ["providers", id, p] as const,
  libraries: (id: string, p?: PageParams) => ["libraries", id, p] as const,
  permissions: (id: string, p?: PageParams) => ["permissions", id, p] as const,
  sbom: (id: string, p?: PageParams) => ["sbom", id, p] as const,
  certificates: (id: string) => ["certificates", id] as const,
  firebase: (id: string, p?: PageParams) => ["firebase", id, p] as const,
  malware: (id: string, p?: PageParams, cat?: string) => ["malware", id, p, cat] as const,
  malwareLookup: (id: string) => ["malware-lookup", id] as const,
  overviewSecurity: (id: string) => ["overview-security", id] as const,
  apkid: (id: string, p?: PageParams) => ["apkid", id, p] as const,
  behaviours: (id: string, p?: PageParams) => ["behaviours", id, p] as const,
  abusedPermissions: (id: string, p?: PageParams, category?: string) => ["abused-permissions", id, p, category] as const,
  codeAnalysis: (id: string, p?: PageParams, severity?: string) => ["code-analysis", id, p, severity] as const,
  reconFindings: (id: string, p?: PageParams, kind?: string) => ["recon-findings", id, p, kind] as const,
  domainIntel: (id: string, p?: PageParams) => ["domain-intel", id, p] as const,
  recon: (id: string) => ["recon", id] as const,
  files: (id: string, opts?: unknown) => ["files", id, opts] as const,
};

export function useAnalyses(p?: PageParams) {
  return useQuery({ queryKey: keys.analyses(p), queryFn: () => api.listAnalyses(p) });
}

export function useAnalysis(id: string) {
  return useQuery({
    queryKey: keys.analysis(id),
    queryFn: () => api.getAnalysis(id),
    // Poll while the pipeline is still running so the overview updates live.
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "pending" || s === "running" ? 2000 : false;
    },
  });
}

export function useUpload() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, onProgress }: { file: File; onProgress?: (p: number) => void }) =>
      api.upload(file, onProgress),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["analyses"] }),
  });
}

export function useDeleteAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteAnalysis(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["analyses"] }),
  });
}

export function useTree(id: string, tree: string) {
  return useQuery({ queryKey: keys.tree(id, tree), queryFn: () => api.tree(id, tree) });
}

export function useManifest(id: string) {
  return useQuery({ queryKey: keys.manifest(id), queryFn: () => api.manifest(id) });
}

export function useManifestSummary(id: string) {
  return useQuery({
    queryKey: keys.manifestSummary(id),
    queryFn: () => api.manifestSummary(id),
  });
}

export function useActivities(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.activities(id, p), queryFn: () => api.activities(id, p) });
}
export function useServices(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.services(id, p), queryFn: () => api.services(id, p) });
}
export function useReceivers(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.receivers(id, p), queryFn: () => api.receivers(id, p) });
}
export function useProviders(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.providers(id, p), queryFn: () => api.providers(id, p) });
}
export function useLibraries(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.libraries(id, p), queryFn: () => api.libraries(id, p) });
}
export function usePermissions(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.permissions(id, p), queryFn: () => api.permissions(id, p) });
}
export function useSbom(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.sbom(id, p), queryFn: () => api.sbom(id, p) });
}
export function useCertificates(id: string) {
  return useQuery({ queryKey: keys.certificates(id), queryFn: () => api.certificates(id) });
}
export function useFirebase(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.firebase(id, p), queryFn: () => api.firebase(id, p) });
}
export function useMalware(id: string, p?: PageParams, category?: string) {
  return useQuery({
    queryKey: keys.malware(id, p, category),
    queryFn: () => api.malware(id, { ...p, category }),
  });
}
export function useMalwareLookup(id: string) {
  return useQuery({ queryKey: keys.malwareLookup(id), queryFn: () => api.malwareLookup(id) });
}
export function useOverviewSecurity(id: string) {
  return useQuery({ queryKey: keys.overviewSecurity(id), queryFn: () => api.overviewSecurity(id) });
}
export function useApkid(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.apkid(id, p), queryFn: () => api.apkid(id, p) });
}
export function useBehaviours(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.behaviours(id, p), queryFn: () => api.behaviours(id, p) });
}
export function useAbusedPermissions(id: string, p?: PageParams, category?: string) {
  return useQuery({
    queryKey: keys.abusedPermissions(id, p, category),
    queryFn: () => api.abusedPermissions(id, { ...p, category }),
  });
}
export function useCodeAnalysis(id: string, p?: PageParams, severity?: string) {
  return useQuery({
    queryKey: keys.codeAnalysis(id, p, severity),
    queryFn: () => api.codeAnalysis(id, { ...p, severity }),
  });
}
export function useReconFindings(id: string, p?: PageParams, kind?: string) {
  return useQuery({
    queryKey: keys.reconFindings(id, p, kind),
    queryFn: () => api.reconFindings(id, { ...p, kind }),
  });
}
export function useDomainIntel(id: string, p?: PageParams) {
  return useQuery({ queryKey: keys.domainIntel(id, p), queryFn: () => api.domainIntel(id, p) });
}
export function useRecon(id: string) {
  return useQuery({ queryKey: keys.recon(id), queryFn: () => api.recon(id) });
}
export function useFiles(id: string, opts: PageParams & { tree?: string; ext?: string }) {
  return useQuery({ queryKey: keys.files(id, opts), queryFn: () => api.listFiles(id, opts) });
}
