// Small shared UI primitives: loading / empty / error states, tags, spinner.
import type { ReactNode } from "react";

export function Spinner() {
  return <div className="spinner" aria-label="loading" />;
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state">
      <Spinner />
      {label}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="state state-empty">{children}</div>;
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return <div className="state">⚠ {message}</div>;
}

const RISK_CLASS: Record<string, string> = {
  CRITICAL: "tag-critical",
  HIGH: "tag-high",
  MEDIUM: "tag-medium",
  LOW: "tag-low",
};

export function RiskTag({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="tag tag-muted">—</span>;
  const cls = RISK_CLASS[value.toUpperCase()] ?? "tag-muted";
  return <span className={`tag ${cls}`}>{value}</span>;
}

export function BoolTag({ value, trueLabel = "YES", falseLabel = "NO" }: {
  value: boolean | null | undefined;
  trueLabel?: string;
  falseLabel?: string;
}) {
  if (value === null || value === undefined) return <span className="tag tag-muted">—</span>;
  return (
    <span className={`tag ${value ? "tag-high" : "tag-muted"}`}>
      {value ? trueLabel : falseLabel}
    </span>
  );
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
