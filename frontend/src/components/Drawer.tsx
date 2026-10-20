// Right-hand detail drawer (component/library inspection). Renders an overlay +
// slide-in panel; ESC or overlay-click closes it. Body is caller-provided.
import { useEffect, type ReactNode } from "react";

interface Props {
  title: string;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
}

export function Drawer({ title, subtitle, onClose, children }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <button type="button" className="close" onClick={onClose} aria-label="Close">
          ✕
        </button>
        <h2>{title}</h2>
        {subtitle && <div className="muted-sm" style={{ fontFamily: "var(--font-mono)" }}>{subtitle}</div>}
        {children}
      </aside>
    </>
  );
}

/** Definition-list row helper for drawer/detail content. */
export function KV({ children }: { children: ReactNode }) {
  return <dl className="kv">{children}</dl>;
}

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children ?? "—"}</dd>
    </>
  );
}
