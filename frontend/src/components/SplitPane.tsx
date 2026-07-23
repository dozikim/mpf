// Draggable horizontal split pane. Persists nothing external; parent controls
// initial width. Pure DOM math so it stays smooth without extra deps.
import { useCallback, useRef, useState, type ReactNode } from "react";

export function SplitPane({
  left,
  right,
  initialLeft = 340,
  minLeft = 180,
  minRight = 320,
}: {
  left: ReactNode;
  right: ReactNode;
  initialLeft?: number;
  minLeft?: number;
  minRight?: number;
}) {
  const [leftWidth, setLeftWidth] = useState(initialLeft);
  const containerRef = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);

  const onMouseDown = useCallback(() => {
    dragging.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMove = (e: MouseEvent) => {
      if (!dragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const next = e.clientX - rect.left;
      const max = rect.width - minRight;
      setLeftWidth(Math.max(minLeft, Math.min(next, max)));
    };
    const onUp = () => {
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, [minLeft, minRight]);

  return (
    <div className="split" ref={containerRef}>
      <div className="split-left" style={{ width: leftWidth }}>
        {left}
      </div>
      <div className="split-gutter" onMouseDown={onMouseDown} role="separator" aria-orientation="vertical" />
      <div className="split-right">{right}</div>
    </div>
  );
}
