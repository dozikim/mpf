// Virtualized, lazily-loaded directory tree.
//
// * Lazy loading: a directory's children are fetched (via `loadChildren`) only
//   when it is first expanded, then cached in node state.
// * Virtualization: only the visible slice of the flattened, expanded tree is
//   rendered (react-virtual), so a 10k-file APK scrolls smoothly.
// * Keyboard nav: ↑/↓ move, →/← expand/collapse, Enter opens a file.
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { TreeNode } from "../api/types";

export interface TreeItem extends TreeNode {
  depth: number;
  expanded: boolean;
  loading: boolean;
  children: TreeItem[] | null;
}

interface Props {
  roots: TreeNode[];
  selectedPath?: string;
  onSelectFile: (path: string, node: TreeItem) => void;
  loadChildren: (path: string) => Promise<TreeNode[]>;
  filter?: string; // filename filter (client-side, over loaded nodes)
}

function toItem(node: TreeNode, depth: number): TreeItem {
  return { ...node, depth, expanded: false, loading: false, children: null };
}

/** Depth-first flatten of expanded nodes into a render list. */
function flatten(items: TreeItem[], filter: string): TreeItem[] {
  const out: TreeItem[] = [];
  const needle = filter.trim().toLowerCase();
  const walk = (nodes: TreeItem[]) => {
    for (const n of nodes) {
      const matches = !needle || n.name.toLowerCase().includes(needle);
      if (matches) out.push(n);
      if (n.expanded && n.children) walk(n.children);
    }
  };
  walk(items);
  return out;
}

export function TreeView({ roots, selectedPath, onSelectFile, loadChildren, filter = "" }: Props) {
  const [items, setItems] = useState<TreeItem[]>(() => roots.map((r) => toItem(r, 0)));
  const [activeIndex, setActiveIndex] = useState(0);
  const parentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setItems(roots.map((r) => toItem(r, 0)));
  }, [roots]);

  const visible = useMemo(() => flatten(items, filter), [items, filter]);

  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24,
    overscan: 20,
  });

  // Mutate a node found by path within the tree (immutable update).
  const updateNode = useCallback(
    (path: string, fn: (n: TreeItem) => TreeItem) => {
      const rec = (nodes: TreeItem[]): TreeItem[] =>
        nodes.map((n) => {
          if (n.path === path) return fn(n);
          if (n.children) return { ...n, children: rec(n.children) };
          return n;
        });
      setItems((prev) => rec(prev));
    },
    []
  );

  const toggle = useCallback(
    async (node: TreeItem) => {
      if (!node.is_dir) {
        onSelectFile(node.path, node);
        return;
      }
      if (node.expanded) {
        updateNode(node.path, (n) => ({ ...n, expanded: false }));
        return;
      }
      if (node.children) {
        updateNode(node.path, (n) => ({ ...n, expanded: true }));
        return;
      }
      // Lazy load
      updateNode(node.path, (n) => ({ ...n, loading: true }));
      try {
        const kids = await loadChildren(node.path);
        updateNode(node.path, (n) => ({
          ...n,
          expanded: true,
          loading: false,
          children: kids.map((k) => toItem(k, n.depth + 1)),
        }));
      } catch {
        updateNode(node.path, (n) => ({ ...n, loading: false }));
      }
    },
    [loadChildren, onSelectFile, updateNode]
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!visible.length) return;
      const node = visible[activeIndex];
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setActiveIndex((i) => Math.min(i + 1, visible.length - 1));
          break;
        case "ArrowUp":
          e.preventDefault();
          setActiveIndex((i) => Math.max(i - 1, 0));
          break;
        case "ArrowRight":
          e.preventDefault();
          if (node?.is_dir && !node.expanded) void toggle(node);
          break;
        case "ArrowLeft":
          e.preventDefault();
          if (node?.is_dir && node.expanded) void toggle(node);
          break;
        case "Enter":
          e.preventDefault();
          if (node) void toggle(node);
          break;
      }
    },
    [activeIndex, visible, toggle]
  );

  useEffect(() => {
    if (activeIndex < visible.length) virtualizer.scrollToIndex(activeIndex);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIndex]);

  return (
    <div className="tree" ref={parentRef} tabIndex={0} onKeyDown={onKeyDown} role="tree">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((v) => {
          const node = visible[v.index];
          const isSelected = node.path === selectedPath;
          const isActive = v.index === activeIndex;
          return (
            <div
              key={node.path}
              role="treeitem"
              aria-expanded={node.is_dir ? node.expanded : undefined}
              aria-selected={isSelected}
              className={`tree-row${isSelected || isActive ? " selected" : ""}`}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${v.start}px)`,
                paddingLeft: 10 + node.depth * 14,
              }}
              onClick={() => {
                setActiveIndex(v.index);
                void toggle(node);
              }}
            >
              {node.is_dir ? (
                <span className={`tree-caret${node.expanded ? " open" : ""}`}>
                  {node.loading ? "◌" : "▶"}
                </span>
              ) : (
                <span className="tree-caret" />
              )}
              <span className="tree-icon">{node.is_dir ? "▸" : "·"}</span>
              <span className="tree-name">{node.name}</span>
              {!node.is_dir && node.size != null && (
                <span className="tree-size">{fmtSize(node.size)}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)}K`;
  return `${(n / (1024 * 1024)).toFixed(1)}M`;
}
