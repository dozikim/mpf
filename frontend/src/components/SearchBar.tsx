// Debounced search input with the MPF search-field chrome. Emits the trimmed
// value after `delay` ms of idle so we don't fire a request per keystroke.
import { useEffect, useRef, useState } from "react";

interface Props {
  placeholder?: string;
  initial?: string;
  delay?: number;
  onChange: (value: string) => void;
  // Fires immediately on Enter (bypasses debounce) — used for content search.
  onSubmit?: (value: string) => void;
}

export function SearchBar({ placeholder = "Search…", initial = "", delay = 250, onChange, onSubmit }: Props) {
  const [value, setValue] = useState(initial);
  const timer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    timer.current = setTimeout(() => onChange(value.trim()), delay);
    return () => clearTimeout(timer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, delay]);

  return (
    <div className="search-field">
      <span className="icon">⌕</span>
      <input
        className="input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && onSubmit) {
            clearTimeout(timer.current);
            onSubmit(value.trim());
          }
        }}
        spellCheck={false}
        autoComplete="off"
      />
    </div>
  );
}
