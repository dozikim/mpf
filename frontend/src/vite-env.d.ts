/// <reference types="vite/client" />

// Monaco's web-worker environment hook (set in main.tsx). Declaring it here
// keeps the worker wiring type-safe without pulling in monaco's ambient types.
interface Window {
  MonacoEnvironment?: {
    getWorker(workerId: string, label: string): Worker;
  };
}
