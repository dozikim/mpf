// Application entrypoint. Wires the QueryClient (TanStack Query) and the router,
// and pulls in the theme + IDE stylesheets so the crimegpt palette is global.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { loader } from "@monaco-editor/react";
// Import the editor core + only the language contributions an APK ever needs
// (Java, XML, JSON). Smali/native/etc. fall back to plaintext highlighting.
// This keeps the bundle a fraction of the full `monaco-editor` barrel.
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import "monaco-editor/esm/vs/basic-languages/java/java.contribution";
import "monaco-editor/esm/vs/basic-languages/xml/xml.contribution";
import "monaco-editor/esm/vs/language/json/monaco.contribution";
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";
import jsonWorker from "monaco-editor/esm/vs/language/json/json.worker?worker";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "./App";
import "./styles/theme.css";
import "./styles/ide.css";

// Serve Monaco from the bundled npm package rather than the default CDN, so the
// console works fully offline / air-gapped (typical for a pentest environment).
// Java/Smali/XML use the plain editor worker; JSON gets its dedicated worker.
self.MonacoEnvironment = {
  getWorker(_id, label) {
    if (label === "json") return new jsonWorker();
    return new editorWorker();
  },
};
loader.config({ monaco });

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>
);
