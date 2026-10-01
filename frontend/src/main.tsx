import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { AuthProvider } from "./lib/auth";
import { UiProvider } from "./components/ui";
import "./styles.css";

try {
  const t = localStorage.getItem("nmp-theme");
  document.documentElement.dataset.theme = t || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
} catch { /* storage unavailable */ }

const qc = new QueryClient({ defaultOptions: { queries: { retry: (n, e: any) => n < 1 && e?.status !== 401 && e?.status !== 403, refetchOnWindowFocus: false, staleTime: 5_000 } } });

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <UiProvider>
          <AuthProvider>
            <App />
          </AuthProvider>
        </UiProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
