import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ActionToastProvider } from "./components/ActionToast";
import { AuthProvider } from "./contexts/AuthContext";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 60_000,
      retry: 1
    }
  }
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ActionToastProvider>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </ActionToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
