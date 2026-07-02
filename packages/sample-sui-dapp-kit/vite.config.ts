import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const providerSuiDist = (fileName: string) =>
  fileURLToPath(new URL(`../provider-sui/dist/${fileName}`, import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@stelis/agent-q-provider-sui/provider-sui": providerSuiDist("provider-sui.js"),
      "@stelis/agent-q-provider-sui/browser": providerSuiDist("browser.js"),
      "@stelis/agent-q-provider-sui/wallet-standard": providerSuiDist("wallet-standard.js"),
    },
  },
});
