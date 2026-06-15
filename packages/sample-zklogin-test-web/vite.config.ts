import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: "index.html",
        callback: "callback.html",
      },
    },
  },
  plugins: [react()],
});
