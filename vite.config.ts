import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    // use src/server.ts as the server entry
    server: { entry: "server" },
  },
});
