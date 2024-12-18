import { defineConfig } from "@trigger.dev/sdk/v3";

export default defineConfig({
  project: "proj_suhworwbyuxaddzinvkr", // Your project reference
  // Your other config settings...
  build: {
    external: ["pg"],
  },
});
