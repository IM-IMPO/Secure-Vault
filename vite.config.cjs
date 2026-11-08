const { defineConfig } = require("vite");

module.exports = defineConfig({
  base: "./",
  resolve: {
    dedupe: ["@firebase/app", "@firebase/component"]
  }
});