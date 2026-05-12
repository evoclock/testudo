import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/renderer/index.html", "./src/renderer/src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#1f1f24",
        panel: "#2a2a32",
        border: "#3a3a44",
        accent: "#5e9bd1",
        muted: "#9b9bab",
        text: "#e5e5ec",
      },
    },
  },
  plugins: [],
};

export default config;
