import type { TestudoAPI } from "./index.ts";

declare global {
  interface Window {
    testudo: TestudoAPI;
  }
}

export {};
