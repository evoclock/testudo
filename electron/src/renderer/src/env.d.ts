/// <reference types="vite/client" />

/**
 * Renderer-scope global type augmentation.
 *
 * tsconfig.web.json's `include` is scoped to `src/renderer/src/**`, so the
 * preload's `index.d.ts` is invisible to the renderer compiler. The shape
 * declared here mirrors `TestudoAPI` in `src/preload/index.ts`; keep them
 * in sync (single source of truth would mean a `src/shared/` directory
 * visible to both tsconfigs, deferred until the surface grows).
 */

interface BridgeConfig {
  url: string;
  token: string;
}

interface TestudoAPI {
  getBridgeConfig: () => Promise<BridgeConfig>;
  openFile: () => Promise<string | null>;
  spawnServe: (args: {
    workflowsRoot: string;
    runsRoot: string;
  }) => Promise<{ pid: number }>;
}

interface Window {
  testudo: TestudoAPI;
}
