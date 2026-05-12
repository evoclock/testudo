/// <reference types="vite/client" />

/**
 * Renderer-scope global type augmentation.
 *
 * tsconfig.web.json's `include` is scoped to `src/renderer/src/**`, so the
 * preload's `index.d.ts` is invisible to the renderer compiler. The shape
 * declared here mirrors `TestudoAPI` in `src/preload/index.ts`; keep them
 * in sync.
 */

interface BridgeStatus {
  running: boolean;
  url: string | null;
  token: string | null;
  port: number | null;
  pid: number | null;
  error: string | null;
}

interface BridgeStartOptions {
  port?: number;
  host?: string;
  workflowsDir?: string;
  runsDir?: string;
}

interface TestudoAPI {
  bridge: {
    status: () => Promise<BridgeStatus>;
    start: (opts?: BridgeStartOptions) => Promise<BridgeStatus>;
    stop: () => Promise<BridgeStatus>;
  };
  openFile: () => Promise<string | null>;
}

interface Window {
  testudo: TestudoAPI;
}
