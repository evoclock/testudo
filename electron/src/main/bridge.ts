/**
 * BridgeManager: owns the testudo serve subprocess.
 *
 * The renderer asks the main process to start / stop / inspect the bridge
 * via IPC. This module is the single source of truth for the child
 * process. The bearer token remains main-process-only; renderer requests
 * cross a narrow IPC proxy that attaches authentication here and only
 * reaches an allowlisted set of bridge paths.
 */
import { app } from "electron";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import type { Writable } from "node:stream";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface BridgeStatus {
  running: boolean;
  url: string | null;
  port: number | null;
  pid: number | null;
  error: string | null;
}

export interface StartOptions {
  port?: number;
  host?: string;
  workflowsDir?: string;
  runsDir?: string;
}

/**
 * Explicit environment allowlist for the bridge child. The child receives
 * only what `testudo serve` documents as non-secret configuration: process
 * basics (PATH/HOME/TMPDIR), locale, the Linux user-state dir, the
 * non-secret Databricks connection coordinates, and the TESTUDO_* config
 * variables actually consumed on the Python side (model endpoints, registry
 * and seats/data dir overrides). Everything else in process.env — in
 * particular provider API keys and DATABRICKS_TOKEN — is excluded by
 * construction: secrets live in the platform credential store, never in a
 * child environment. No documented consumer is known to need more; if one
 * appears, extend this list with a comment naming the consumer rather than
 * widening to `...process.env`.
 */
const CHILD_ENV_ALLOWLIST: readonly string[] = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "XDG_STATE_HOME",
  "DATABRICKS_SERVER_HOSTNAME",
  "DATABRICKS_HTTP_PATH",
  "TESTUDO_OLLAMA_URL",
  "TESTUDO_OPENAI_BASE_URL",
  "TESTUDO_MODEL_REGISTRY",
  "TESTUDO_CONFIG_DIR",
  "TESTUDO_DATA_DIR",
  "TESTUDO_REPO_ROOT",
];

function buildChildEnv(): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = {};
  for (const name of CHILD_ENV_ALLOWLIST) {
    const value = process.env[name];
    if (value !== undefined) {
      env[name] = value;
    }
  }
  return env;
}

/**
 * Bridge paths the renderer is allowed to reach through the IPC proxy.
 * Derived 1:1 from the renderer's actual calls in
 * electron/src/renderer/src/lib/api.ts (BridgeClient methods + seatsMethods
 * post targets) and the components that call them (App.tsx, WorkflowPanel,
 * DatabasePanel, SeatsPanel). Do not add a path here without a matching
 * renderer call. Patterns are plain regex sources (no flags) so they can be
 * validated from the Python test suite (tests/test_electron_bridge_allowlist.py).
 */
export const BRIDGE_PATH_ALLOWLIST: readonly string[] = [
  "^/health$",
  "^/workflows$",
  "^/workflows/[^/]+/readme$",
  "^/tools$",
  "^/env-check$",
  "^/runs$",
  "^/runs/[^/]+$",
  "^/seats/config$",
  "^/seats/draft$",
  "^/seats/draft/update$",
  "^/seats/config/apply$",
  "^/seats/config/delete$",
  "^/seats/ssh/probe$",
  "^/seats/ssh/trust$",
  "^/seats/preview$",
  "^/seats/consent$",
  "^/seats/operate$",
  "^/seats/force-stop-challenge$",
  "^/seats/provider-key$",
  "^/seats/provider-key/state$",
];

export function isAllowedBridgePath(path: string): boolean {
  return BRIDGE_PATH_ALLOWLIST.some((pattern) => new RegExp(pattern).test(path));
}

export class BridgeManager {
  private child: ChildProcess | null = null;
  private currentToken: string | null = null;
  private currentUrl: string | null = null;
  private currentPort: number | null = null;
  private lastError: string | null = null;

  status(): BridgeStatus {
    return {
      running: this.child !== null && this.child.exitCode === null,
      url: this.currentUrl,
      port: this.currentPort,
      pid: this.child?.pid ?? null,
      error: this.lastError,
    };
  }

  async start(opts: StartOptions = {}): Promise<BridgeStatus> {
    if (this.status().running) {
      return this.status();
    }
    this.lastError = null;

    const port = opts.port ?? 8000;
    const host = opts.host ?? "127.0.0.1";
    const workflowsDir = opts.workflowsDir ?? this.resolveWorkflowsDir();
    const runsDir = opts.runsDir ?? this.resolveRunsDir();
    const command = this.resolveCommand();
    const args = [
      "serve",
      "--port",
      String(port),
      "--host",
      host,
      "--workflows-dir",
      workflowsDir,
      "--runs-dir",
      runsDir,
    ];

    // The token travels over an inherited pipe (fd 3), never argv or logs.
    const token = randomBytes(32).toString("base64url");
    args.push("--token-fd", "3");

    process.stderr.write(
      `[bridge] spawning: ${command} ${args.join(" ")} (cwd=${process.cwd()})\n`,
    );

    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe", "pipe"],
      env: buildChildEnv(),
    });
    this.child = child;

    const tokenPipe = child.stdio[3] as Writable;
    // A child that dies before draining fd 3 would otherwise surface the
    // failed token write as an unhandled stream error; the early-exit
    // guard below turns that scenario into a clean start() failure.
    tokenPipe.on("error", () => undefined);
    tokenPipe.end(token);

    child.stderr?.setEncoding("utf-8");
    child.stderr?.on("data", (chunk: string) => {
      process.stderr.write(`[testudo serve] ${chunk}`);
    });

    this.currentToken = token;
    this.currentUrl = `http://${host}:${port}`;
    this.currentPort = port;

    // Early-exit guard: settle as soon as the child leaves the running
    // state (spawn failure, instant crash, or later exit) so waitForHealth
    // can fail fast instead of polling a dead child for the full window.
    let settleExit!: (code: number | null) => void;
    const exited = new Promise<number | null>((accept) => {
      settleExit = accept;
    });
    child.once("exit", (code) => settleExit(code));
    child.once("error", (err: Error) => {
      process.stderr.write(`[bridge] child error: ${err.message}\n`);
      settleExit(null);
    });

    child.on("exit", (code) => {
      process.stderr.write(`[testudo serve] exited with ${code}\n`);
      this.currentToken = null;
      this.currentUrl = null;
      this.currentPort = null;
      this.child = null;
    });

    try {
      await this.waitForHealth(this.currentUrl!, 20_000, exited);
    } catch (err) {
      // Kill-on-failure: a child that never became healthy must not
      // survive start() as an orphan. SIGKILL because a child hung before
      // its event loop runs (e.g. before reading fd 3) cannot be trusted
      // to handle SIGTERM.
      this.killChild();
      this.lastError = (err as Error).message;
      throw err;
    }

    return this.status();
  }

  async request(path: string, method = "GET", body?: string): Promise<{ status: number; body: string }> {
    if (
      !this.currentUrl ||
      !this.currentToken ||
      !path.startsWith("/") ||
      path.startsWith("//") ||
      !["GET", "POST"].includes(method)
    ) {
      throw new Error("bridge-request-unavailable");
    }
    if (!isAllowedBridgePath(path)) {
      throw new Error("bridge-request-forbidden");
    }
    const response = await fetch(`${this.currentUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.currentToken}`,
      },
      body,
    });
    return { status: response.status, body: await response.text() };
  }

  async stop(): Promise<BridgeStatus> {
    if (!this.child || this.child.exitCode !== null) {
      this.child = null;
      this.currentToken = null;
      this.currentUrl = null;
      this.currentPort = null;
      return this.status();
    }
    return new Promise((accept) => {
      const child = this.child!;
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
      }, 5_000);
      child.once("exit", () => {
        clearTimeout(timer);
        this.child = null;
        this.currentToken = null;
        this.currentUrl = null;
        this.currentPort = null;
        accept(this.status());
      });
      child.kill("SIGTERM");
    });
  }

  killSync(): void {
    if (this.child && this.child.exitCode === null) {
      try {
        this.child.kill("SIGTERM");
      } catch {
        // ignore
      }
    }
  }

  /** Failure-path cleanup: kill an unhealthy child and scrub its state.
   * Only reached when the child was never proven healthy, so there is no
   * graceful-shutdown wait (see start()). */
  private killChild(): void {
    const child = this.child;
    this.child = null;
    this.currentToken = null;
    this.currentUrl = null;
    this.currentPort = null;
    if (child && child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone; nothing to clean up.
      }
    }
  }

  private async waitForHealth(
    url: string,
    timeoutMs: number,
    exited?: Promise<number | null>,
  ): Promise<void> {
    let exitCode: number | null | undefined;
    if (exited) {
      // `exited` only ever resolves, so this needs no rejection handling;
      // the flag check below is what short-circuits the poll loop.
      void exited.then((code) => {
        exitCode = code;
      });
    }
    const deadline = Date.now() + timeoutMs;
    let lastErr: unknown = null;
    while (Date.now() < deadline) {
      if (exitCode !== undefined) {
        throw new Error(`bridge exited before becoming healthy (code=${exitCode})`);
      }
      try {
        const r = await fetch(`${url}/health`);
        if (r.ok) return;
      } catch (err) {
        lastErr = err;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error(
      `bridge did not respond on ${url}/health within ${timeoutMs}ms (last: ${String(lastErr)})`,
    );
  }

  private resolveCommand(): string {
    const env = process.env.TESTUDO_CLI;
    if (env && existsSync(env)) {
      process.stderr.write(`[bridge] resolved testudo via TESTUDO_CLI=${env}\n`);
      return env;
    }

    if (app.isPackaged) {
      const bundled = join(process.resourcesPath, "testudo-bridge");
      process.stderr.write(`[bridge] packaged: using bundled binary at ${bundled}\n`);
      return bundled;
    }

    const repoRoot = resolve(__dirname, "../../..");
    const venvBin = join(repoRoot, ".venv", "bin", "testudo");
    if (existsSync(venvBin)) {
      process.stderr.write(`[bridge] resolved testudo via venv: ${venvBin}\n`);
      return venvBin;
    }

    process.stderr.write(
      `[bridge] no testudo at TESTUDO_CLI or ${venvBin}; falling back to PATH lookup ("testudo")\n`,
    );
    return "testudo";
  }

  private resolveWorkflowsDir(): string {
    const repoRoot = resolve(__dirname, "../../..");
    return join(repoRoot, "examples");
  }

  private resolveRunsDir(): string {
    const repoRoot = resolve(__dirname, "../../..");
    return join(repoRoot, "runs");
  }
}
