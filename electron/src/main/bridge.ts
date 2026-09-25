/**
 * BridgeManager: owns the testudo serve subprocess.
 *
 * The renderer asks the main process to start / stop / inspect the bridge
 * via IPC. This module is the single source of truth for the child
 * process. The bearer token remains main-process-only; renderer requests
 * cross a narrow IPC proxy that attaches authentication here.
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

    const token = randomBytes(32).toString("base64url");
    args.push("--token-fd", "3");

    process.stderr.write(
      `[bridge] spawning: ${command} ${args.join(" ")} (cwd=${process.cwd()})\n`,
    );

    const childEnv = { ...process.env };
    for (const name of [
      "OPENAI_API_KEY",
      "TESTUDO_OPENAI_API_KEY",
      "OPENROUTER_API_KEY",
      "DATABRICKS_TOKEN",
    ]) {
      delete childEnv[name];
    }
    this.child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe", "pipe"],
      env: childEnv,
    });
    const tokenPipe = this.child.stdio[3] as Writable;
    tokenPipe.end(token);
    this.child.stderr?.setEncoding("utf-8");
    this.child.stderr?.on("data", (chunk: string) => {
      process.stderr.write(`[testudo serve] ${chunk}`);
    });
    this.currentToken = token;
    this.currentUrl = `http://${host}:${port}`;
    this.currentPort = port;

    // Wait for /health to respond
    await this.waitForHealth(this.currentUrl!, 20_000);

    this.child.on("exit", (code) => {
      process.stderr.write(`[testudo serve] exited with ${code}\n`);
      this.currentToken = null;
      this.currentUrl = null;
      this.currentPort = null;
      this.child = null;
    });

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

  private killChild(): void {
    if (this.child) {
      try {
        this.child.kill("SIGTERM");
      } catch {
        // ignore
      }
      this.child = null;
    }
  }

  private async waitForHealth(url: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    let lastErr: unknown = null;
    while (Date.now() < deadline) {
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
