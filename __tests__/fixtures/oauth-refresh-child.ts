import { auth } from "@modelcontextprotocol/client";
import { writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import { McpOAuthProvider } from "../../mcp-oauth-provider.ts";

const [attemptId, serverUrl] = process.argv.slice(2);
const started = performance.now();
const barrier = process.env.PI_OAUTH_TEST_BARRIER;
if (barrier) {
  await writeFile(join(barrier, `ready-${attemptId}`), "ready");
  while (true) {
    try { await access(join(barrier, "go")); break } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
  }
}
const provider = new McpOAuthProvider("oauth-refresh-race-shared", serverUrl, { clientId: "test-client" }, { onRedirect: async () => {} });
try {
  const outcome = await auth(provider, { serverUrl, fetchFn: provider.createAuthFetchFn() });
  console.log(JSON.stringify({ attemptId, pid: process.pid, elapsedMs: Math.round(performance.now() - started), outcome }));
} catch (error) {
  console.log(JSON.stringify({ attemptId, pid: process.pid, elapsedMs: Math.round(performance.now() - started), outcome: error instanceof Error ? error.name : "error" }));
  process.exitCode = 1;
}
