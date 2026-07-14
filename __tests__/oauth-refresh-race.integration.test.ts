import { afterEach, describe, expect, it } from "vitest"
import { createServer, type Server } from "node:http"
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawn } from "node:child_process"
import { auth } from "@modelcontextprotocol/client"
import { McpOAuthProvider } from "../mcp-oauth-provider.ts"
import { getAuthEntry, getServerDir, updateClientInfo, updateTokens } from "../mcp-auth.ts"
import { getAuthLockPath, ownsAuthLock, acquireAuthLock, releaseAuthLock } from "../mcp-auth-lock.ts"

const dirs: string[] = []
const servers: Server[] = []
async function directory() { const value = await mkdtemp(join(tmpdir(), "pi-oauth-race-")); dirs.push(value); return value }

async function endpoint() {
  let refreshes = 0
  let validRefresh = "rotation-0"
  const suppliedRefreshes: Array<string | null> = []
  let metadataRequests = 0
  let releaseMetadata!: () => void
  const metadataGate = new Promise<void>(resolve => { releaseMetadata = resolve })
  const server = createServer(async (req, res) => {
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
    if (req.url?.startsWith("/.well-known/oauth-protected-resource")) {
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ resource: `${base}/mcp`, authorization_servers: [base] })); return
    }
    if (req.url?.startsWith("/.well-known/oauth-authorization-server")) {
      metadataRequests++
      if (metadataRequests >= 2) releaseMetadata()
      await Promise.race([metadataGate, new Promise(resolve => setTimeout(resolve, 200))])
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, response_types_supported: ["code"], grant_types_supported: ["refresh_token"], token_endpoint_auth_methods_supported: ["none"] })); return
    }
    if (req.url === "/token") {
      refreshes++
      let body = ""; for await (const chunk of req) body += chunk
      const supplied = new URLSearchParams(body).get("refresh_token")
      suppliedRefreshes.push(supplied)
      if (supplied !== validRefresh) { res.statusCode = 400; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ error: "invalid_grant" })); return }
      validRefresh = "rotation-1"
      await new Promise(resolve => setTimeout(resolve, 500))
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ access_token: "access-1", refresh_token: validRefresh, token_type: "Bearer", expires_in: 3600 })); return
    }
    res.statusCode = 404; res.end()
  })
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); servers.push(server)
  return { url: `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`, refreshes: () => refreshes, suppliedRefreshes }
}

function provider(url: string) { return new McpOAuthProvider("shared", url, { clientId: "test-client" }, { onRedirect: async () => {} }) }
async function run(url: string) { const p = provider(url); return auth(p, { serverUrl: url, fetchFn: p.createAuthFetchFn() }) }

function child(id: string, url: string, store: string, barrier?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const processHandle = spawn(process.execPath, ["--import", "tsx", "__tests__/fixtures/oauth-refresh-child.ts", id, url], { cwd: process.cwd(), env: { ...process.env, PI_MCP_ADAPTER_TEST_AUTH_STORE: `file:${store}`, ...(barrier ? { PI_OAUTH_TEST_BARRIER: barrier } : {}) } })
    let output = ""; processHandle.stdout.on("data", chunk => output += chunk); processHandle.stderr.on("data", chunk => output += chunk)
    processHandle.on("close", code => code === 0 ? resolve() : reject(new Error(output)))
  })
}

afterEach(async () => {
  delete process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE
  delete process.env.MCP_OAUTH_DIR
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))))
  await Promise.all(dirs.splice(0).map(value => rm(value, { recursive: true, force: true })))
})

describe("OAuth refresh race", () => {
  it("refreshes issuer-less tokens without self-invalidating the transaction", async () => {
    const mock = await endpoint(); const store = await directory(); process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = `file:${store}`
    await updateClientInfo("shared", { clientId: "test-client" }, mock.url)
    await updateTokens("shared", { accessToken: "expired", refreshToken: "rotation-0", expiresAt: 1 }, mock.url)
    await expect(run(mock.url)).resolves.toBe("AUTHORIZED")
    expect(getAuthEntry("shared")?.tokens?.issuer).toBe(mock.url.replace(/\/mcp$/, ""))
    expect(mock.refreshes()).toBe(1)
  })

  it("keeps the credential lock outside a legacy directory removed by migration", async () => {
    const legacy = await directory(); const store = await directory(); process.env.MCP_OAUTH_DIR = legacy; process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = `file:${store}`
    const serverDir = getServerDir("shared"); await mkdir(serverDir, { recursive: true }); await writeFile(join(serverDir, "tokens.json"), JSON.stringify({ serverUrl: "https://example/mcp", tokens: { accessToken: "old" } }))
    const acquired = await acquireAuthLock("shared")
    expect(getAuthEntry("shared")?.tokens?.accessToken).toBe("old")
    expect(ownsAuthLock(acquired.fence)).toBe(true)
    expect(getAuthLockPath("shared").startsWith(legacy)).toBe(false)
    await releaseAuthLock(acquired.fence, acquired.handle)
  })

  it("does not let a stale generation delete its successor", async () => {
    const first = await acquireAuthLock("generation")
    await rm(first.fence.lockPath, { recursive: true, force: true })
    const second = await acquireAuthLock("generation")
    await releaseAuthLock(first.fence, first.handle)
    expect(ownsAuthLock(second.fence)).toBe(true)
    await releaseAuthLock(second.fence, second.handle)
  })

  it("performs one rotating refresh across processes", async () => {
    const mock = await endpoint(); const store = await directory(); process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = `file:${store}`
    await updateClientInfo("shared", { clientId: "test-client" }, mock.url)
    await updateTokens("shared", { accessToken: "expired", refreshToken: "rotation-0", expiresAt: 1 }, mock.url)
    const barrier = await directory()
    const children = [child("one", mock.url, store, barrier), child("two", mock.url, store, barrier)]
    for (const id of ["one", "two"]) {
      while (true) { try { await access(join(barrier, `ready-${id}`)); break } catch { await new Promise(resolve => setTimeout(resolve, 10)) } }
    }
    await writeFile(join(barrier, "go"), "go")
    await Promise.all(children)
    expect(mock.refreshes(), JSON.stringify(mock.suppliedRefreshes)).toBe(1)
    expect(getAuthEntry("shared")?.tokens?.accessToken).toBe("access-1")
  })
})
