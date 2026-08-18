import { afterEach, describe, expect, it } from "vitest"
import { createServer, type Server } from "node:http"
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { spawn } from "node:child_process"
import { auth } from "@modelcontextprotocol/client"
import { abortable } from "../abort.ts"
import { McpOAuthProvider } from "../mcp-oauth-provider.ts"
import { getAuthEntry, getServerDir, invalidateAuthEntryCache, updateClientInfo, updateTokens } from "../mcp-auth.ts"
import { getAuthLockPath, ownsAuthLock, acquireAuthLock, releaseAuthLock } from "../mcp-auth-lock.ts"

const SERVER_NAME = "oauth-refresh-race-shared"
const AUTH_CACHE_DISABLED_ENV = "PI_MCP_ADAPTER_DISABLE_AUTH_CACHE"
const defaultAuthCacheDisabled = process.env[AUTH_CACHE_DISABLED_ENV]
const dirs: string[] = []
const servers: Server[] = []
async function directory() { const value = await mkdtemp(join(tmpdir(), "pi-oauth-race-")); dirs.push(value); return value }

interface EndpointOptions {
  metadataRequests?: number
  refreshDelayMs?: number
  hangFirstRefresh?: boolean
  stallFirstRefreshBody?: boolean
}

async function endpoint(options: EndpointOptions = {}) {
  const requiredMetadataRequests = options.metadataRequests ?? 1
  const refreshDelayMs = options.refreshDelayMs ?? 500
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
      if (metadataRequests >= requiredMetadataRequests) releaseMetadata()
      await metadataGate
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, response_types_supported: ["code"], grant_types_supported: ["refresh_token"], token_endpoint_auth_methods_supported: ["none"] })); return
    }
    if (req.url === "/token") {
      refreshes++
      let body = ""; for await (const chunk of req) body += chunk
      const supplied = new URLSearchParams(body).get("refresh_token")
      suppliedRefreshes.push(supplied)
      if (supplied !== validRefresh) { res.statusCode = 400; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ error: "invalid_grant" })); return }
      if (options.hangFirstRefresh && refreshes === 1) return
      if (options.stallFirstRefreshBody && refreshes === 1) {
        // Commit rotation before returning headers: the client cannot know whether the
        // submitted generation is still safe when the body never completes.
        validRefresh = "rotation-1"
        res.setHeader("content-type", "application/json")
        res.write('{"access_token":')
        res.flushHeaders()
        return
      }
      validRefresh = "rotation-1"
      await new Promise(resolve => setTimeout(resolve, refreshDelayMs))
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ access_token: "access-1", refresh_token: validRefresh, token_type: "Bearer", expires_in: 3600 })); return
    }
    res.statusCode = 404; res.end()
  })
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve)); servers.push(server)
  return { url: `http://127.0.0.1:${(server.address() as { port: number }).port}/mcp`, refreshes: () => refreshes, suppliedRefreshes }
}

function provider(url: string) { return new McpOAuthProvider(SERVER_NAME, url, { clientId: "test-client" }, { onRedirect: async () => {} }) }
async function run(url: string) { const p = provider(url); return auth(p, { serverUrl: url, fetchFn: p.createAuthFetchFn() }) }

async function setupExpiredRefresh(options: EndpointOptions = {}) {
  const mock = await endpoint(options)
  const store = await directory()
  process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = `file:${store}`
  await updateClientInfo(SERVER_NAME, { clientId: "test-client" }, mock.url)
  await updateTokens(SERVER_NAME, { accessToken: "expired", refreshToken: "rotation-0", expiresAt: 1 }, mock.url)
  return { mock, store }
}

async function abortActiveRefresh(mock: Awaited<ReturnType<typeof endpoint>>) {
  const controller = new AbortController()
  const first = new McpOAuthProvider(SERVER_NAME, mock.url, { clientId: "test-client" }, { onRedirect: async () => {} }, {}, controller.signal)
  const detachedOperation = first.withSdkAuth(() => auth(first, { serverUrl: mock.url, fetchFn: first.createAuthFetchFn() }))
  const callerOperation = abortable(detachedOperation, controller.signal)
  while (mock.refreshes() === 0) await new Promise(resolve => setTimeout(resolve, 10))
  controller.abort()
  await expect(callerOperation).rejects.toMatchObject({ name: "AbortError" })
  return { detachedOperation }
}

async function expectSuccessorReauthentication(url: string, timeoutMessage: string): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(timeoutMessage)), 3_000)
    })
    await expect(Promise.race([run(url), timeout])).rejects.toThrow("Re-authentication required")
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

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
  delete process.env.MCP_OAUTH_DETACHED_REFRESH_GRACE_MS
  if (defaultAuthCacheDisabled === undefined) delete process.env[AUTH_CACHE_DISABLED_ENV]
  else process.env[AUTH_CACHE_DISABLED_ENV] = defaultAuthCacheDisabled
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))))
  await Promise.all(dirs.splice(0).map(value => rm(value, { recursive: true, force: true })))
})

describe("OAuth refresh race", () => {
  it("refreshes issuer-less tokens without self-invalidating the transaction", async () => {
    const { mock } = await setupExpiredRefresh()
    await expect(run(mock.url)).resolves.toBe("AUTHORIZED")
    expect(getAuthEntry(SERVER_NAME)?.tokens?.issuer).toBe(mock.url.replace(/\/mcp$/, ""))
    expect(mock.refreshes()).toBe(1)
  })

  it("keeps a rotating refresh fenced after its caller aborts", async () => {
    const { mock } = await setupExpiredRefresh()
    await abortActiveRefresh(mock)

    await expect(run(mock.url)).resolves.toBe("AUTHORIZED")
    expect(mock.refreshes()).toBe(1)
    expect(getAuthEntry(SERVER_NAME)?.tokens).toMatchObject({ accessToken: "access-1", refreshToken: "rotation-1" })
  })

  it("bounds a detached refresh that never completes", async () => {
    const { mock } = await setupExpiredRefresh({ hangFirstRefresh: true })
    process.env.MCP_OAUTH_DETACHED_REFRESH_GRACE_MS = "100"
    const { detachedOperation } = await abortActiveRefresh(mock)

    await expectSuccessorReauthentication(mock.url, "successor refresh did not progress after detached refresh grace period")
    await expect(detachedOperation).rejects.toThrow("OAuth flow is no longer active")
    expect(mock.refreshes()).toBe(1)
    expect(getAuthEntry(SERVER_NAME)?.tokens).toBeUndefined()
    expect(getAuthEntry(SERVER_NAME)?.clientInfo).toMatchObject({ clientId: "test-client" })
  })

  it("quarantines a refresh committed before its response body stalls", async () => {
    const { mock } = await setupExpiredRefresh({ stallFirstRefreshBody: true })
    process.env.MCP_OAUTH_DETACHED_REFRESH_GRACE_MS = "100"
    const { detachedOperation } = await abortActiveRefresh(mock)

    await expectSuccessorReauthentication(mock.url, "successor refresh did not progress after stalled response grace period")
    await expect(detachedOperation).rejects.toThrow("OAuth flow is no longer active")
    expect(mock.refreshes()).toBe(1)
    expect(mock.suppliedRefreshes).toEqual(["rotation-0"])
    expect(getAuthEntry(SERVER_NAME)?.tokens).toBeUndefined()
    expect(getAuthEntry(SERVER_NAME)?.clientInfo).toMatchObject({ clientId: "test-client" })
  })

  it("keeps the credential lock outside a legacy directory removed by migration", async () => {
    const legacy = await directory(); const store = await directory(); process.env.MCP_OAUTH_DIR = legacy; process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = `file:${store}`
    const serverDir = getServerDir(SERVER_NAME); await mkdir(serverDir, { recursive: true }); await writeFile(join(serverDir, "tokens.json"), JSON.stringify({ serverUrl: "https://example/mcp", tokens: { accessToken: "old" } }))
    const acquired = await acquireAuthLock(SERVER_NAME)
    expect(getAuthEntry(SERVER_NAME)?.tokens?.accessToken).toBe("old")
    expect(ownsAuthLock(acquired.fence)).toBe(true)
    expect(getAuthLockPath(SERVER_NAME).startsWith(legacy)).toBe(false)
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

  it("performs one rotating refresh across processes with the production cache enabled", async () => {
    delete process.env[AUTH_CACHE_DISABLED_ENV]
    const { mock, store } = await setupExpiredRefresh({ metadataRequests: 2, refreshDelayMs: 1_000 })
    const barrier = await directory()
    const children = [child("one", mock.url, store, barrier), child("two", mock.url, store, barrier)]
    for (const id of ["one", "two"]) {
      while (true) { try { await access(join(barrier, `ready-${id}`)); break } catch { await new Promise(resolve => setTimeout(resolve, 10)) } }
    }
    await writeFile(join(barrier, "go"), "go")
    await Promise.all(children)
    expect(mock.refreshes(), JSON.stringify(mock.suppliedRefreshes)).toBe(1)
    invalidateAuthEntryCache(SERVER_NAME)
    expect(getAuthEntry(SERVER_NAME)?.tokens?.accessToken).toBe("access-1")
  })
})
