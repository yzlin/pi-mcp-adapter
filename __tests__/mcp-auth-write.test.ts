import { afterEach, describe, expect, it } from "vitest"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { getAuthEntry, resetTestAuthSecretStore, updateTokens, updateTokensIfRevisionMatches } from "../mcp-auth.ts"
import { acquireAuthLock, ownsAuthLock, releaseAuthLock } from "../mcp-auth-lock.ts"

afterEach(() => {
  resetTestAuthSecretStore()
  delete process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE
})

describe("OAuth credential fenced writes", () => {
  it("rejects a stale revision without overwriting its successor", async () => {
    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "memory"
    await updateTokens("write-fence", { accessToken: "first" }, "https://example/mcp")
    const stale = getAuthEntry("write-fence")!.tokenRevision
    await updateTokens("write-fence", { accessToken: "successor" }, "https://example/mcp")
    expect(await updateTokensIfRevisionMatches("write-fence", { accessToken: "stale" }, stale, "https://example/mcp")).toBe(false)
    expect(getAuthEntry("write-fence")?.tokens?.accessToken).toBe("successor")
  })

  it("does not let a displaced owner remove a replacement generation", async () => {
    const first = await acquireAuthLock("write-generation")
    rmSync(first.fence.lockPath, { recursive: true, force: true })
    const successor = await acquireAuthLock("write-generation")
    await releaseAuthLock(first.fence, first.handle)
    expect(ownsAuthLock(successor.fence)).toBe(true)
    await releaseAuthLock(successor.fence, successor.handle)
  })
})
