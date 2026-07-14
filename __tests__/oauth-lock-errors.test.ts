import { afterEach, describe, expect, it } from "vitest"
import { mkdir, rm, utimes, writeFile } from "node:fs/promises"
import { acquireAuthLock, getAuthLockPath } from "../mcp-auth-lock.ts"

afterEach(async () => {
  delete process.env.MCP_OAUTH_LOCK_WAIT_MS
  delete process.env.MCP_OAUTH_LOCK_STALE_MS
  await rm(getAuthLockPath("lock-error"), { recursive: true, force: true })
})

describe("OAuth lock filesystem errors", () => {
  it("times out rather than deleting a fresh foreign generation", async () => {
    process.env.MCP_OAUTH_LOCK_WAIT_MS = "50"
    const lock = getAuthLockPath("lock-error")
    await mkdir(lock, { recursive: true })
    await writeFile(`${lock}/owner`, "999999:foreign")
    await expect(acquireAuthLock("lock-error")).rejects.toThrow(/Timed out/)
  })

  it("recovers a stale dead-owner generation", async () => {
    process.env.MCP_OAUTH_LOCK_STALE_MS = "1000"
    const lock = getAuthLockPath("lock-error")
    await mkdir(lock, { recursive: true })
    await writeFile(`${lock}/owner`, "999999:dead")
    const old = new Date(Date.now() - 2_000)
    await utimes(`${lock}/owner`, old, old)
    const acquired = await acquireAuthLock("lock-error")
    expect(acquired.fence.owner).not.toBe("999999:dead")
    await acquired.handle.close()
    await rm(acquired.fence.lockPath, { recursive: true, force: true })
  })
})
