/**
 * Tests for mcp-auth.ts - Auth storage module
 */

import { describe, it, before, after } from "node:test"
import assert from "node:assert"
import { mkdirSync, rmSync, existsSync, writeFileSync } from "fs"
import { dirname, join } from "path"
import { tmpdir } from "os"
import { randomBytes } from "crypto"

// Set up isolated temp directory for tests
const TEST_DIR = join(tmpdir(), `mcp-oauth-test-${randomBytes(4).toString('hex')}`)
process.env.MCP_OAUTH_DIR = TEST_DIR

import {
  getAuthEntry,
  getAuthEntryFilePath,
  migrateLegacyAuthEntry,
  getAuthForUrl,
  saveAuthEntry,
  removeAuthEntry,
  updateTokens,
  updateTokensIfRevisionMatches,
  updateClientInfo,
  updateCodeVerifier,
  clearCodeVerifier,
  updateOAuthState,
  getOAuthState,
  clearOAuthState,
  isTokenExpired,
  hasStoredTokens,
  clearAllCredentials,
  clearClientInfo,
  clearTokens,
  resetTestAuthSecretStore,
  loadTestKeyringEntryClass,
  type AuthEntry,
} from "./mcp-auth.ts"

describe("mcp-auth", () => {
  before(() => {
    // Ensure clean state
    try {
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, { recursive: true, force: true })
      }
      mkdirSync(TEST_DIR, { recursive: true })
    } catch {
      // Ignore cleanup errors
    }
  })

  after(() => {
    // Clean up temp directory
    try {
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, { recursive: true, force: true })
      }
    } catch {
      // Ignore cleanup errors
    }
  })


  describe("keyring native binding fallback", () => {
    class FakeEntry {
      constructor(readonly service: string, readonly account: string) {}
      getPassword(): string | null { return null }
      setPassword(): void {}
      deleteCredential(): boolean { return true }
    }

    it("loads the native binding by absolute path when the package loader fails", async () => {
      const loaderError = new Error("package loader failed")
      const nativePath = "/tmp/keyring-darwin-arm64/keyring.darwin-arm64.node"
      const required: string[] = []
      const requireStub = Object.assign((id: string) => {
        required.push(id)
        if (id === "@napi-rs/keyring") throw loaderError
        if (id === nativePath) return { Entry: FakeEntry }
        throw new Error(`unexpected require: ${id}`)
      }, {
        resolve(id: string) {
          assert.strictEqual(id, "@napi-rs/keyring-darwin-arm64/package.json")
          return "/tmp/keyring-darwin-arm64/package.json"
        },
      })

      const Entry = loadTestKeyringEntryClass(requireStub, "darwin", "arm64")

      assert.strictEqual(Entry, FakeEntry)
      assert.deepStrictEqual(required, ["@napi-rs/keyring", nativePath])
    })

    it("tries the Linux musl package when the gnu package is unavailable", async () => {
      const loaderError = new Error("package loader failed")
      const nativePath = "/tmp/keyring-linux-x64-musl/keyring.linux-x64-musl.node"
      const resolved: string[] = []
      const requireStub = Object.assign((id: string) => {
        if (id === "@napi-rs/keyring") throw loaderError
        if (id === nativePath) return { Entry: FakeEntry }
        throw new Error(`unexpected require: ${id}`)
      }, {
        resolve(id: string) {
          resolved.push(id)
          if (id === "@napi-rs/keyring-linux-x64-musl/package.json") return "/tmp/keyring-linux-x64-musl/package.json"
          throw new Error(`missing package: ${id}`)
        },
      })

      const Entry = loadTestKeyringEntryClass(requireStub, "linux", "x64")

      assert.strictEqual(Entry, FakeEntry)
      assert.deepStrictEqual(resolved, [
        "@napi-rs/keyring-linux-x64-gnu/package.json",
        "@napi-rs/keyring-linux-x64-musl/package.json",
      ])
    })

    it("keeps the original loader error in the cause chain when fallback fails", async () => {
      const loaderError = new Error("package loader failed")
      const fallbackError = new Error("native binding failed")
      const requireStub = Object.assign((id: string) => {
        if (id === "@napi-rs/keyring") throw loaderError
        throw fallbackError
      }, {
        resolve() { return "/tmp/keyring-darwin-arm64/package.json" },
      })

      assert.throws(() => loadTestKeyringEntryClass(requireStub, "darwin", "arm64"), (error) => {
        assert(error instanceof Error)
        assert.match(error.message, /absolute-path native binding fallback also failed: native binding failed/)
        let current: unknown = error
        while (current && typeof current === "object") {
          if (current === loaderError) return true
          current = (current as { cause?: unknown }).cause
        }
        assert.fail("original loader error was not preserved in the cause chain")
      })
    })
  })

  describe("getAuthEntry", () => {
    it("should return undefined for non-existent entry", async () => {
      const entry = getAuthEntry("non-existent")
      assert.strictEqual(entry, undefined)
    })

    it("should import legacy plaintext entries and remove the file", async () => {
      const filePath = getAuthEntryFilePath("legacy-import")
      mkdirSync(dirname(filePath), { recursive: true })
      writeFileSync(filePath, JSON.stringify({
        tokens: { accessToken: "legacy-token" },
        serverUrl: "https://api.example.com",
      }), "utf-8")

      const entry = await migrateLegacyAuthEntry("legacy-import")
      assert.strictEqual(entry?.tokens?.accessToken, "legacy-token")
      assert.strictEqual(existsSync(filePath), false)
      assert.strictEqual(getAuthEntry("legacy-import")?.tokens?.accessToken, "legacy-token")
    })

    it("should reject malformed legacy plaintext entries", () => {
      const filePath = getAuthEntryFilePath("legacy-invalid")
      mkdirSync(dirname(filePath), { recursive: true })
      writeFileSync(filePath, JSON.stringify({
        tokens: { refreshToken: "missing-access-token" },
      }), "utf-8")

      assert.throws(
        () => getAuthEntry("legacy-invalid"),
        /Failed to parse OAuth credentials.*invalid credential shape/,
      )
      assert.strictEqual(existsSync(filePath), true)
    })

    it("should fail closed when the secure credential store is unavailable", () => {
      const previous = process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE
      process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "unavailable"
      resetTestAuthSecretStore()
      try {
        assert.throws(
          () => getAuthEntry("secure-store-unavailable"),
          /Failed to read OAuth credentials.*OS secure credential store/,
        )
      } finally {
        if (previous === undefined) {
          delete process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE
        } else {
          process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = previous
        }
      }
    })
  })

  describe("saveAuthEntry / getAuthEntry", () => {
    it("should save and retrieve an auth entry", async () => {
      const entry: AuthEntry = {
        tokens: {
          accessToken: "test-token",
          refreshToken: "refresh-token",
          expiresAt: 1234567890,
          scope: "read write",
        },
        serverUrl: "https://api.example.com",
      }

      await saveAuthEntry("test-server", entry, "https://api.example.com")
      const retrieved = getAuthEntry("test-server")

      assert.deepStrictEqual(retrieved, entry)
    })

    it("should update existing entries", async () => {
      const entry1: AuthEntry = {
        tokens: { accessToken: "token1" },
        serverUrl: "https://api.example.com",
      }
      const entry2: AuthEntry = {
        tokens: { accessToken: "token2" },
        serverUrl: "https://api.example.com",
      }

      await saveAuthEntry("test-server", entry1, "https://api.example.com")
      await saveAuthEntry("test-server", entry2, "https://api.example.com")
      const retrieved = getAuthEntry("test-server")

      assert.strictEqual(retrieved?.tokens?.accessToken, "token2")
    })
  })

  describe("getAuthForUrl", () => {
    it("should return entry when URL matches", async () => {
      const entry: AuthEntry = {
        tokens: { accessToken: "test-token" },
        serverUrl: "https://api.example.com",
      }

      await saveAuthEntry("test-server", entry, "https://api.example.com")
      const retrieved = getAuthForUrl("test-server", "https://api.example.com")

      assert.deepStrictEqual(retrieved, entry)
    })

    it("should return undefined when URL doesn't match", async () => {
      const entry: AuthEntry = {
        tokens: { accessToken: "test-token" },
        serverUrl: "https://api.example.com",
      }

      await saveAuthEntry("test-server", entry, "https://api.example.com")
      const retrieved = getAuthForUrl("test-server", "https://different.com")

      assert.strictEqual(retrieved, undefined)
    })

    it("should return undefined when serverUrl is not stored", async () => {
      const entry: AuthEntry = {
        tokens: { accessToken: "test-token" },
      }

      await saveAuthEntry("test-server", entry)
      const retrieved = getAuthForUrl("test-server", "https://api.example.com")

      assert.strictEqual(retrieved, undefined)
    })
  })

  describe("removeAuthEntry", () => {
    it("should remove an entry", async () => {
      const entry: AuthEntry = {
        tokens: { accessToken: "test-token" },
      }

      await saveAuthEntry("test-server", entry)
      await removeAuthEntry("test-server")
      const retrieved = getAuthEntry("test-server")

      assert.strictEqual(retrieved, undefined)
    })
  })

  describe("updateTokens", () => {
    it("should update tokens for a server", async () => {
      await updateTokens("test-server", {
        accessToken: "new-token",
        refreshToken: "new-refresh",
        expiresAt: 1234567890,
        scope: "read",
      })

      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.tokens?.accessToken, "new-token")
    })

    it("should preserve existing client info", async () => {
      await updateClientInfo("test-server", { clientId: "client-123" })
      await updateTokens("test-server", { accessToken: "token" })

      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.clientInfo?.clientId, "client-123")
      assert.strictEqual(entry?.tokens?.accessToken, "token")
    })

    it("should clear URL-bound auth state when tokens move to a different server URL", async () => {
      await saveAuthEntry("token-url-change", {
        tokens: { accessToken: "old-token", refreshToken: "old-refresh" },
        clientInfo: { clientId: "old-client" },
        codeVerifier: "old-verifier",
        oauthState: "old-state",
        serverUrl: "https://old.example.com/mcp",
      }, "https://old.example.com/mcp")

      await updateTokens("token-url-change", { accessToken: "new-token" }, "https://new.example.com/mcp")

      assert.strictEqual(getAuthForUrl("token-url-change", "https://old.example.com/mcp"), undefined)
      const newEntry = getAuthForUrl("token-url-change", "https://new.example.com/mcp")
      assert.strictEqual(newEntry?.tokens?.accessToken, "new-token")
      assert.strictEqual(newEntry?.clientInfo, undefined)
      assert.strictEqual(newEntry?.codeVerifier, undefined)
      assert.strictEqual(newEntry?.oauthState, undefined)
    })

    it("should clear legacy URL-bound auth state when saving tokens with a server URL", async () => {
      await saveAuthEntry("token-legacy-url-change", {
        tokens: { accessToken: "old-token", refreshToken: "old-refresh" },
        clientInfo: { clientId: "old-client" },
        codeVerifier: "old-verifier",
        oauthState: "old-state",
      })

      await updateTokens("token-legacy-url-change", { accessToken: "new-token" }, "https://new.example.com/mcp")

      const newEntry = getAuthForUrl("token-legacy-url-change", "https://new.example.com/mcp")
      assert.strictEqual(newEntry?.tokens?.accessToken, "new-token")
      assert.strictEqual(newEntry?.clientInfo, undefined)
      assert.strictEqual(newEntry?.codeVerifier, undefined)
      assert.strictEqual(newEntry?.oauthState, undefined)
    })
  })

  describe("updateClientInfo", () => {
    it("should update client info for a server", async () => {
      await updateClientInfo("test-server", {
        clientId: "client-123",
        clientSecret: "secret",
        clientIdIssuedAt: 1234567890,
        clientSecretExpiresAt: 1234567999,
      })

      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.clientInfo?.clientId, "client-123")
      assert.strictEqual(entry?.clientInfo?.clientSecret, "secret")
    })

    it("should clear URL-bound credentials when client info moves to a different server URL", async () => {
      await saveAuthEntry("url-change", {
        tokens: { accessToken: "old-token", refreshToken: "old-refresh" },
        clientInfo: { clientId: "old-client" },
        codeVerifier: "old-verifier",
        oauthState: "old-state",
        serverUrl: "https://old.example.com/mcp",
      }, "https://old.example.com/mcp")

      await updateClientInfo("url-change", { clientId: "new-client" }, "https://new.example.com/mcp")

      assert.strictEqual(getAuthForUrl("url-change", "https://old.example.com/mcp"), undefined)
      const newEntry = getAuthForUrl("url-change", "https://new.example.com/mcp")
      assert.strictEqual(newEntry?.clientInfo?.clientId, "new-client")
      assert.strictEqual(newEntry?.tokens, undefined)
      assert.strictEqual(newEntry?.codeVerifier, undefined)
      assert.strictEqual(newEntry?.oauthState, undefined)
    })

    it("should clear stale verifier and state when legacy client info gains a server URL", async () => {
      await saveAuthEntry("legacy-url-change", {
        tokens: { accessToken: "old-token", refreshToken: "old-refresh" },
        clientInfo: { clientId: "old-client" },
        codeVerifier: "old-verifier",
        oauthState: "old-state",
      })

      await updateClientInfo("legacy-url-change", { clientId: "new-client" }, "https://new.example.com/mcp")

      const newEntry = getAuthForUrl("legacy-url-change", "https://new.example.com/mcp")
      assert.strictEqual(newEntry?.clientInfo?.clientId, "new-client")
      assert.strictEqual(newEntry?.tokens, undefined)
      assert.strictEqual(newEntry?.codeVerifier, undefined)
      assert.strictEqual(newEntry?.oauthState, undefined)
    })
  })

  describe("updateCodeVerifier / clearCodeVerifier", () => {
    it("should save and retrieve code verifier", async () => {
      await updateCodeVerifier("test-server", "verifier-123")
      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.codeVerifier, "verifier-123")
    })

    it("should clear code verifier", async () => {
      await updateCodeVerifier("test-server", "verifier-123")
      await clearCodeVerifier("test-server")
      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.codeVerifier, undefined)
    })
  })

  describe("updateOAuthState / getOAuthState / clearOAuthState", () => {
    it("should save and retrieve OAuth state", async () => {
      await updateOAuthState("test-server", "state-abc-123")
      const state = getOAuthState("test-server")
      assert.strictEqual(state, "state-abc-123")
    })

    it("should clear OAuth state", async () => {
      await updateOAuthState("test-server", "state-abc-123")
      await clearOAuthState("test-server")
      const state = getOAuthState("test-server")
      assert.strictEqual(state, undefined)
    })
  })

  describe("isTokenExpired", () => {
    it("should return null if no tokens", async () => {
      const expired = isTokenExpired("expiry-test-null")
      assert.strictEqual(expired, null)
    })

    it("should return false if no expiry", async () => {
      await updateTokens("expiry-test-no-expiry", { accessToken: "token" })
      const expired = isTokenExpired("expiry-test-no-expiry")
      assert.strictEqual(expired, false)
    })

    it("should return true if expired", async () => {
      await updateTokens("expiry-test-expired", {
        accessToken: "token",
        expiresAt: 1, // Way in the past
      })
      const expired = isTokenExpired("expiry-test-expired")
      assert.strictEqual(expired, true)
    })

    it("should return false if not expired", async () => {
      await updateTokens("expiry-test-future", {
        accessToken: "token",
        expiresAt: Date.now() / 1000 + 3600, // 1 hour from now
      })
      const expired = isTokenExpired("expiry-test-future")
      assert.strictEqual(expired, false)
    })
  })

  describe("hasStoredTokens", () => {
    it("should return false if no tokens", async () => {
      assert.strictEqual(hasStoredTokens("has-tokens-test-false"), false)
    })

    it("should return true if tokens exist", async () => {
      await updateTokens("has-tokens-test-true", { accessToken: "token" })
      assert.strictEqual(hasStoredTokens("has-tokens-test-true"), true)
    })
  })

  describe("clearAllCredentials", () => {
    it("should remove all credentials", async () => {
      await updateTokens("test-server", { accessToken: "token" })
      await updateClientInfo("test-server", { clientId: "client" })
      await updateCodeVerifier("test-server", "verifier")

      await clearAllCredentials("test-server")

      assert.strictEqual(getAuthEntry("test-server"), undefined)
    })
  })

  describe("clearClientInfo", () => {
    it("should only remove client info", async () => {
      await updateTokens("test-server", { accessToken: "token" })
      await updateClientInfo("test-server", { clientId: "client" })

      await clearClientInfo("test-server")

      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.clientInfo, undefined)
      assert.strictEqual(entry?.tokens?.accessToken, "token")
    })
  })

  describe("token revision fencing", () => {
    it("rejects publication from a stale refresh snapshot", async () => {
      const name = "stale-refresh-publication"
      await updateTokens(name, { accessToken: "old" }, "https://example.com")
      const staleRevision = getAuthForUrl(name, "https://example.com")?.tokenRevision
      await updateTokens(name, { accessToken: "successor" }, "https://example.com")

      assert.strictEqual(await updateTokensIfRevisionMatches(
        name,
        { accessToken: "stale-result" },
        staleRevision,
        "https://example.com",
      ), false)
      assert.strictEqual(getAuthForUrl(name, "https://example.com")?.tokens?.accessToken, "successor")
    })
  })

  describe("clearTokens", () => {
    it("should only remove tokens", async () => {
      await updateTokens("test-server", { accessToken: "token" })
      await updateClientInfo("test-server", { clientId: "client" })

      await clearTokens("test-server")

      const entry = getAuthEntry("test-server")
      assert.strictEqual(entry?.tokens, undefined)
      assert.strictEqual(entry?.clientInfo?.clientId, "client")
    })
  })
})
