import { createHash, randomUUID } from "node:crypto"
import { mkdirSync, openSync, readFileSync, rmSync, statSync, writeSync, closeSync, fsyncSync } from "node:fs"
import { mkdir, open, readFile, rename, rm, stat, writeFile, type FileHandle } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"

export interface AuthLockFence {
  lockPath: string
  ownerPath: string
  owner: string
  dev: number
  ino: number
}

type RecoveryClaim = { claimant: string; owner: string | null; dev: number; ino: number; expiresAt: number }
type Generation = { owner: string | undefined; dev: number; ino: number; mtimeMs: number }
const DEFAULT_WAIT_MS = 15_000
const DEFAULT_STALE_MS = 30_000
const MIN_STALE_MS = 1_000
const MAX_TIMER_DELAY = 2_147_483_647
const RECOVERY_LEASE_MS = 1_000
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

function timing(name: "MCP_OAUTH_LOCK_WAIT_MS" | "MCP_OAUTH_LOCK_STALE_MS", fallback: number): number {
  const value = process.env[name]
  if (value === undefined) return fallback
  const parsed = Number(value)
  const minimum = name === "MCP_OAUTH_LOCK_STALE_MS" ? MIN_STALE_MS : 1
  return Number.isInteger(parsed) && parsed >= minimum && parsed <= MAX_TIMER_DELAY ? parsed : fallback
}

function namespace(serverName: string): string {
  if (typeof serverName !== "string") throw new Error(`Invalid MCP server name: ${JSON.stringify(serverName)}`)
  const account = `sha256-${createHash("sha256").update(serverName, "utf8").digest("hex")}`
  const uid = typeof process.getuid === "function" ? process.getuid() : "nouid"
  return join(tmpdir(), `pi-mcp-adapter-oauth-${uid}`, account)
}

/** Long-lived refresh lease path. Stable across agent/storage directory configuration. */
export function getAuthLockPath(serverName: string): string { return join(namespace(serverName), "refresh.lock") }
/** Short-lived credential read-modify-write lock, keyed exactly by keyring service/account. */
export function getCredentialLockPath(serverName: string): string { return join(namespace(serverName), "credential.lock") }

function expected(error: unknown, contention = false): boolean {
  const code = (error as NodeJS.ErrnoException).code
  return code === "ENOENT" || code === "ENOTDIR" || (contention && (code === "EEXIST" || code === "ENOTEMPTY"))
}
function parseClaim(value: string): RecoveryClaim | undefined {
  try {
    const c = JSON.parse(value) as Partial<RecoveryClaim>
    if (typeof c.claimant !== "string" || (typeof c.owner !== "string" && c.owner !== null)
      || !Number.isFinite(c.dev) || !Number.isFinite(c.ino) || !Number.isFinite(c.expiresAt)) return undefined
    return c as RecoveryClaim
  } catch { return undefined }
}
function alive(owner: string): boolean | undefined {
  const pid = /^(\d+):/.exec(owner)?.[1]
  if (!pid) return undefined
  try { process.kill(Number(pid), 0); return true } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH" ? false : true
  }
}
async function readMaybe(path: string): Promise<string | undefined> {
  try { return await readFile(path, "utf8") } catch (error) { if (expected(error)) return undefined; throw error }
}
async function inspect(lockPath: string): Promise<Generation> {
  const ownerPath = join(lockPath, "owner")
  try {
    const [owner, lease] = await Promise.all([readFile(ownerPath, "utf8"), stat(ownerPath)])
    return { owner, dev: lease.dev, ino: lease.ino, mtimeMs: lease.mtimeMs }
  } catch (error) {
    if (!expected(error)) throw error
    const lease = await stat(lockPath)
    return { owner: undefined, dev: lease.dev, ino: lease.ino, mtimeMs: lease.mtimeMs }
  }
}
function same(a: Generation, b: Generation): boolean { return a.owner === b.owner && a.dev === b.dev && a.ino === b.ino }

async function recover(lockPath: string, staleMs: number): Promise<void> {
  let observed: Generation
  try { observed = await inspect(lockPath) } catch (error) { if (expected(error)) return; throw error }
  const releasedPath = join(lockPath, "released")
  const released = await readMaybe(releasedPath)
  if (released === undefined && Date.now() - observed.mtimeMs <= staleMs) return

  const recoveryPath = join(lockPath, ".recovery")
  const publicationPath = join(lockPath, ".publication")
  const claimant = `${process.pid}:${randomUUID()}`
  const claim: RecoveryClaim = { claimant, owner: observed.owner ?? null, dev: observed.dev, ino: observed.ino, expiresAt: Date.now() + RECOVERY_LEASE_MS }
  const serialized = JSON.stringify(claim)
  try {
    await writeFile(recoveryPath, serialized, { flag: "wx", mode: 0o600 })
  } catch (error) {
    if (!expected(error, true)) throw error
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") return
    try {
      const [markerText, markerStat] = await Promise.all([readFile(recoveryPath, "utf8"), stat(recoveryPath)])
      const existing = parseClaim(markerText)
      const expired = existing ? existing.expiresAt <= Date.now() : Date.now() - markerStat.mtimeMs > RECOVERY_LEASE_MS
      if (!expired) return
      const [current, markerNow, markerTextNow] = await Promise.all([inspect(lockPath), stat(recoveryPath), readFile(recoveryPath, "utf8")])
      const markerSame = markerNow.dev === markerStat.dev && markerNow.ino === markerStat.ino
        && (existing ? parseClaim(markerTextNow)?.claimant === existing.claimant : markerTextNow === markerText)
      if (same(observed, current) && markerSame) await rm(recoveryPath, { force: true })
    } catch (inner) { if (!expected(inner)) throw inner }
    return
  }

  let gated = false
  try {
    const marker = parseClaim(await readFile(recoveryPath, "utf8"))
    let current = await inspect(lockPath)
    if (marker?.claimant !== claimant || !same(observed, current)) return
    // A live heartbeat after the claim was formed wins. Partial generations get a full lease.
    if (released === undefined && Date.now() - current.mtimeMs <= staleMs) return
    try {
      await writeFile(publicationPath, claimant, { flag: "wx", mode: 0o600 }); gated = true
      current = await inspect(lockPath)
      // Re-check generation and staleness inside the publication gate.
      if (same(observed, current)
        && (await readMaybe(releasedPath) !== undefined || Date.now() - current.mtimeMs > staleMs)) {
        await rm(lockPath, { recursive: true, force: true })
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
      try {
        const [publisher, gate, gatedGeneration] = await Promise.all([readFile(publicationPath, "utf8"), stat(publicationPath), inspect(lockPath)])
        const ownerAlive = alive(publisher)
        if (same(observed, gatedGeneration) && (ownerAlive === false || (ownerAlive === undefined && Date.now() - gate.mtimeMs > staleMs))) {
          await rm(publicationPath, { force: true })
        }
      } catch (inner) { if (!expected(inner)) throw inner }
    }
  } finally {
    try { if (gated && await readFile(publicationPath, "utf8") === claimant) await rm(publicationPath, { force: true }) } catch (error) { if (!expected(error)) throw error }
    try { if (parseClaim(await readFile(recoveryPath, "utf8"))?.claimant === claimant) await rm(recoveryPath, { force: true }) } catch (error) { if (!expected(error)) throw error }
  }
}

async function acquirePath(lockPath: string, serverName: string, kind: string, staleMs: number, waitMs: number): Promise<{ fence: AuthLockFence; handle: FileHandle }> {
  await mkdir(join(lockPath, ".."), { recursive: true, mode: 0o700 })
  const owner = `${process.pid}:${randomUUID()}`
  const deadline = Date.now() + waitMs
  while (true) {
    const candidate = `${lockPath}.claim-${process.pid}-${randomUUID()}`
    let handle: FileHandle | undefined
    let published = false
    try {
      await mkdir(candidate, { mode: 0o700 })
      handle = await open(join(candidate, "owner"), "wx+", 0o600)
      await handle.writeFile(owner)
      await handle.sync()
      try {
        await rename(candidate, lockPath)
        const lease = await handle.stat()
        published = true
        return { fence: { lockPath, ownerPath: join(lockPath, "owner"), owner, dev: lease.dev, ino: lease.ino }, handle }
      } catch (error) { if (!expected(error, true)) throw error }
    } finally {
      if (handle && !published) await handle.close().catch(() => {})
      if (!published) await rm(candidate, { recursive: true, force: true })
    }
    await recover(lockPath, staleMs)
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for OAuth ${kind} lock for MCP server: ${serverName}`)
    await sleep(25 + Math.floor(Math.random() * 50))
  }
}

export function ownsAuthLock(fence: AuthLockFence): boolean {
  try { const s = statSync(fence.ownerPath); return readFileSync(fence.ownerPath, "utf8") === fence.owner && s.dev === fence.dev && s.ino === fence.ino } catch { return false }
}
function writeNew(path: string, value: string): void {
  const fd = openSync(path, "wx", 0o600)
  try { const b = Buffer.from(value); let p = 0; while (p < b.length) { const n = writeSync(fd, b, p, b.length - p); if (n <= 0) throw new Error("Failed to write OAuth lock marker"); p += n } fsyncSync(fd) } finally { closeSync(fd) }
}
export function withAuthPublication<T>(fence: AuthLockFence, operation: () => T): T {
  const gate = join(fence.lockPath, ".publication")
  writeNew(gate, fence.owner)
  try { if (!ownsAuthLock(fence)) throw new Error("OAuth lock ownership lost before publication"); return operation() }
  finally { try { if (readFileSync(gate, "utf8") === fence.owner) rmSync(gate, { force: true }) } catch (error) { if (!expected(error)) throw error } }
}

export async function acquireAuthLock(serverName: string): Promise<{ fence: AuthLockFence; handle: FileHandle }> {
  return acquirePath(getAuthLockPath(serverName), serverName, "refresh", timing("MCP_OAUTH_LOCK_STALE_MS", DEFAULT_STALE_MS), timing("MCP_OAUTH_LOCK_WAIT_MS", DEFAULT_WAIT_MS))
}
export async function acquireCredentialLock(serverName: string): Promise<{ fence: AuthLockFence; handle: FileHandle }> {
  return acquirePath(getCredentialLockPath(serverName), serverName, "credential storage", DEFAULT_STALE_MS, DEFAULT_WAIT_MS)
}
export function heartbeatAuthLock(handle: FileHandle, fence: AuthLockFence): () => void {
  const interval = Math.max(10, Math.floor(timing("MCP_OAUTH_LOCK_STALE_MS", DEFAULT_STALE_MS) / 3))
  const timer = setInterval(() => { const now = new Date(); void handle.utimes(now, now).then(async () => { const s = await stat(fence.ownerPath); if (s.dev !== fence.dev || s.ino !== fence.ino) clearInterval(timer) }).catch(() => clearInterval(timer)) }, interval)
  timer.unref(); return () => clearInterval(timer)
}
export async function releaseAuthLock(fence: AuthLockFence, handle: FileHandle): Promise<void> {
  let closeError: unknown
  try { await handle.close() } catch (error) { closeError = error }
  try {
    if (ownsAuthLock(fence)) {
      const recovery = join(fence.lockPath, ".recovery")
      if (await readMaybe(recovery) !== undefined) {
        try { await writeFile(join(fence.lockPath, "released"), fence.owner, { flag: "wx", mode: 0o600 }) } catch (error) { if (!expected(error, true)) throw error }
      } else withAuthPublication(fence, () => rmSync(fence.lockPath, { recursive: true, force: true }))
    }
  } catch (error) { if (!expected(error, true)) throw error }
  if (closeError) throw closeError
}
