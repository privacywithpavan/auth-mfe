/**
 * Local HTTPS certificates for dev servers other than `next dev`, from the mkcert CA
 * that `next dev --experimental-https` installs. Browsers then trust every local app.
 * Never use these outside local development.
 */
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"

/** Where Next.js caches the mkcert binary it downloads (same lookup as Next's getCacheDirectory). */
function mkcertDir() {
  switch (process.platform) {
    case "darwin":
      return path.join(homedir(), "Library/Caches/mkcert")
    case "win32":
      return path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), "AppData/Local"), "mkcert")
    default:
      return path.join(process.env.XDG_CACHE_HOME ?? path.join(homedir(), ".cache"), "mkcert")
  }
}

function mkcertBinary() {
  const dir = mkcertDir()
  const binary = existsSync(dir) && readdirSync(dir).find((name) => /^mkcert-v.*-(darwin|linux|windows)-/.test(name))
  if (!binary) {
    throw new Error("mkcert not found. Run the auth MFE's `pnpm dev` once first; it installs mkcert and its local CA.")
  }
  return path.join(dir, binary)
}

/** A certificate for `hostname` in `dir` (e.g. the app's ./certificates), created on first use. */
export function ensureDevCertificate({ hostname, dir }: { hostname: string; dir: string }) {
  const cert = path.join(dir, `${hostname}.pem`)
  const key = path.join(dir, `${hostname}-key.pem`)
  if (!existsSync(cert)) {
    mkdirSync(dir, { recursive: true })
    execFileSync(mkcertBinary(), ["-cert-file", cert, "-key-file", key, hostname], { stdio: "inherit" })
  }
  return { cert: readFileSync(cert), key: readFileSync(key) }
}
