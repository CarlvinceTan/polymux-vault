// Agent skill installation, the same shape as `cua-driver skills`: one pack in
// this repo, symlinked into each detected agent's skills/ dir.
//
// A symlink rather than a copy, for two reasons: the pack cannot drift from the
// source tree, and there is no build or fetch step to keep it current. Nothing
// here overwrites the user's own work, so a link pointing somewhere else, or a
// real file already in the way, is reported and left untouched.
import { existsSync, lstatSync, mkdirSync, readlinkSync, rmSync, symlinkSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..")
/** The pack this project ships. */
export const PACK = join(ROOT, "skills", "vault")
/** The link name, which OpenCode requires to match the skill's own name. */
const NAME = "vault"

/** The agents this pack can be linked into, in the order cua-driver reports them. */
const AGENTS: { agent: string; dir: string }[] = [
  { agent: "Claude Code", dir: join(homedir(), ".claude", "skills") },
  { agent: "Codex", dir: join(homedir(), ".agents", "skills") },
  { agent: "Prime Agent", dir: join(homedir(), ".prime", "agent", "skills") },
  { agent: "OpenClaw", dir: join(homedir(), ".openclaw", "skills") },
  { agent: "OpenCode", dir: join(homedir(), ".config", "opencode", "skills") },
  { agent: "Antigravity", dir: join(homedir(), ".gemini", "skills") },
  { agent: "Hermes", dir: join(homedir(), ".hermes", "skills") },
]

export type LinkState = "linked" | "absent" | "agent missing" | "foreign" | "occupied"
export type AgentLink = { agent: string; dir: string; link: string; state: LinkState; pointsTo?: string }
export type Outcome = { link: AgentLink; ok: boolean; note?: string }

/** An agent is present when the directory its skills/ would live in exists. */
const agentPresent = (dir: string) => existsSync(dirname(dir))

/** What currently sits at the link path, following nothing. */
function stateOf(link: string): { state: LinkState; pointsTo?: string } {
  let stat
  try {
    stat = lstatSync(link)
  } catch {
    return { state: "absent" }
  }
  if (!stat.isSymbolicLink()) return { state: "occupied" }
  const pointsTo = readlinkSync(link)
  return { state: resolve(dirname(link), pointsTo) === resolve(PACK) ? "linked" : "foreign", pointsTo }
}

/** Per-agent link state. Read-only. */
export function status(): AgentLink[] {
  return AGENTS.map(({ agent, dir }) => {
    const link = join(dir, NAME)
    if (!agentPresent(dir)) return { agent, dir, link, state: "agent missing" as const }
    return { agent, dir, link, ...stateOf(link) }
  })
}

/**
 * Links the pack into every detected agent. Idempotent: a link that is already
 * correct is left alone, and anything else is reported rather than replaced. An
 * agent that is not installed is skipped, not a failure.
 */
export function install(): Outcome[] {
  return AGENTS.map(({ agent, dir }) => {
    const link = join(dir, NAME)
    if (!agentPresent(dir)) return { link: { agent, dir, link, state: "agent missing" as const }, ok: true, note: "skipped" }
    const current = stateOf(link)
    if (current.state === "linked") return { link: { agent, dir, link, ...current }, ok: true, note: "already linked" }
    if (current.state !== "absent") return { link: { agent, dir, link, ...current }, ok: false, note: "left alone" }
    mkdirSync(dir, { recursive: true })
    symlinkSync(PACK, link)
    return { link: { agent, dir, link, state: "linked" }, ok: true, note: "linked" }
  })
}

/** Removes only the links this tool made. A foreign link is not ours to remove. */
export function uninstall(): Outcome[] {
  return AGENTS.map(({ agent, dir }) => {
    const link = join(dir, NAME)
    if (!agentPresent(dir)) return { link: { agent, dir, link, state: "agent missing" as const }, ok: true, note: "skipped" }
    const current = stateOf(link)
    if (current.state === "linked") {
      rmSync(link)
      return { link: { agent, dir, link, state: "absent" }, ok: true, note: "unlinked" }
    }
    if (current.state === "absent") return { link: { agent, dir, link, ...current }, ok: true, note: "nothing to remove" }
    return { link: { agent, dir, link, ...current }, ok: false, note: "left alone" }
  })
}

const LABEL: Record<LinkState, string> = {
  linked: "linked",
  absent: "not linked",
  "agent missing": "agent dir not present",
  foreign: "foreign link",
  occupied: "a real file",
}

/** One report line per agent, in the shape cua-driver uses. */
export function formatLink(link: AgentLink): string {
  const tail =
    link.state === "linked"
      ? `${link.link} → ${PACK}`
      : link.state === "agent missing"
        ? link.dir
        : link.state === "foreign"
          ? `${link.link} → ${link.pointsTo}`
          : link.link
  return `  ${link.agent} — ${LABEL[link.state]}: ${tail}`
}
