// Maintenance CLI for the parts that are not agent-facing, which today is the
// skill install. The MCP server is what agents talk to, over stdio.
import { formatLink, install, PACK, status, uninstall } from "./skills.ts"

const args = process.argv.slice(2)
const command = args[0]

function usage(): void {
  console.log(
    [
      "usage: vault skills <status|install|uninstall>",
      "",
      "  skills status     where the agent skill pack is linked (read-only)",
      "  skills install    symlink the pack into each detected agent",
      "  skills uninstall  remove the links this tool made",
      "",
      "`skills update` is a synonym for install: the pack is this repo, so there is",
      "nothing to fetch or refresh.",
    ].join("\n"),
  )
}

if (command !== "skills") {
  usage()
  process.exit(1)
}

const sub = args[1] ?? "status"
if (!["status", "install", "update", "uninstall"].includes(sub)) {
  usage()
  process.exit(1)
}

console.log(`Local skill pack: ${PACK}`)
if (sub === "status") {
  for (const link of status()) console.log(formatLink(link))
} else {
  const outcomes = sub === "uninstall" ? uninstall() : install()
  for (const outcome of outcomes) {
    console.log(`${formatLink(outcome.link)}${outcome.note ? ` (${outcome.note})` : ""}`)
  }
  if (outcomes.some((outcome) => !outcome.ok)) process.exit(1)
}
