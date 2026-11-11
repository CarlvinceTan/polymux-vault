// Entry point: `vault-mcp` on the stdio transport.
import { serve } from "./mcp.ts";
import { INSTRUCTIONS, tools } from "./tools.ts";

serve({
  name: "vault",
  version: "0.1.0",
  instructions: INSTRUCTIONS,
  tools,
});
