// Minimal MCP server over the stdio transport: newline-delimited JSON-RPC 2.0
// on stdin and stdout. Only the surface a tool-only server needs: initialize,
// ping, tools/list, tools/call, plus empty answers for prompts and resources so
// a client that asks anyway is never left hanging.
//
// stdout carries protocol frames and nothing else. Diagnostics go to stderr,
// because a stray write to stdout desynchronises the client.
//
// No dependency on any agent runtime: this is the whole protocol layer.

export interface ToolContext {
  /** The calling OpenCode session, from CallToolRequest._meta.sessionID. */
  sessionID?: string | undefined;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  run: (input: any, context: ToolContext) => Promise<string>;
}

export interface ServerDefinition {
  name: string;
  version: string;
  /** Shown to the client during initialize. Keep it short. */
  instructions?: string;
  tools: ToolDefinition[];
}

// Revisions this server is willing to speak. It only uses initialize, ping and
// tools, which all of them share.
const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL = "2025-06-18";

export function serve(server: ServerDefinition): void {
  const log = (message: string) => process.stderr.write(`[${server.name}] ${message}\n`);
  const out = (message: unknown) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const result = (id: unknown, value: unknown) => out({ jsonrpc: "2.0", id, result: value });
  const failure = (id: unknown, code: number, message: string) =>
    out({ jsonrpc: "2.0", id, error: { code, message } });

  // Calls run one at a time. A whole-file rewrite per mutation is the normal
  // shape here, so overlapping calls would race on the same database.
  let queue: Promise<void> = Promise.resolve();
  const serialize = (work: () => Promise<void>): void => {
    queue = queue.then(work, work);
  };

  async function dispatch(id: unknown, method: string, params: any): Promise<void> {
    switch (method) {
      case "initialize":
        return result(id, {
          protocolVersion: SUPPORTED_PROTOCOLS.includes(params?.protocolVersion)
            ? params.protocolVersion
            : DEFAULT_PROTOCOL,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: server.name, version: server.version },
          ...(server.instructions ? { instructions: server.instructions } : {}),
        });

      case "ping":
        return result(id, {});

      case "tools/list":
        return result(id, {
          tools: server.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema,
          })),
        });

      case "prompts/list":
        return result(id, { prompts: [] });
      case "resources/list":
        return result(id, { resources: [] });
      case "resources/templates/list":
        return result(id, { resourceTemplates: [] });

      case "tools/call": {
        const name = String(params?.name ?? "");
        const tool = server.tools.find((candidate) => candidate.name === name);
        if (!tool) return failure(id, -32602, `unknown tool "${name}"`);
        const context: ToolContext = { sessionID: params?._meta?.sessionID };
        try {
          const text = await tool.run(params?.arguments ?? {}, context);
          return result(id, { content: [{ type: "text", text }] });
        } catch (problem) {
          const message = problem instanceof Error ? problem.message : String(problem);
          log(`${name}: ${message}`);
          return result(id, { content: [{ type: "text", text: message }], isError: true });
        }
      }

      default:
        return failure(id, -32601, `method not found: ${method}`);
    }
  }

  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (line) {
        let message: any;
        try {
          message = JSON.parse(line);
        } catch {
          log("dropped a line that was not JSON");
          message = undefined;
        }
        // A request without an id is a notification and is never answered.
        if (message && message.id !== undefined && message.id !== null) {
          const id = message.id;
          serialize(async () => {
            try {
              await dispatch(id, String(message.method ?? ""), message.params);
            } catch (problem) {
              const text = problem instanceof Error ? problem.message : String(problem);
              failure(id, -32603, text);
            }
          });
        }
      }
      index = buffer.indexOf("\n");
    }
  });
  // A client that closes stdin gets the answers it already asked for, then the
  // process leaves. Writing through the callback keeps the last frame from being
  // truncated by an immediate exit.
  process.stdin.on("end", () => {
    void queue.then(() => process.stdout.write("", () => process.exit(0)));
  });
}
