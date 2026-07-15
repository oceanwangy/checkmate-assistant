import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
  type StdioServerParameters,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ChatConfig } from "./config.js";
import { AUTH0_READ_ONLY_TOOLS } from "./config.js";
import { safeError, sanitizeToolResult } from "./sanitize.js";
import type {
  McpCallResult,
  McpServerStatus,
  McpToolDefinition,
} from "./types.js";

const CHECKMATE_TOOLS = new Set([
  "checkmate_list_reports",
  "checkmate_get_report_summary",
  "checkmate_search_findings",
  "checkmate_get_finding",
  "checkmate_get_application_posture",
  "checkmate_get_security_topic_context",
]);
const AUTH0_TOOLS = new Set<string>(AUTH0_READ_ONLY_TOOLS);

type ServerName = "checkmate" | "auth0";

interface ConnectedServer {
  client: Client;
  transport: StdioClientTransport;
  tools: McpToolDefinition[];
}

function textResult(result: {
  content?: Array<{ type: string; text?: string }>;
}): unknown {
  const text = result.content
    ?.filter((item) => item.type === "text" && typeof item.text === "string")
    .map((item) => item.text)
    .join("\n");
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { text };
  }
}

function extractResult(result: unknown): unknown {
  if (!result || typeof result !== "object") return result;
  const value = result as {
    structuredContent?: unknown;
    content?: Array<{ type: string; text?: string }>;
  };
  return value.structuredContent ?? textResult(value);
}

function isErrorResult(result: unknown): boolean {
  return Boolean(
    result &&
    typeof result === "object" &&
    "isError" in result &&
    (result as { isError?: unknown }).isError,
  );
}

export interface McpHubLike {
  initialize(): Promise<void>;
  close(): Promise<void>;
  getTools(): McpToolDefinition[];
  getStatus(): {
    checkmate: McpServerStatus;
    auth0: McpServerStatus;
  };
  callTool(name: string, args: Record<string, unknown>): Promise<McpCallResult>;
}

export class McpHub implements McpHubLike {
  private readonly servers = new Map<ServerName, ConnectedServer>();
  private readonly statuses: Record<ServerName, McpServerStatus>;

  constructor(private readonly config: ChatConfig) {
    this.statuses = {
      checkmate: { enabled: true, connected: false, readOnly: true },
      auth0: {
        enabled: config.auth0Enabled,
        connected: false,
        readOnly: true,
      },
    };
  }

  async initialize(): Promise<void> {
    await this.connect(
      "checkmate",
      {
        command: process.execPath,
        args: [
          this.config.checkmateServerPath,
          "--reports-dir",
          this.config.reportsDirectory,
        ],
        cwd: this.config.projectRoot,
        env: getDefaultEnvironment(),
        stderr: "pipe",
      },
      CHECKMATE_TOOLS,
    );

    if (this.config.auth0Enabled) {
      try {
        await this.connect(
          "auth0",
          {
            command: this.config.auth0Command,
            args: this.config.auth0Arguments,
            cwd: this.config.projectRoot,
            env: {
              ...getDefaultEnvironment(),
              AUTH0_MCP_ANALYTICS: "false",
              AUTH0_MCP_READ_ONLY: "true",
              AUTH0_MCP_TOOLS: AUTH0_READ_ONLY_TOOLS.join(","),
            },
            stderr: "pipe",
          },
          AUTH0_TOOLS,
        );
      } catch (error) {
        this.statuses.auth0 = {
          enabled: true,
          connected: false,
          readOnly: true,
          error: safeError(error),
        };
      }
    }
  }

  private async connect(
    name: ServerName,
    parameters: StdioServerParameters,
    allowlist: ReadonlySet<string>,
  ): Promise<void> {
    const client = new Client({
      name: `checkmate-chat-${name}-client`,
      version: "0.1.0",
    });
    const transport = new StdioClientTransport(parameters);
    let recentStderr = "";
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      recentStderr = `${recentStderr}${String(chunk)}`.slice(-2_000);
    });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      const tools = listed.tools
        .filter((tool) => allowlist.has(tool.name))
        .map((tool): McpToolDefinition => {
          const definition: McpToolDefinition = {
            server: name,
            name: tool.name,
            inputSchema: tool.inputSchema,
          };
          if (tool.description) definition.description = tool.description;
          return definition;
        });
      if (name === "checkmate" && tools.length !== allowlist.size) {
        throw new Error(
          `CheckMate MCP advertised ${tools.length} of ${allowlist.size} expected read-only tools.`,
        );
      }
      this.servers.set(name, { client, transport, tools });
      this.statuses[name] = {
        enabled: true,
        connected: true,
        readOnly: true,
      };
      transport.onclose = () => {
        this.servers.delete(name);
        this.statuses[name] = {
          enabled: true,
          connected: false,
          readOnly: true,
          error: "The MCP server disconnected.",
        };
      };
    } catch (error) {
      await transport.close().catch(() => undefined);
      const suffix = recentStderr.trim() ? ` ${recentStderr.trim()}` : "";
      throw new Error(`${safeError(error)}${suffix}`.slice(0, 1_000));
    }
  }

  getTools(): McpToolDefinition[] {
    return [...this.servers.values()].flatMap((server) => server.tools);
  }

  getStatus(): {
    checkmate: McpServerStatus;
    auth0: McpServerStatus;
  } {
    return {
      checkmate: { ...this.statuses.checkmate },
      auth0: { ...this.statuses.auth0 },
    };
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpCallResult> {
    const serverName: ServerName | undefined = CHECKMATE_TOOLS.has(name)
      ? "checkmate"
      : AUTH0_TOOLS.has(name)
        ? "auth0"
        : undefined;
    if (!serverName) {
      throw new Error(
        `Tool ${name} is not on the chatbot read-only allowlist.`,
      );
    }
    const server = this.servers.get(serverName);
    if (!server || !server.tools.some((tool) => tool.name === name)) {
      throw new Error(`${serverName} MCP tool ${name} is unavailable.`);
    }
    const result = await server.client.callTool({ name, arguments: args });
    return {
      server: serverName,
      tool: name,
      isError: isErrorResult(result),
      value: sanitizeToolResult(extractResult(result), {
        maskPersonalData: serverName === "auth0",
      }),
    };
  }

  async close(): Promise<void> {
    const connections = [...this.servers.values()];
    this.servers.clear();
    await Promise.allSettled(
      connections.map(async ({ client }) => {
        await client.close();
      }),
    );
    for (const name of ["checkmate", "auth0"] as const) {
      this.statuses[name] = {
        enabled: name === "checkmate" || this.config.auth0Enabled,
        connected: false,
        readOnly: true,
      };
    }
  }
}
