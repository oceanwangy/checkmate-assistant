import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { createCheckmateMcpServer } from "../packages/checkmate-mcp-server/src/server.js";

const clients: Client[] = [];
const servers: ReturnType<typeof createCheckmateMcpServer>[] = [];

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe("CheckMate MCP server", () => {
  it("advertises and executes its read-only report tools over MCP", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "checkmate-mcp-"));
    await writeFile(
      path.join(directory, "report.json"),
      JSON.stringify([
        {
          finding_name: "checkBreachedPasswordDetection",
          finding_title: "Breached Password Detection",
          severity: "High",
          name: "Tenant attack protection",
          message: "Breached password detection is disabled.",
        },
      ]),
    );

    const server = createCheckmateMcpServer({ reportsDirectory: directory });
    const client = new Client({ name: "checkmate-test", version: "0.1.0" });
    servers.push(server);
    clients.push(client);
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name)).toEqual(
      expect.arrayContaining([
        "checkmate_list_reports",
        "checkmate_get_report_summary",
        "checkmate_search_findings",
        "checkmate_get_finding",
        "checkmate_get_application_posture",
        "checkmate_get_security_topic_context",
      ]),
    );

    const result = await client.callTool({
      name: "checkmate_get_security_topic_context",
      arguments: { topic: "credential_stuffing" },
    });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      topic: "credential_stuffing",
      resultCount: 1,
      findings: [
        expect.objectContaining({
          validatorId: "checkBreachedPasswordDetection",
        }),
      ],
    });

    const resources = await client.listResources();
    expect(resources.resources).toEqual([
      expect.objectContaining({ uri: "checkmate://reports/latest/summary" }),
    ]);
    const prompts = await client.listPrompts();
    expect(prompts.prompts.map((prompt) => prompt.name)).toEqual(
      expect.arrayContaining([
        "investigate-security-question",
        "harden-application",
      ]),
    );
  });
});
