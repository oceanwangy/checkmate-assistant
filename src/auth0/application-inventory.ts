import { z } from "zod";
import type { CheckmateConfig } from "../config/env.js";
import { AppError } from "../utils/errors.js";

const tokenSchema = z.object({ access_token: z.string().min(1) });
const applicationSchema = z
  .object({
    client_id: z.string().min(1),
    name: z.string().min(1).optional(),
    app_type: z.string().min(1).optional(),
  })
  .passthrough();
const applicationsSchema = z.array(applicationSchema);

export interface Auth0Application {
  clientId: string;
  name: string;
  appType?: string;
}

export type Fetcher = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;

function tenantBaseUrl(domain: string): string {
  if (!/^[a-zA-Z0-9.-]+\.auth0\.com$/.test(domain)) {
    throw new AppError(
      "AUTH0_READ_FAILED",
      "The selected profile domain is not a valid Auth0 tenant domain.",
    );
  }
  return `https://${domain}`;
}

async function parseJson(response: Response): Promise<unknown> {
  if (!response.ok) {
    throw new AppError(
      "AUTH0_READ_FAILED",
      `Auth0 application inventory request failed with status ${response.status}.`,
    );
  }
  try {
    return (await response.json()) as unknown;
  } catch (error) {
    throw new AppError("AUTH0_READ_FAILED", "Auth0 returned invalid JSON.", {
      cause: error,
    });
  }
}

export async function listAuth0Applications(
  config: CheckmateConfig,
  fetcher: Fetcher = fetch,
): Promise<Auth0Application[]> {
  const baseUrl = tenantBaseUrl(config.domain);
  try {
    const tokenResponse = await fetcher(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: config.clientId,
        client_secret: config.clientSecret,
        audience: `${baseUrl}/api/v2/`,
        scope: "read:clients",
      }),
      signal: AbortSignal.timeout(30_000),
    });
    const token = tokenSchema.safeParse(await parseJson(tokenResponse));
    if (!token.success) {
      throw new AppError(
        "AUTH0_READ_FAILED",
        "Auth0 returned an invalid access token response.",
      );
    }

    const applications: Auth0Application[] = [];
    for (let page = 0; page < 50; page += 1) {
      const url = new URL(`${baseUrl}/api/v2/clients`);
      url.searchParams.set("fields", "client_id,name,app_type");
      url.searchParams.set("include_fields", "true");
      url.searchParams.set("is_global", "false");
      url.searchParams.set("per_page", "100");
      url.searchParams.set("page", String(page));
      const response = await fetcher(url, {
        headers: { authorization: `Bearer ${token.data.access_token}` },
        signal: AbortSignal.timeout(30_000),
      });
      const parsed = applicationsSchema.safeParse(await parseJson(response));
      if (!parsed.success) {
        throw new AppError(
          "AUTH0_READ_FAILED",
          "Auth0 returned an invalid application list.",
        );
      }
      applications.push(
        ...parsed.data.map((application) => ({
          clientId: application.client_id,
          name: application.name ?? "Unnamed application",
          ...(application.app_type ? { appType: application.app_type } : {}),
        })),
      );
      if (parsed.data.length < 100) break;
    }

    return applications.sort((left, right) =>
      left.name.localeCompare(right.name),
    );
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      "AUTH0_READ_FAILED",
      "Unable to load the Auth0 application inventory for this finding.",
      { cause: error },
    );
  }
}
