import { getBaseUrl, REST_API_VERSION, sanitizePathSegment, type SnykApiConfig } from "./types.js";
import { fetchWithRetry, restRateLimiter } from "./rateLimit.js";

/**
 * Snyk REST API (JSON:API). Use for: orgs, groups, projects, issues, etc.
 * Rate-limited to stay under 1620/min; retries on 429.
 * Docs: https://docs.snyk.io/snyk-api/rest-api/about-the-rest-api
 */
export async function restFetch(
  config: SnykApiConfig,
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const { rest } = getBaseUrl(config);
  const url = path.startsWith("http") ? path : `${rest}${path.startsWith("/") ? path : `/${path}`}`;
  const versionParam = url.includes("?") ? `&version=${REST_API_VERSION}` : `?version=${REST_API_VERSION}`;
  const finalUrl = url + versionParam;
  return fetchWithRetry(restRateLimiter, () =>
    fetch(finalUrl, {
      ...options,
      headers: {
        "Content-Type": "application/vnd.api+json",
        Authorization: `token ${config.token}`,
        ...options.headers,
      },
    })
  );
}

export async function listOrgs(config: SnykApiConfig): Promise<{ data: { id: string; attributes?: { name?: string; group_id?: string } }[] }> {
  const res = await restFetch(config, "/orgs");
  if (!res.ok) throw new Error(`REST listOrgs failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<{ data: { id: string; attributes?: { name?: string; group_id?: string } }[] }>;
}

/** Get the group_id from the first org the token can access (for accounts that require group_id to create orgs). */
export async function getDefaultGroupId(config: SnykApiConfig): Promise<string | null> {
  const { data } = await listOrgs(config);
  const firstWithGroup = data?.find((org) => org.attributes?.group_id);
  return firstWithGroup?.attributes?.group_id ?? null;
}

/** Get org display name by org ID (from listOrgs). Returns null if not found. */
export async function getOrgName(config: SnykApiConfig, orgId: string): Promise<string | null> {
  const { data } = await listOrgs(config);
  const org = data?.find((o) => o.id === orgId);
  return org?.attributes?.name ?? null;
}

export async function listProjects(
  config: SnykApiConfig,
  orgId: string
): Promise<{ data: { id: string; attributes?: { name?: string } }[] }> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/projects`);
  if (!res.ok) throw new Error(`REST listProjects failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<{ data: { id: string; attributes?: { name?: string } }[] }>;
}

/** Bulk update inventory assets (REST API). PATCH /orgs/{org_id}/inventory/assets. Body: JSON:API data array with type "asset", id, and attributes (class, labels, tags). */
export async function bulkUpdateInventoryAssets(
  config: SnykApiConfig,
  orgId: string,
  body: { data: Array<{ type: string; id: string; attributes: { class?: string; labels?: string[]; tags?: Record<string, string> } }> }
): Promise<Record<string, unknown>> {
  const safeOrgId = sanitizePathSegment(orgId, "org_id");
  const res = await restFetch(config, `/orgs/${safeOrgId}/inventory/assets`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`REST bulkUpdateInventoryAssets failed: ${res.status} ${await res.text()}`);
  return res.json() as Promise<Record<string, unknown>>;
}
