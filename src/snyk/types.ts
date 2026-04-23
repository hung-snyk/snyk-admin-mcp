export type SnykRegion = "global" | "eu" | "us" | "au";

export const REST_API_VERSION = "2024-10-15";

/** Sanitize ID/path segment before use in API URLs to prevent SSRF. Returns validated string. */
export function sanitizePathSegment(value: string, label: string): string {
  if (!value || typeof value !== "string") throw new Error(`Invalid ${label}`);
  if (!/^[a-zA-Z0-9-]{1,128}$/.test(value) || value.includes("..")) {
    throw new Error(`Invalid ${label}: must be alphanumeric or UUID`);
  }
  return value;
}

export interface SnykApiConfig {
  token: string;
  /** Base URL without path, e.g. https://api.snyk.io or https://api.us.snyk.io */
  baseUrl?: string;
  /** If set, overrides baseUrl using known regions */
  region?: SnykRegion;
}

export function getBaseUrl(config: SnykApiConfig): { rest: string; v1: string } {
  if (config.baseUrl) {
    const base = config.baseUrl.replace(/\/$/, "");
    return { rest: `${base}/rest`, v1: `${base}/v1` };
  }
  const hosts: Record<SnykRegion, string> = {
    global: "https://api.snyk.io",
    eu: "https://api.eu.snyk.io",
    us: "https://api.us.snyk.io",
    au: "https://api.au.snyk.io",
  };
  const host = hosts[config.region ?? "global"];
  return { rest: `${host}/rest`, v1: `${host}/v1` };
}
