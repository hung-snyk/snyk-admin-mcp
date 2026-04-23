#!/usr/bin/env node
import path from "path";
import { fileURLToPath } from "url";
import { config as loadEnv } from "dotenv";

// Load .env from project root (one level up from dist/)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadEnv({ path: path.join(__dirname, "..", ".env") });

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import * as rest from "./snyk/rest.js";
import * as v1 from "./snyk/v1.js";
import { sanitizePathSegment, type SnykApiConfig } from "./snyk/types.js";
import { createApproval, consumeApproval } from "./approval.js";

const SNYK_TOKEN = process.env.SNYK_API_TOKEN ?? process.env.SNYK_TOKEN ?? "";
const SNYK_REGION = (process.env.SNYK_API_REGION ?? "global") as "global" | "eu" | "us" | "au";

function getConfig(): SnykApiConfig {
  if (!SNYK_TOKEN) throw new Error("SNYK_API_TOKEN or SNYK_TOKEN environment variable is required");
  return { token: SNYK_TOKEN, region: SNYK_REGION };
}

/** Format org_id as "name (id)" when name is available. */
async function formatOrgId(config: SnykApiConfig, orgId: string): Promise<string> {
  const name = await rest.getOrgName(config, orgId);
  return name ? `${name} (${orgId})` : orgId;
}

/** Format integration_id as "type (id)" when type is available. */
async function formatIntegrationId(config: SnykApiConfig, orgId: string, integrationId: string): Promise<string> {
  const typeName = await v1.getIntegrationTypeName(config, orgId, integrationId);
  return typeName ? `${typeName} (${integrationId})` : integrationId;
}

const server = new Server(
  {
    name: "snyk-admin-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// --- Copy org settings ---
const CopySettingsArgsSchema = z.object({
  source_org_id: z.string().describe("Source organization ID (to copy from)"),
  target_org_id: z.string().describe("Target organization ID (to copy to)"),
  dry_run: z.boolean().default(true).describe("If true, only return a plan; no changes. Set false and provide approval_token to apply."),
  approval_token: z.string().optional().describe("Required when dry_run is false; use the token returned from a prior dry run."),
});

// --- Clone integration ---
const CloneIntegrationArgsSchema = z.object({
  source_org_id: z.string().describe("Organization ID that has the integration"),
  integration_id: z.string().describe("Integration ID to clone"),
  target_org_id: z.string().describe("Organization ID to clone the integration into"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Bulk asset labels (project tags in V1) ---
const BulkLabelsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  project_ids: z.array(z.string()).describe("List of project IDs to apply labels to"),
  labels: z.array(z.object({
    key: z.string(),
    value: z.string().optional(),
  })).describe("Labels to add (key or key:value)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Bulk update inventory assets (REST Inventory Assets API) ---
const BulkUpdateInventoryAssetsArgsSchema = z.object({
  org_id: z.string().describe("Organization ID"),
  updates: z.array(z.object({
    asset_id: z.string().describe("Inventory asset ID to update"),
    class: z.string().optional().describe("Asset classification"),
    labels: z.array(z.string()).optional().describe("Free-form labels"),
    tags: z.record(z.string(), z.string()).optional().describe("Structured key:value tags"),
  })).min(1).describe("List of asset updates (each can set class, labels, and/or tags)"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

// --- Create organization (V1) ---
const CreateOrganizationArgsSchema = z.object({
  name: z.string().describe("Name of the new organization"),
  group_id: z.string().optional().describe("Group ID to create the org under (required for Enterprise/group accounts)"),
  source_org_id: z.string().optional().describe("Optional template org ID to copy settings from"),
  dry_run: z.boolean().default(true),
  approval_token: z.string().optional(),
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "snyk_copy_org_settings",
      description: "Copy organization settings from a source org to a target org. Uses Snyk V1 API (org settings). Always run with dry_run=true first to get a plan and approval_token, then run with dry_run=false and approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          source_org_id: { type: "string", description: "Source organization ID (to copy from)" },
          target_org_id: { type: "string", description: "Target organization ID (to copy to)" },
          dry_run: { type: "boolean", description: "If true, only return a plan; no changes. Set false and provide approval_token to apply.", default: true },
          approval_token: { type: "string", description: "Required when dry_run is false; use the token returned from a prior dry run." },
        },
        required: ["source_org_id", "target_org_id"],
      },
    },
    {
      name: "snyk_clone_integration",
      description: "Clone an integration (with settings and credentials) from one organization to another. Uses Snyk V1 API. CLI integrations are not supported (rejected). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: {
        type: "object",
        properties: {
          source_org_id: { type: "string", description: "Organization ID that has the integration" },
          integration_id: { type: "string", description: "Integration ID to clone" },
          target_org_id: { type: "string", description: "Organization ID to clone the integration into" },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["source_org_id", "integration_id", "target_org_id"],
      },
    },
    {
      name: "snyk_bulk_asset_labels",
      description: "Add labels (tags) to multiple projects in bulk. Uses Snyk V1 API (project tags). Use dry_run=true first to see the plan, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          project_ids: { type: "array", items: { type: "string" }, description: "List of project IDs to apply labels to" },
          labels: {
            type: "array",
            items: { type: "object", properties: { key: { type: "string" }, value: { type: "string" } }, required: ["key"] },
            description: "Labels to add (key or key:value)",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "project_ids", "labels"],
      },
    },
    {
      name: "snyk_bulk_update_inventory_assets",
      description: "Bulk update inventory assets (class, labels, tags) using the REST Inventory Assets API (PATCH /orgs/{org_id}/inventory/assets). Use dry_run=true first, then dry_run=false with approval_token to apply.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
          updates: {
            type: "array",
            items: {
              type: "object",
              properties: {
                asset_id: { type: "string", description: "Inventory asset ID to update" },
                class: { type: "string", description: "Asset classification" },
                labels: { type: "array", items: { type: "string" }, description: "Free-form labels" },
                tags: { type: "object", additionalProperties: { type: "string" }, description: "Structured key:value tags" },
              },
              required: ["asset_id"],
            },
            description: "List of asset updates",
          },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["org_id", "updates"],
      },
    },
    {
      name: "snyk_create_organization",
      description: "Create a new Snyk organization. Uses Snyk V1 API (POST /org). Optional: group_id (required for group/Enterprise), source_org_id (copy settings from template). Use dry_run=true first, then dry_run=false with approval_token to execute.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "Name of the new organization" },
          group_id: { type: "string", description: "Group ID to create the org under (required for Enterprise/group accounts)" },
          source_org_id: { type: "string", description: "Optional template org ID to copy settings from" },
          dry_run: { type: "boolean", default: true },
          approval_token: { type: "string" },
        },
        required: ["name"],
      },
    },
    {
      name: "snyk_list_orgs",
      description: "List organizations accessible to the token (REST API). Read-only, no approval needed.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
    {
      name: "snyk_list_integrations",
      description: "List integrations for an organization (V1 API). Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
        },
        required: ["org_id"],
      },
    },
    {
      name: "snyk_list_projects",
      description: "List projects for an organization (REST API). Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          org_id: { type: "string", description: "Organization ID" },
        },
        required: ["org_id"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const config = getConfig();
    if (name === "snyk_list_orgs") {
      const data = await rest.listOrgs(config);
      const lines = (data.data ?? []).map((org) => {
        const name = org.attributes?.name ?? "—";
        return `${name} (${org.id})`;
      });
      const summary = lines.length ? lines.join("\n") : "No organizations.";
      const full = { data: data.data?.map((org) => ({ id: org.id, name: org.attributes?.name ?? null, group_id: org.attributes?.group_id ?? null })) };
      return {
        content: [{ type: "text", text: `${summary}\n\nFull data:\n${JSON.stringify(full, null, 2)}` }],
        isError: false,
      };
    }
    if (name === "snyk_list_integrations") {
      const org_id = (args as { org_id?: string }).org_id;
      if (!org_id) throw new Error("org_id is required");
      const data = await v1.listIntegrations(config, sanitizePathSegment(org_id, "org_id"));
      const orgName = await rest.getOrgName(config, org_id);
      const header = orgName ? `Integrations for ${orgName} (${org_id}):` : `Integrations for org ${org_id}:`;
      const lines = Object.entries(data).map(([typeName, id]) => `${typeName} (${id})`);
      const body = lines.length ? lines.join("\n") : "No integrations.";
      return {
        content: [{ type: "text", text: `${header}\n\n${body}\n\nRaw:\n${JSON.stringify(data, null, 2)}` }],
        isError: false,
      };
    }
    if (name === "snyk_list_projects") {
      const org_id = (args as { org_id?: string }).org_id;
      if (!org_id) throw new Error("org_id is required");
      const data = await rest.listProjects(config, sanitizePathSegment(org_id, "org_id"));
      return {
        content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
        isError: false,
      };
    }

    if (name === "snyk_create_organization") {
      const parsed = CreateOrganizationArgsSchema.parse(args);
      const resolvedGroupId = parsed.group_id ?? (await rest.getDefaultGroupId(config));
      if (!resolvedGroupId) {
        return {
          content: [{
            type: "text",
            text: "No group_id provided and none could be inferred (token may have only personal orgs or no orgs). Provide group_id explicitly, or use snyk_list_orgs to get an org's group_id from attributes.",
          }],
          isError: true,
        };
      }
      if (parsed.dry_run) {
        const plan = {
          action: "create_organization",
          name: parsed.name,
          group_id: resolvedGroupId,
          source_org_id: parsed.source_org_id,
        };
        const approval_token = createApproval(plan);
        const sourceOrgLabel = parsed.source_org_id ? ` (copying settings from ${await formatOrgId(config, parsed.source_org_id)})` : "";
        return {
          content: [{
            type: "text",
            text: `Dry run – will create organization "${parsed.name}" in group ${resolvedGroupId}${sourceOrgLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_create_organization with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "create_organization") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { name: string; group_id?: string; source_org_id?: string };
      const result = await v1.createOrganization(config, {
        name: p.name,
        group_id: p.group_id ? sanitizePathSegment(p.group_id, "group_id") : undefined,
        source_org_id: p.source_org_id ? sanitizePathSegment(p.source_org_id, "source_org_id") : undefined,
      });
      const resultOrgName = (result as { name?: string }).name ?? (result as { id?: string }).id;
      return {
        content: [{ type: "text", text: `Organization created: ${resultOrgName}. Result: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_copy_org_settings") {
      const parsed = CopySettingsArgsSchema.parse(args);
      const sourceLabel = await formatOrgId(config, parsed.source_org_id);
      const targetLabel = await formatOrgId(config, parsed.target_org_id);
      if (parsed.dry_run) {
        const settings = await v1.getOrgSettings(config, sanitizePathSegment(parsed.source_org_id, "source_org_id"));
        const plan = {
          action: "copy_org_settings",
          source_org_id: parsed.source_org_id,
          target_org_id: parsed.target_org_id,
          settings_to_apply: settings,
          note: "Only requestAccess and similar editable fields will be applied (V1 org settings).",
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – copy settings from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_copy_org_settings again with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "copy_org_settings") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { settings_to_apply?: Record<string, unknown>; target_org_id?: string };
      await v1.updateOrgSettings(config, sanitizePathSegment(p.target_org_id!, "target_org_id"), p.settings_to_apply ?? {});
      return {
        content: [{ type: "text", text: `Org settings copied to ${targetLabel}.` }],
        isError: false,
      };
    }

    if (name === "snyk_clone_integration") {
      const parsed = CloneIntegrationArgsSchema.parse(args);
      const safeSourceOrg = sanitizePathSegment(parsed.source_org_id, "source_org_id");
      const safeIntegrationId = sanitizePathSegment(parsed.integration_id, "integration_id");
      const integrationType = await v1.getIntegrationTypeName(config, safeSourceOrg, safeIntegrationId);
      if (v1.isCliIntegrationType(integrationType)) {
        return {
          content: [{
            type: "text",
            text: "CLI integration cannot be cloned via the API; skip it when copying integrations between organizations.",
          }],
          isError: true,
        };
      }
      const sourceLabel = await formatOrgId(config, parsed.source_org_id);
      const targetLabel = await formatOrgId(config, parsed.target_org_id);
      const integrationLabel = await formatIntegrationId(config, parsed.source_org_id, parsed.integration_id);
      if (parsed.dry_run) {
        const plan = {
          action: "clone_integration",
          source_org_id: parsed.source_org_id,
          integration_id: parsed.integration_id,
          target_org_id: parsed.target_org_id,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – clone integration ${integrationLabel} from ${sourceLabel} to ${targetLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_clone_integration with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "clone_integration") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { source_org_id: string; integration_id: string; target_org_id: string };
      const result = await v1.cloneIntegration(
        config,
        sanitizePathSegment(p.source_org_id, "source_org_id"),
        sanitizePathSegment(p.integration_id, "integration_id"),
        sanitizePathSegment(p.target_org_id, "target_org_id")
      );
      const doneTargetLabel = await formatOrgId(config, p.target_org_id);
      const doneIntegrationLabel = await formatIntegrationId(config, p.source_org_id, p.integration_id);
      return {
        content: [{ type: "text", text: `Integration ${doneIntegrationLabel} cloned to ${doneTargetLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_bulk_asset_labels") {
      const parsed = BulkLabelsArgsSchema.parse(args);
      if (parsed.dry_run) {
        const plan = {
          action: "bulk_asset_labels",
          org_id: parsed.org_id,
          project_ids: parsed.project_ids,
          labels: parsed.labels,
          total_operations: parsed.project_ids.length * parsed.labels.length,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will add ${parsed.labels.length} label(s) to ${parsed.project_ids.length} project(s) (${plan.total_operations} operations).\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_bulk_asset_labels with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "bulk_asset_labels") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { org_id: string; project_ids: string[]; labels: { key: string; value?: string }[] };
      const safeOrgId = sanitizePathSegment(p.org_id, "org_id");
      const results: { projectId: string; label: { key: string; value?: string }; ok: boolean; error?: string }[] = [];
      for (const projectId of p.project_ids) {
        const safeProjectId = sanitizePathSegment(projectId, "project_id");
        for (const label of p.labels) {
          try {
            await v1.addProjectTag(config, safeOrgId, safeProjectId, label.key, label.value);
            results.push({ projectId, label, ok: true });
          } catch (err) {
            results.push({ projectId, label, ok: false, error: String(err) });
          }
        }
      }
      return {
        content: [{ type: "text", text: `Bulk labels applied. Results:\n${JSON.stringify(results, null, 2)}` }],
        isError: false,
      };
    }

    if (name === "snyk_bulk_update_inventory_assets") {
      const parsed = BulkUpdateInventoryAssetsArgsSchema.parse(args);
      const orgLabel = await formatOrgId(config, parsed.org_id);
      const data = parsed.updates.map((u) => {
        const attributes: { class?: string; labels?: string[]; tags?: Record<string, string> } = {};
        if (u.class !== undefined) attributes.class = u.class;
        if (u.labels !== undefined) attributes.labels = u.labels;
        if (u.tags !== undefined) attributes.tags = u.tags;
        return {
          type: "asset" as const,
          id: sanitizePathSegment(u.asset_id, "asset_id"),
          attributes,
        };
      });
      const withAttributes = data.filter((d) => Object.keys(d.attributes).length > 0);
      if (withAttributes.length === 0 && data.length > 0) {
        return {
          content: [{ type: "text", text: "Each update must specify at least one of: class, labels, or tags." }],
          isError: true,
        };
      }
      const body = { data: withAttributes.length > 0 ? withAttributes : data };
      if (parsed.dry_run) {
        const plan = {
          action: "bulk_update_inventory_assets",
          org_id: parsed.org_id,
          update_count: body.data.length,
          updates: parsed.updates,
          request_body: body,
        };
        const approval_token = createApproval(plan);
        return {
          content: [{
            type: "text",
            text: `Dry run – will bulk update ${parsed.updates.length} inventory asset(s) in ${orgLabel}.\n\nPlan:\n${JSON.stringify(plan, null, 2)}\n\nTo apply, call snyk_bulk_update_inventory_assets with dry_run=false and approval_token="${approval_token}"`,
          }],
          isError: false,
        };
      }
      const plan = consumeApproval(parsed.approval_token ?? "");
      if (!plan || (plan as { action?: string }).action !== "bulk_update_inventory_assets") {
        return { content: [{ type: "text", text: "Invalid or expired approval_token. Run with dry_run=true first." }], isError: true };
      }
      const p = plan as { org_id: string; request_body: typeof body };
      const result = await rest.bulkUpdateInventoryAssets(
        config,
        sanitizePathSegment(p.org_id, "org_id"),
        p.request_body
      );
      const doneLabel = await formatOrgId(config, p.org_id);
      return {
        content: [{ type: "text", text: `Bulk inventory assets updated in ${doneLabel}.\n\nResult: ${JSON.stringify(result, null, 2)}` }],
        isError: false,
      };
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Snyk Admin MCP server running on stdio.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
