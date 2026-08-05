import { createHash } from "node:crypto";
import path from "node:path";
import type { ApiPlan, ApiPlanCall } from "./api-plan.js";

const AUTH0_TERRAFORM_PROVIDER_VERSION = "~> 1.52.0";

const CLIENT_FIELDS = [
  "addons",
  "allowed_clients",
  "allowed_logout_urls",
  "allowed_origins",
  "app_type",
  "async_approval_notification_channels",
  "callbacks",
  "client_aliases",
  "client_metadata",
  "compliance_level",
  "cross_origin_auth",
  "cross_origin_loc",
  "custom_login_page",
  "custom_login_page_on",
  "default_organization",
  "description",
  "encryption_key",
  "express_configuration",
  "fedcm_login",
  "form_template",
  "grant_types",
  "initiate_login_uri",
  "is_first_party",
  "is_token_endpoint_ip_header_trusted",
  "jwt_configuration",
  "logo_uri",
  "mobile",
  "my_organization_configuration",
  "native_social_login",
  "oidc_backchannel_logout_urls",
  "oidc_conformant",
  "oidc_logout",
  "organization_discovery_methods",
  "organization_require_behavior",
  "organization_usage",
  "redirection_policy",
  "refresh_token",
  "require_proof_of_possession",
  "require_pushed_authorization_requests",
  "resource_server_identifier",
  "session_transfer",
  "skip_non_verifiable_callback_uri_confirmation_prompt",
  "sso",
  "sso_disabled",
  "third_party_security_mode",
  "token_exchange",
  "token_quota",
  "web_origins",
] as const;

const CONNECTION_ROOT_IGNORES = [
  "authentication",
  "connected_accounts",
  "display_name",
  "is_domain_connection",
  "metadata",
  "realms",
  "show_as_button",
] as const;

// Auth0 warns that omitted connection options can be removed on update. These
// paths are kept in imported state with lifecycle.ignore_changes unless the
// administrator explicitly selected that setting in this change package.
const CONNECTION_OPTION_FIELDS = [
  "access_token_url",
  "adfs_server",
  "allowed_audiences",
  "api_enable_groups",
  "api_enable_users",
  "app_id",
  "attribute_map",
  "attributes",
  "auth_params",
  "authentication_methods",
  "authorization_endpoint",
  "brute_force_protection",
  "client_id",
  "client_secret",
  "community_base_url",
  "configuration",
  "connection_settings",
  "consumer_key",
  "consumer_secret",
  "custom_headers",
  "custom_password_hash",
  "custom_scripts",
  "debug",
  "decryption_key",
  "destination_url",
  "digest_algorithm",
  "disable_cache",
  "disable_self_service_change_password",
  "disable_sign_out",
  "disable_signup",
  "discovery_url",
  "domain",
  "domain_aliases",
  "dpop_signing_alg",
  "email",
  "enable_script_context",
  "enabled_database_customization",
  "entity_id",
  "fed_metadata_xml",
  "federated_connections_access_tokens",
  "fields_map",
  "forward_request_info",
  "from",
  "gateway_authentication",
  "gateway_url",
  "global_token_revocation_jwt_iss",
  "global_token_revocation_jwt_sub",
  "icon_url",
  "id_token_session_expiry_supported",
  "id_token_signed_response_algs",
  "identity_api",
  "idp_initiated",
  "import_mode",
  "ips",
  "issuer",
  "jwks_uri",
  "key_id",
  "map_user_id_to_id",
  "max_groups_to_retrieve",
  "messaging_service_sid",
  "metadata_url",
  "metadata_xml",
  "mfa",
  "name",
  "non_persistent_attrs",
  "passkey_options",
  "password_complexity_options",
  "password_dictionary",
  "password_history",
  "password_no_personal_info",
  "password_options",
  "password_policy",
  "ping_federate_base_url",
  "pkce_enabled",
  "precedence",
  "protocol_binding",
  "provider",
  "realm_fallback",
  "recipient_url",
  "request_template",
  "request_token_url",
  "requires_username",
  "scopes",
  "scripts",
  "send_back_channel_nonce",
  "session_key",
  "set_user_root_attributes",
  "should_trust_email_verified_connection",
  "sign_in_endpoint",
  "sign_out_endpoint",
  "sign_saml_request",
  "signature_algorithm",
  "signature_method",
  "signing_cert",
  "signing_key",
  "strategy_version",
  "subject",
  "syntax",
  "team_id",
  "template",
  "tenant_domain",
  "token_endpoint",
  "token_endpoint_auth_method",
  "token_endpoint_auth_signing_alg",
  "token_endpoint_jwtca_aud_format",
  "totp",
  "twilio_sid",
  "twilio_token",
  "type",
  "upstream_params",
  "use_cert_auth",
  "use_kerberos",
  "use_oauth_spec_scope",
  "use_wsfed",
  "user_authorization_url",
  "user_id_attribute",
  "userinfo_endpoint",
  "validation",
  "waad_common_endpoint",
  "waad_protocol",
] as const;

const CLIENT_PATHS = new Map([
  ["callbacks", "callbacks"],
  ["cross_origin_authentication", "cross_origin_auth"],
  ["grant_types", "grant_types"],
  ["jwt_configuration.alg", "jwt_configuration"],
]);

const CONNECTION_PATHS = new Map([
  ["options.passwordPolicy", "password_policy"],
  [
    "options.password_complexity_options.min_length",
    "password_complexity_options",
  ],
  ["options.password_history.enable", "password_history"],
  ["options.password_no_personal_info.enable", "password_no_personal_info"],
  ["options.authentication_methods.passkey.enabled", "authentication_methods"],
  ["options.attributes.email.verification_method", "attributes"],
]);

const ATTACK_PATHS = new Set([
  "enabled",
  "mode",
  "shields",
  "stage.pre-change-password.shields",
  "stage.pre-user-registration.shields",
]);

export interface TerraformCoverage {
  managedCallIds: string[];
  apiOnlyCalls: Array<{
    id: string;
    resourceName: string;
    reason: string;
  }>;
}

function hclString(value: string): string {
  return JSON.stringify(value);
}

function hclValue(value: unknown): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return hclString(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => hclValue(item)).join(", ")}]`;
  }
  throw new Error("Terraform output contains an unsupported value type.");
}

function valueAt(source: unknown, dottedPath: string): unknown {
  let current = source;
  for (const segment of dottedPath.split(".")) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function target(call: ApiPlanCall, configPath: string): unknown {
  const result = valueAt(call.body, configPath);
  if (result === undefined) {
    throw new Error(`Terraform target is missing for ${configPath}.`);
  }
  return result;
}

function terraformLabel(call: ApiPlanCall): string {
  const readable = call.resourceName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 35);
  const digest = createHash("sha256")
    .update(`${call.resourceType}:${call.resourceId}`)
    .digest("hex")
    .slice(0, 8);
  return `${readable || "resource"}_${digest}`;
}

function callCoverage(call: ApiPlanCall): {
  managed: boolean;
  reason?: string;
} {
  const paths = call.preconditions.map(({ path: configPath }) => configPath);
  if (call.resourceType === "client") {
    const managed = paths.every((configPath) => CLIENT_PATHS.has(configPath));
    return managed
      ? { managed }
      : {
          managed,
          reason:
            "The Auth0 provider has no safe mapping for one or more application fields.",
        };
  }
  if (call.resourceType === "connection") {
    const managed = paths.every((configPath) =>
      CONNECTION_PATHS.has(configPath),
    );
    return managed
      ? { managed }
      : {
          managed,
          reason:
            "The Auth0 provider has no safe mapping for one or more connection fields.",
        };
  }
  const managed = paths.every((configPath) => ATTACK_PATHS.has(configPath));
  return managed
    ? { managed }
    : {
        managed,
        reason:
          "The Auth0 provider has no safe mapping for one or more attack-protection fields.",
      };
}

export function terraformCoverage(plan: ApiPlan): TerraformCoverage {
  const coverage: TerraformCoverage = { managedCallIds: [], apiOnlyCalls: [] };
  for (const call of plan.calls) {
    const result = callCoverage(call);
    if (result.managed) {
      coverage.managedCallIds.push(call.id);
    } else {
      coverage.apiOnlyCalls.push({
        id: call.id,
        resourceName: call.resourceName,
        reason:
          result.reason ?? "This change is available only in api-plan.yml.",
      });
    }
  }
  return coverage;
}

function lifecycle(ignoreChanges: readonly string[]): string {
  return `  lifecycle {
    prevent_destroy = true
    ignore_changes = [
${ignoreChanges.map((field) => `      ${field},`).join("\n")}
    ]
  }`;
}

function clientResource(call: ApiPlanCall): string {
  const label = terraformLabel(call);
  const selected = new Set(
    call.preconditions.map(({ path: configPath }) =>
      CLIENT_PATHS.get(configPath)!,
    ),
  );
  const settings: string[] = [];
  if (selected.has("callbacks")) {
    settings.push(
      `  callbacks         = ${hclValue(target(call, "callbacks"))}`,
    );
  }
  if (selected.has("cross_origin_auth")) {
    settings.push(
      `  cross_origin_auth = ${hclValue(target(call, "cross_origin_authentication"))}`,
    );
  }
  if (selected.has("grant_types")) {
    settings.push(
      `  grant_types       = ${hclValue(target(call, "grant_types"))}`,
    );
  }
  if (selected.has("jwt_configuration")) {
    settings.push(`  jwt_configuration {
    alg = ${hclValue(target(call, "jwt_configuration.alg"))}
  }`);
  }
  const ignores: string[] = CLIENT_FIELDS.filter(
    (field) => !selected.has(field),
  );
  if (selected.has("jwt_configuration")) {
    ignores.push(
      "jwt_configuration[0].lifetime_in_seconds",
      "jwt_configuration[0].scopes",
      "jwt_configuration[0].secret_encoded",
    );
  }
  return `data "auth0_client" "${label}" {
  client_id = ${hclString(call.resourceId)}
}

resource "auth0_client" "${label}" {
  name = data.auth0_client.${label}.name
${settings.join("\n")}

${lifecycle(ignores)}
}

import {
  to = auth0_client.${label}
  id = ${hclString(call.resourceId)}
}`;
}

function connectionOptions(call: ApiPlanCall): {
  content: string;
  selected: Set<string>;
  nestedIgnores: string[];
} {
  const paths = new Set(
    call.preconditions.map(({ path: configPath }) => configPath),
  );
  const selected = new Set(
    [...paths].map((configPath) => CONNECTION_PATHS.get(configPath)!),
  );
  const blocks: string[] = [];
  const nestedIgnores: string[] = [];
  if (paths.has("options.passwordPolicy")) {
    blocks.push(
      `    password_policy = ${hclValue(target(call, "options.passwordPolicy"))}`,
    );
  }
  if (paths.has("options.password_complexity_options.min_length")) {
    blocks.push(`    password_complexity_options {
      min_length = ${hclValue(target(call, "options.password_complexity_options.min_length"))}
    }`);
  }
  if (paths.has("options.password_history.enable")) {
    blocks.push(`    password_history {
      enable = ${hclValue(target(call, "options.password_history.enable"))}
    }`);
    nestedIgnores.push("options[0].password_history[0].size");
  }
  if (paths.has("options.password_no_personal_info.enable")) {
    blocks.push(`    password_no_personal_info {
      enable = ${hclValue(target(call, "options.password_no_personal_info.enable"))}
    }`);
  }
  if (paths.has("options.authentication_methods.passkey.enabled")) {
    blocks.push(`    authentication_methods {
      passkey {
        enabled = ${hclValue(target(call, "options.authentication_methods.passkey.enabled"))}
      }
    }`);
    nestedIgnores.push(
      "options[0].authentication_methods[0].email_otp",
      "options[0].authentication_methods[0].password",
      "options[0].authentication_methods[0].phone_otp",
    );
  }
  if (paths.has("options.attributes.email.verification_method")) {
    blocks.push(`    attributes {
      email {
        verification_method = ${hclValue(target(call, "options.attributes.email.verification_method"))}
      }
    }`);
    nestedIgnores.push(
      "options[0].attributes[0].phone_number",
      "options[0].attributes[0].username",
      "options[0].attributes[0].email[0].identifier",
      "options[0].attributes[0].email[0].profile_required",
      "options[0].attributes[0].email[0].signup",
      "options[0].attributes[0].email[0].unique",
    );
  }
  return { content: blocks.join("\n"), selected, nestedIgnores };
}

function connectionResource(call: ApiPlanCall): string {
  const label = terraformLabel(call);
  const options = connectionOptions(call);
  const ignoredOptions = CONNECTION_OPTION_FIELDS.filter(
    (field) => !options.selected.has(field),
  ).map((field) => `options[0].${field}`);
  return `data "auth0_connection" "${label}" {
  connection_id        = ${hclString(call.resourceId)}
  skip_enabled_clients = true
}

resource "auth0_connection" "${label}" {
  name     = data.auth0_connection.${label}.name
  strategy = data.auth0_connection.${label}.strategy

  options {
${options.content}
  }

${lifecycle([
  ...CONNECTION_ROOT_IGNORES,
  ...ignoredOptions,
  ...options.nestedIgnores,
])}
}

import {
  to = auth0_connection.${label}
  id = ${hclString(call.resourceId)}
}`;
}

function attackProtectionResource(
  calls: readonly ApiPlanCall[],
  plan: ApiPlan,
): string {
  const bruteForce = calls.find(
    (call) => call.resourceName === "Brute Force Protection",
  );
  const breachedPassword = calls.find(
    (call) => call.resourceName === "Breached Password Detection",
  );
  const blocks: string[] = [];
  const ignores = ["bot_detection", "captcha", "suspicious_ip_throttling"];
  if (bruteForce) {
    const paths = new Set(
      bruteForce.preconditions.map(({ path: value }) => value),
    );
    const settings = [
      `    enabled = ${paths.has("enabled") ? hclValue(target(bruteForce, "enabled")) : "data.auth0_attack_protection.current.brute_force_protection[0].enabled"}`,
    ];
    for (const field of ["mode", "shields"] as const) {
      if (paths.has(field))
        settings.push(`    ${field} = ${hclValue(target(bruteForce, field))}`);
      else ignores.push(`brute_force_protection[0].${field}`);
    }
    ignores.push(
      "brute_force_protection[0].allowlist",
      "brute_force_protection[0].max_attempts",
    );
    blocks.push(`  brute_force_protection {
${settings.join("\n")}
  }`);
  } else {
    ignores.push("brute_force_protection");
  }
  if (breachedPassword) {
    const paths = new Set(
      breachedPassword.preconditions.map(({ path: value }) => value),
    );
    const settings = [
      `    enabled = ${paths.has("enabled") ? hclValue(target(breachedPassword, "enabled")) : "data.auth0_attack_protection.current.breached_password_detection[0].enabled"}`,
    ];
    if (paths.has("shields")) {
      settings.push(
        `    shields = ${hclValue(target(breachedPassword, "shields"))}`,
      );
    } else {
      ignores.push("breached_password_detection[0].shields");
    }
    ignores.push(
      "breached_password_detection[0].admin_notification_frequency",
      "breached_password_detection[0].method",
    );
    if (paths.has("stage.pre-change-password.shields")) {
      settings.push(`    pre_change_password {
      shields = ${hclValue(target(breachedPassword, "stage.pre-change-password.shields"))}
    }`);
    } else {
      ignores.push("breached_password_detection[0].pre_change_password");
    }
    if (paths.has("stage.pre-user-registration.shields")) {
      settings.push(`    pre_user_registration {
      shields = ${hclValue(target(breachedPassword, "stage.pre-user-registration.shields"))}
    }`);
    } else {
      ignores.push("breached_password_detection[0].pre_user_registration");
    }
    blocks.push(`  breached_password_detection {
${settings.join("\n")}
  }`);
  } else {
    ignores.push("breached_password_detection");
  }
  const digest = createHash("sha256")
    .update(`${plan.profile}:${plan.sourceReport}:attack-protection`)
    .digest("hex");
  const importId = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
  return `data "auth0_attack_protection" "current" {}

resource "auth0_attack_protection" "checkmate" {
${blocks.join("\n\n")}

${lifecycle(ignores)}
}

import {
  to = auth0_attack_protection.checkmate
  id = ${hclString(importId)}
}`;
}

function changeObject(call: ApiPlanCall): string {
  const changes = call.preconditions.map((precondition) => {
    const proposed = target(call, precondition.path);
    return `          {
            path     = ${hclString(precondition.path)}
            current  = ${hclValue(precondition.expectedValue)}
            proposed = ${hclValue(proposed)}
          }`;
  });
  return `      {
        id            = ${hclString(call.id)}
        resource_name = ${hclString(call.resourceName)}
        changes = [
${changes.join(",\n")}
        ]
      }`;
}

export function buildTerraformDeploymentConfiguration(plan: ApiPlan): string {
  const coverage = terraformCoverage(plan);
  const managed = plan.calls.filter((call) =>
    coverage.managedCallIds.includes(call.id),
  );
  const resources = managed
    .filter((call) => call.resourceType === "client")
    .map(clientResource);
  resources.push(
    ...managed
      .filter((call) => call.resourceType === "connection")
      .map(connectionResource),
  );
  const attackCalls = managed.filter(
    (call) => call.resourceType === "attack_protection",
  );
  if (attackCalls.length > 0) {
    resources.push(attackProtectionResource(attackCalls, plan));
  }
  const calls = plan.calls.map(changeObject);
  return `# Generated by CheckMate Remediation Assistant.
# Genuine deployment configuration for existing Auth0 resources.
# Review terraform plan before apply. Import blocks adopt the existing resources into this state.
# prevent_destroy and ignore_changes protect unrelated imported settings.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = "${AUTH0_TERRAFORM_PROVIDER_VERSION}"
    }
  }
}

provider "auth0" {}

${resources.join("\n\n")}

locals {
  checkmate_deployment = {
    schema_version             = 1
    profile                    = ${hclString(plan.profile)}
    source_report              = ${hclString(path.basename(plan.sourceReport))}
    generated_at               = ${hclString(plan.generatedAt)}
    terraform_managed_call_ids = ${hclValue(coverage.managedCallIds)}
    api_only_call_ids          = ${hclValue(coverage.apiOnlyCalls.map(({ id }) => id))}
    changes = [
${calls.join(",\n")}
    ]
  }
}

output "checkmate_deployment" {
  description = "CheckMate deployment coverage and reviewed changes for ${plan.profile}."
  value       = local.checkmate_deployment
}
`;
}
