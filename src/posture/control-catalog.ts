export const POSTURE_MODEL_VERSION = "auth0-posture-v1";

export const POSTURE_CATEGORIES = [
  {
    id: "authentication",
    title: "Authentication and attack protection",
    budget: 30,
  },
  {
    id: "applications",
    title: "Application and OAuth security",
    budget: 25,
  },
  {
    id: "tokens",
    title: "Token and API security",
    budget: 20,
  },
  {
    id: "tenant",
    title: "Tenant and administration boundaries",
    budget: 15,
  },
  {
    id: "operations",
    title: "Monitoring and secure operations",
    budget: 10,
  },
] as const;

export type PostureCategoryId = (typeof POSTURE_CATEGORIES)[number]["id"];
export type PostureImportance = "foundational" | "high" | "moderate" | "low";

export const POSTURE_IMPORTANCE_WEIGHTS: Record<PostureImportance, number> = {
  foundational: 4,
  high: 3,
  moderate: 2,
  low: 1,
};

export const POSTURE_REVIEW_GUIDANCE: Readonly<Record<string, string>> = {
  checkGuardianPolicy:
    "Review the MFA policy and require MFA for the appropriate users and applications.",
  checkPasswordResetMFA:
    "Review the password reset flow and require MFA for privileged or sensitive accounts.",
  checkCrossOriginAuthentication:
    "Disable cross-origin authentication for applications that do not require a legacy cross-origin flow.",
  checkPKCEEnforcement:
    "Enforce PKCE for public applications where the application flow supports it.",
  checkRefreshToken:
    "Review refresh-token rotation and expiry settings for applications that use refresh tokens.",
  checkManagementAPIUserAccess:
    "Identify approved applications, then restrict Management API user access to that approved set.",
  checkEnabledDynamicClientRegistration:
    "Disable dynamic client registration unless the tenant has a documented requirement for it.",
  checkLogStream:
    "Configure a log stream to the organisation's monitoring or SIEM destination.",
};

export interface PostureControl {
  validatorId: string;
  title: string;
  category: PostureCategoryId;
  importance: PostureImportance;
}

const control = (
  validatorId: string,
  title: string,
  category: PostureCategoryId,
  importance: PostureImportance,
): PostureControl => ({
  validatorId,
  title,
  category,
  importance,
});

/**
 * A deliberately curated security-control catalog. CheckMate severity is useful
 * evidence, but it is not used as the posture weight: some important controls,
 * such as MFA policy, are informational findings in the source report.
 */
export const POSTURE_CONTROLS: readonly PostureControl[] = [
  control(
    "checkGuardianPolicy",
    "MFA policy",
    "authentication",
    "foundational",
  ),
  control(
    "checkBruteForce",
    "Brute-force protection",
    "authentication",
    "foundational",
  ),
  control(
    "checkBreachedPassword",
    "Breached-password protection",
    "authentication",
    "foundational",
  ),
  control(
    "checkSuspiciousIPThrottling",
    "Suspicious IP throttling",
    "authentication",
    "high",
  ),
  control(
    "checkGuardianFactors",
    "Strong MFA factors",
    "authentication",
    "high",
  ),
  control("checkPasswordPolicy", "Password policy", "authentication", "high"),
  control(
    "checkPasswordComplexity",
    "Password complexity",
    "authentication",
    "high",
  ),
  control(
    "checkPasswordNoPersonalInfo",
    "Personal information in passwords",
    "authentication",
    "moderate",
  ),
  control("checkPasswordHistory", "Password history", "authentication", "low"),
  control(
    "checkPasswordResetMFA",
    "MFA during password reset",
    "authentication",
    "high",
  ),
  control(
    "checkUserEnumeration",
    "User enumeration protection",
    "authentication",
    "moderate",
  ),
  control(
    "checkAuthenticationMethods",
    "Authentication methods",
    "authentication",
    "moderate",
  ),
  control(
    "checkEmailAttributeVerification",
    "Email verification",
    "authentication",
    "moderate",
  ),

  control(
    "checkJWTSignAlg",
    "Application JWT signing algorithm",
    "applications",
    "foundational",
  ),
  control(
    "checkAllowedCallbacks",
    "Allowed callback URLs",
    "applications",
    "high",
  ),
  control("checkGrantTypes", "OAuth grant types", "applications", "high"),
  control(
    "checkCrossOriginAuthentication",
    "Cross-origin authentication",
    "applications",
    "high",
  ),
  control("checkWebOrigins", "Allowed web origins", "applications", "high"),
  control("checkPKCEEnforcement", "PKCE enforcement", "applications", "high"),
  control(
    "checkRefreshToken",
    "Refresh-token configuration",
    "applications",
    "high",
  ),
  control(
    "checkAllowedLogoutUrl",
    "Allowed logout URLs",
    "applications",
    "low",
  ),
  control(
    "checkAPISigningAlgorithm",
    "API signing algorithm",
    "tokens",
    "foundational",
  ),
  control("checkAPITokenLifetime", "API token lifetime", "tokens", "high"),
  control(
    "checkAPIAuthorizationPolicy",
    "API authorization policy",
    "tokens",
    "high",
  ),
  control(
    "checkManagementAPIUserAccess",
    "Management API user access",
    "tenant",
    "high",
  ),
  control("checkCanonicalDomain", "Canonical domain", "tenant", "moderate"),
  control(
    "checkBlockCanonicalDomain",
    "Canonical domain blocking",
    "tenant",
    "moderate",
  ),
  control(
    "checkEnabledDynamicClientRegistration",
    "Dynamic client registration",
    "tenant",
    "high",
  ),
  control("checkDefaultAudience", "Default API audience", "tenant", "low"),
  control("checkDefaultDirectory", "Default directory", "tenant", "low"),
  control(
    "checkEnabledDatabaseCustomization",
    "Database customisation",
    "tenant",
    "moderate",
  ),
  control("checkLogStream", "Security log streaming", "operations", "high"),
  control(
    "checkActionsHardCodedValues",
    "Secrets in Actions",
    "operations",
    "high",
  ),
  control(
    "checkDASHardCodedValues",
    "Secrets in database scripts",
    "operations",
    "high",
  ),
  control(
    "checkDependencies",
    "Extension dependency versions",
    "operations",
    "high",
  ),
  control("checkActionsRuntime", "Actions runtime", "operations", "moderate"),
  control(
    "checkSessionLifetime",
    "Tenant session lifetime",
    "operations",
    "moderate",
  ),
];
