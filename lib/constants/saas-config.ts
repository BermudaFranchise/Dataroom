/**
 * FundRoom AI SaaS Platform Configuration
 *
 * Central configuration for the multi-tenant SaaS platform.
 * All domain routing, branding defaults, and platform identity live here.
 *
 * Domain Architecture:
 *   - fundroom.ai              → Marketing website (external)
 *   - app.fundroom.ai          → New org signup + setup wizard
 *   - app.login.fundroom.ai    → FundRoom AI branded admin login portal
 *   - *.custom-domain.com      → Tenant custom domains (datarooms, portals)
 *
 * Environment Variables:
 *   - NEXT_PUBLIC_PLATFORM_DOMAIN      → "fundroom.ai" (override for dev/staging)
 *   - NEXT_PUBLIC_APP_DOMAIN           → "app.fundroom.ai"
 *   - NEXT_PUBLIC_LOGIN_DOMAIN         → "app.login.fundroom.ai"
 *   - NEXT_PUBLIC_PLATFORM_NAME        → "FundRoom AI" (override)
 *   - NEXT_PUBLIC_PLATFORM_SUPPORT_EMAIL → "support@fundroom.ai"
 */

// ---------------------------------------------------------------------------
// Platform Identity
// ---------------------------------------------------------------------------

export const PLATFORM_NAME = process.env.NEXT_PUBLIC_PLATFORM_NAME || "FundRoom AI";
export const PLATFORM_SHORT_NAME = "FundRoom";
export const PLATFORM_DESCRIPTION =
  "Secure investor portals, datarooms, and fundraising infrastructure for funds and startups.";
export const PLATFORM_TAGLINE = "Raise smarter. Close faster.";

// ---------------------------------------------------------------------------
// Platform Domains
// ---------------------------------------------------------------------------

/** Root marketing domain — the company website */
export const PLATFORM_DOMAIN =
  process.env.NEXT_PUBLIC_PLATFORM_DOMAIN || "fundroom.ai";

/** App domain — new org signup + setup wizard */
export const APP_DOMAIN =
  process.env.NEXT_PUBLIC_APP_DOMAIN || "app.fundroom.ai";

/** Login domain — FundRoom AI branded admin login portal */
export const LOGIN_DOMAIN =
  process.env.NEXT_PUBLIC_LOGIN_DOMAIN || "app.login.fundroom.ai";

/** Full URLs for convenience */
export const PLATFORM_URL = `https://${PLATFORM_DOMAIN}`;
export const APP_URL = `https://${APP_DOMAIN}`;
export const LOGIN_URL = `https://${LOGIN_DOMAIN}`;

/**
 * All domains that belong to the FundRoom AI platform itself.
 * Requests from these hosts should NOT be treated as custom tenant domains.
 */
export const PLATFORM_DOMAINS = [
  PLATFORM_DOMAIN,
  APP_DOMAIN,
  LOGIN_DOMAIN,
  // Include any subdomains
  `www.${PLATFORM_DOMAIN}`,
] as const;

// ---------------------------------------------------------------------------
// Platform Contact Info
// ---------------------------------------------------------------------------

export const PLATFORM_SUPPORT_EMAIL =
  process.env.NEXT_PUBLIC_PLATFORM_SUPPORT_EMAIL || "support@fundroom.ai";
export const PLATFORM_SECURITY_EMAIL = "security@fundroom.ai";
export const PLATFORM_NOREPLY_EMAIL = "noreply@fundroom.ai";

// ---------------------------------------------------------------------------
// Branding Defaults (for new orgs / FundRoom AI default skin)
// ---------------------------------------------------------------------------

export const PLATFORM_BRANDING = {
  /** Default logo paths — served from /public/_static/ */
  logoLight: "/_static/fundroom-logo-light.svg",
  logoDark: "/_static/fundroom-logo-dark.svg",
  logoIcon: "/_static/fundroom-icon.svg",
  favicon: "/_static/favicon.png",

  /** Default brand colors */
  primaryColor: "#0F172A", // slate-900
  accentColor: "#3B82F6", // blue-500
  backgroundColor: "#FFFFFF",

  /** "Powered by" badge (shown on tenant sites unless paid to remove) */
  poweredByText: `Powered by ${PLATFORM_SHORT_NAME}`,
  poweredByUrl: `https://${PLATFORM_DOMAIN}`,
  poweredByRemovalFee: 50, // USD/month
} as const;

// ---------------------------------------------------------------------------
// Platform Headers (replaces old BFFUND_HEADERS)
// ---------------------------------------------------------------------------

export const PLATFORM_HEADERS = {
  headers: {
    "x-powered-by": `${PLATFORM_NAME} - Secure Investor Infrastructure`,
  },
} as const;

// ---------------------------------------------------------------------------
// Domain Detection Helpers
// ---------------------------------------------------------------------------

/**
 * Check if a hostname belongs to the FundRoom AI platform.
 * Used by middleware to distinguish platform domains from tenant custom domains.
 */
export function isPlatformDomain(host: string): boolean {
  const cleanHost = host.split(":")[0]; // strip port
  return (
    cleanHost === PLATFORM_DOMAIN ||
    cleanHost === APP_DOMAIN ||
    cleanHost === LOGIN_DOMAIN ||
    cleanHost === `www.${PLATFORM_DOMAIN}` ||
    cleanHost.endsWith(`.${PLATFORM_DOMAIN}`)
  );
}

/**
 * Check if the hostname is the app signup domain (app.fundroom.ai).
 */
export function isAppSignupDomain(host: string): boolean {
  const cleanHost = host.split(":")[0];
  return cleanHost === APP_DOMAIN;
}

/**
 * Check if the hostname is the branded login domain (app.login.fundroom.ai).
 */
export function isLoginPortalDomain(host: string): boolean {
  const cleanHost = host.split(":")[0];
  return cleanHost === LOGIN_DOMAIN;
}

/**
 * Determine which platform context a request is in based on host.
 * Returns null for tenant custom domains (handled by DomainMiddleware).
 */
export function getPlatformContext(
  host: string,
): "marketing" | "app" | "login" | "main" | null {
  const cleanHost = host.split(":")[0];

  if (cleanHost === PLATFORM_DOMAIN || cleanHost === `www.${PLATFORM_DOMAIN}`) {
    return "marketing";
  }
  if (cleanHost === APP_DOMAIN) {
    return "app";
  }
  if (cleanHost === LOGIN_DOMAIN) {
    return "login";
  }
  // If it's a subdomain of fundroom.ai not explicitly matched, treat as main app
  if (cleanHost.endsWith(`.${PLATFORM_DOMAIN}`)) {
    return "main";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Known Hosting Domains (not tenant custom domains)
// ---------------------------------------------------------------------------

/**
 * Domains that are known infrastructure hosts — not custom tenant domains.
 * Used by isCustomDomain() to avoid routing Vercel/Replit preview URLs
 * through DomainMiddleware.
 */
export const INFRASTRUCTURE_DOMAIN_PATTERNS = [
  "localhost",
  ".vercel.app",
  ".replit.app",
  ".replit.dev",
  ".repl.co",
  `.${PLATFORM_DOMAIN}`,
  PLATFORM_DOMAIN,
] as const;

/**
 * Check if a host is a known infrastructure/platform domain (not a tenant custom domain).
 */
export function isInfrastructureDomain(host: string): boolean {
  const cleanHost = host.split(":")[0];
  return INFRASTRUCTURE_DOMAIN_PATTERNS.some(
    (pattern) =>
      cleanHost === pattern ||
      cleanHost === pattern.replace(/^\./, "") ||
      cleanHost.endsWith(pattern),
  );
}
