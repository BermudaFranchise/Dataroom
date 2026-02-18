import { NextFetchEvent, NextRequest, NextResponse } from "next/server";

import AppMiddleware from "@/lib/middleware/app";
import { createCSPResponse, wrapResponseWithCSP } from "@/lib/middleware/csp";
import DomainMiddleware from "@/lib/middleware/domain";

import { BLOCKED_PATHNAMES } from "./lib/constants";
import IncomingWebhookMiddleware, {
  isWebhookPath,
} from "./lib/middleware/incoming-webhooks";
import PostHogMiddleware from "./lib/middleware/posthog";
import { serverInstance } from "./lib/rollbar";

function isAnalyticsPath(path: string): boolean {
  const pattern = /^\/ingest\/.*/;
  return pattern.test(path);
}

function validateHost(host: string | null): boolean {
  if (!host) return false;
  
  const hostPattern = /^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$/;
  const cleanHost = host.split(':')[0];
  
  if (cleanHost.length > 253) return false;
  if (!hostPattern.test(cleanHost)) return false;
  
  return true;
}

function validateClientIP(req: NextRequest): string | null {
  const forwardedFor = req.headers.get("x-forwarded-for");
  const realIP = req.headers.get("x-real-ip");
  
  const ip = forwardedFor?.split(',')[0]?.trim() || realIP || null;
  
  if (ip) {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Pattern = /^([a-fA-F0-9:]+)$/;
    
    if (!ipv4Pattern.test(ip) && !ipv6Pattern.test(ip)) {
      return null;
    }
  }
  
  return ip;
}

function escapePath(path: string): string {
  return path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sanitizePath(path: string): string {
  let sanitized = path.replace(/\.{2,}/g, '');
  sanitized = sanitized.replace(/\/+/g, '/');
  sanitized = decodeURIComponent(sanitized).replace(/[<>'"]/g, '');
  return sanitized;
}

function isCustomDomain(host: string): boolean {
  // In development, only .local domains are custom
  if (process.env.NODE_ENV === "development") {
    return host?.includes(".local") || false;
  }

  // Known infrastructure/platform domains are NOT custom domains.
  // Custom domains are tenant-owned (e.g., dataroom.acme.com).
  // Platform subdomains (app.fundroom.ai, app.login.fundroom.ai) ARE treated
  // as custom domains here so DomainMiddleware can handle their routing.
  const platformDomain = process.env.NEXT_PUBLIC_PLATFORM_DOMAIN || "fundroom.ai";
  const knownNonCustomPatterns = [
    "localhost",
    ".vercel.app",
    ".replit.app",
    ".replit.dev",
    ".repl.co",
  ];

  const cleanHost = host?.split(":")[0] || "";

  // If it's a known infra host (Vercel, Replit, localhost), not custom
  if (knownNonCustomPatterns.some((p) => cleanHost === p || cleanHost.endsWith(p))) {
    return false;
  }

  // The root platform domain itself (fundroom.ai, www.fundroom.ai) is not custom
  if (cleanHost === platformDomain || cleanHost === `www.${platformDomain}`) {
    return false;
  }

  // Platform subdomains (app.fundroom.ai, app.login.fundroom.ai) are routed
  // through DomainMiddleware for SaaS-specific handling, so treat as "custom"
  // to let DomainMiddleware intercept them.
  if (cleanHost.endsWith(`.${platformDomain}`)) {
    return true;
  }

  // Legacy tenant domains — keep until fully migrated to SaaS model
  // bermudafranchisegroup.com subdomains ARE custom tenant domains
  // The NEXTAUTH_URL host (current main app host) is NOT a custom domain
  const nextauthHost = process.env.NEXTAUTH_URL
    ? new URL(process.env.NEXTAUTH_URL).hostname
    : "";
  if (nextauthHost && cleanHost === nextauthHost) {
    return false;
  }

  // Everything else is a tenant custom domain
  return true;
}

function createErrorResponse(message: string, status: number): NextResponse {
  return new NextResponse(
    JSON.stringify({ error: message }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

export const config = {
  matcher: [
    "/((?!api/|_next/|_static|vendor|_icons|_vercel|favicon.ico|favicon.png|sitemap.xml|sw.js|sw-version.json|manifest.json|offline).*)",
  ],
};

export default async function proxy(req: NextRequest, ev: NextFetchEvent) {
  try {
    const path = sanitizePath(req.nextUrl.pathname);
    const host = req.headers.get("host");

    if (!validateHost(host)) {
      return createErrorResponse("Invalid host header", 400);
    }

    const clientIP = validateClientIP(req);
    if (clientIP) {
      req.headers.set("x-client-ip", clientIP);
    }

    if (isAnalyticsPath(path)) {
      const response = await PostHogMiddleware(req);
      return wrapResponseWithCSP(req, response);
    }

    if (isWebhookPath(host)) {
      const response = await IncomingWebhookMiddleware(req);
      return wrapResponseWithCSP(req, response);
    }

    if (isCustomDomain(host || "")) {
      const response = await DomainMiddleware(req);
      return wrapResponseWithCSP(req, response);
    }

    if (
      !path.startsWith("/view/") &&
      !path.startsWith("/verify") &&
      !path.startsWith("/unsubscribe")
    ) {
      const response = await AppMiddleware(req);
      if (response) {
        return wrapResponseWithCSP(req, response);
      }
      return createCSPResponse(req);
    }

    if (path.startsWith("/view/")) {
      const isBlocked = BLOCKED_PATHNAMES.some((blockedPath) => {
        const escapedBlockedPath = escapePath(blockedPath);
        const blockPattern = new RegExp(escapedBlockedPath);
        return blockPattern.test(path);
      });

      if (isBlocked || path.includes(".")) {
        const url = req.nextUrl.clone();
        const rewriteResponse = NextResponse.rewrite(url, { status: 404 });
        return wrapResponseWithCSP(req, rewriteResponse);
      }
    }

    return createCSPResponse(req);
  } catch (error) {
    serverInstance.error(error as Error, {
      path: req.nextUrl.pathname,
      method: req.method,
      host: req.headers.get("host"),
    });
    console.error("[Proxy Error]", error instanceof Error ? error.message : "Unknown error");
    
    return createErrorResponse("Internal server error", 500);
  }
}
