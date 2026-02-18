import { NextRequest, NextResponse } from "next/server";

import { BLOCKED_PATHNAMES } from "@/lib/constants";
import {
  PLATFORM_HEADERS,
  PLATFORM_URL,
  isAppSignupDomain,
  isInfrastructureDomain,
  isLoginPortalDomain,
} from "@/lib/constants/saas-config";

export default async function DomainMiddleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const host = req.headers.get("host");

  // -----------------------------------------------------------------------
  // Platform sub-domain routing (app.fundroom.ai, app.login.fundroom.ai)
  // These are NOT tenant custom domains — they belong to the SaaS platform.
  // -----------------------------------------------------------------------

  if (host && isAppSignupDomain(host)) {
    if (path === "/") {
      return NextResponse.redirect(new URL("/signup", req.url));
    }
    return NextResponse.next();
  }

  if (host && isLoginPortalDomain(host)) {
    if (path === "/") {
      return NextResponse.redirect(new URL("/admin/login", req.url));
    }
    return NextResponse.next();
  }

  // -----------------------------------------------------------------------
  // Safety: if fundroom.ai, www.fundroom.ai, *.vercel.app, or any other
  // infrastructure domain reaches here (shouldn't normally happen via
  // proxy.ts), pass through — never rewrite platform/infra hosts.
  // -----------------------------------------------------------------------

  if (host && isInfrastructureDomain(host)) {
    return NextResponse.next();
  }

  // -----------------------------------------------------------------------
  // Tenant custom domain handling
  // -----------------------------------------------------------------------

  // If it's the root path, redirect to the tenant's login or a default page
  if (path === "/") {
    // Legacy tenant-specific root redirects (migrating to DB-driven)
    if (host === "guide.permithealth.com") {
      return NextResponse.redirect(
        new URL("https://guide.permithealth.com/faq", req.url),
      );
    }

    if (host === "fund.tradeair.in") {
      return NextResponse.redirect(
        new URL("https://tradeair.in/sv-fm-inbound", req.url),
      );
    }

    if (host === "docs.pashupaticapital.com") {
      return NextResponse.redirect(
        new URL("https://www.pashupaticapital.com/", req.url),
      );
    }

    if (host === "partners.braxtech.net") {
      return NextResponse.redirect(
        new URL("https://partners.braxtech.net/investors", req.url),
      );
    }

    // Bermuda Franchise Group tenant custom domain → login page
    if (
      host === "dataroom.bermudafranchisegroup.com" ||
      host === "bermudafranchisegroup.com" ||
      host === "www.bermudafranchisegroup.com"
    ) {
      return NextResponse.redirect(new URL("/login", req.url));
    }

    // Default: any unknown custom domain root → redirect to platform marketing site
    // In the future this could look up the org by domain and redirect to their login
    return NextResponse.redirect(new URL(PLATFORM_URL, req.url));
  }

  const url = req.nextUrl.clone();

  // Check for blocked pathnames
  if (BLOCKED_PATHNAMES.includes(path) || path.includes(".")) {
    url.pathname = "/404";
    return NextResponse.rewrite(url, { status: 404 });
  }

  // Rewrite the URL to the correct page component for custom domains
  // Rewrite to the pages/view/domains/[domain]/[slug] route
  url.pathname = `/view/domains/${host}${path}`;

  return NextResponse.rewrite(url, {
    headers: {
      "X-Robots-Tag": "noindex",
      ...PLATFORM_HEADERS.headers,
    },
  });
}
