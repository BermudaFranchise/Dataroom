import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

export default async function AppMiddleware(req: NextRequest) {
  const timestamp = new Date().toISOString();
  const requestId = Math.random().toString(36).substring(7);
  const url = req.nextUrl;
  const path = url.pathname;

  // Log ALL requests through middleware for debugging
  const sessionCookie = req.cookies.get("next-auth.session-token");
  const secureCookie = req.cookies.get("__Secure-next-auth.session-token");
  const allCookies = req.cookies.getAll();
  const allCookieNames = allCookies.map(c => c.name);

  console.log(`[MIDDLEWARE][${requestId}] ========== REQUEST ==========`);
  console.log(`[MIDDLEWARE][${requestId}] Timestamp: ${timestamp}`);
  console.log(`[MIDDLEWARE][${requestId}] Path: ${path}`);
  console.log(`[MIDDLEWARE][${requestId}] Host: ${req.headers.get("host")}`);
  console.log(`[MIDDLEWARE][${requestId}] Cookies:`, {
    count: allCookies.length,
    names: allCookieNames,
    'next-auth.session-token': sessionCookie ? `present (${sessionCookie.value.length} chars)` : 'MISSING',
    '__Secure-next-auth.session-token': secureCookie ? 'present' : 'MISSING',
  });

  // Fast path for root - immediately redirect to login without token check
  if (path === "/") {
    console.log(`[MIDDLEWARE][${requestId}] Root path - redirecting to /login`);
    return NextResponse.redirect(new URL("/login", req.url));
  }

  const isInvited = url.searchParams.has("invitation");
  // CRITICAL: Must specify cookieName to match auth-options.ts which overrides
  // the default cookie name to "next-auth.session-token" (without __Secure- prefix).
  // Without this, getToken() in production looks for "__Secure-next-auth.session-token"
  // based on NEXTAUTH_URL being https, but the cookie is actually "next-auth.session-token".
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET,
    cookieName: "next-auth.session-token",
  });

  const userEmail = token?.email;
  const userRole = (token?.role as string) || "LP";
  const userCreatedAt = (token as any)?.createdAt as string | undefined;

  console.log(`[MIDDLEWARE][${requestId}] Token check:`, {
    hasToken: !!token,
    userEmail: userEmail ? userEmail.substring(0, 3) + "***" : "none",
    userRole,
    tokenKeys: token ? Object.keys(token) : [],
  });

  // Public pages accessible without auth
  if (path === "/lp/onboard" || path === "/lp/login" || path === "/signup") {
    console.log(`[MIDDLEWARE][${requestId}] Public page - allowing through`);
    return NextResponse.next();
  }

  // View pages are public - they have their own access control via visitor tokens
  if (path.startsWith("/view/")) {
    console.log(`[MIDDLEWARE][${requestId}] View page - allowing through`);
    return NextResponse.next();
  }

  // viewer-redirect has its own session handling and redirects appropriately
  // Let it through so it can check session server-side and redirect
  if (path === "/viewer-redirect") {
    console.log(`[MIDDLEWARE][${requestId}] Viewer-redirect - allowing through for server-side session check`);
    return NextResponse.next();
  }

  // LP authenticated routes (require login and LP/GP role)
  if (path.startsWith("/lp/")) {
    if (!userEmail) {
      const loginUrl = new URL("/lp/login", req.url);
      const nextPath = url.search ? `${path}${url.search}` : path;
      loginUrl.searchParams.set("next", nextPath);
      return NextResponse.redirect(loginUrl);
    }
    if (userRole !== "LP" && userRole !== "GP") {
      return NextResponse.redirect(new URL("/viewer-redirect", req.url));
    }
    return NextResponse.next();
  }
  
  // GP/Admin routes - require GP role or team membership
  const gpRoutes = ["/dashboard", "/settings", "/documents", "/datarooms", "/admin", "/hub"];
  const isAdminLoginPage = path === "/admin/login";
  if (!isAdminLoginPage && gpRoutes.some((r) => path.startsWith(r))) {
    console.log(`[MIDDLEWARE][${requestId}] GP route detected: ${path}`);
    if (!userEmail) {
      console.log(`[MIDDLEWARE][${requestId}] No user email - redirecting to admin login`);
      const loginUrl = new URL("/admin/login", req.url);
      const nextPath = url.search ? `${path}${url.search}` : path;
      loginUrl.searchParams.set("next", nextPath);
      return NextResponse.redirect(loginUrl);
    }
    // Check user role - LP users should be redirected to LP portal
    if (userRole === "LP") {
      console.log(`[MIDDLEWARE][${requestId}] LP user on GP route - redirecting to viewer-portal`);
      return NextResponse.redirect(new URL("/viewer-portal", req.url));
    }
    console.log(`[MIDDLEWARE][${requestId}] GP route authorized - allowing through`);
    return NextResponse.next();
  }

  // UNAUTHENTICATED if there's no token and the path isn't a login page
  const isLoginPage = path === "/login" || path === "/admin/login" || path === "/lp/login";
  const isAdminRoute = path.startsWith("/dashboard") || path.startsWith("/settings") || path.startsWith("/documents") || path.startsWith("/datarooms");
  
  if (!userEmail && !isLoginPage) {
    let loginPath = "/login";
    if (isAdminRoute) {
      loginPath = "/admin/login";
    }
    
    const loginUrl = new URL(loginPath, req.url);
    if (path !== "/") {
      const nextPath = url.search ? `${path}${url.search}` : path;
      loginUrl.searchParams.set("next", nextPath);
    }
    return NextResponse.redirect(loginUrl);
  }

  // AUTHENTICATED if the user was created recently, redirect to welcome
  if (
    userEmail &&
    userCreatedAt &&
    new Date(userCreatedAt).getTime() > Date.now() - 10000 &&
    path !== "/welcome" &&
    !isInvited
  ) {
    return NextResponse.redirect(new URL("/welcome", req.url));
  }

  // AUTHENTICATED if the path is a login page, redirect appropriately
  if (userEmail && isLoginPage) {
    const nextParam = url.searchParams.get("next");
    let nextPath = nextParam ? decodeURIComponent(nextParam) : null;

    // Prevent redirect loops
    if (nextPath && (nextPath.includes("/login") || nextPath.includes("/admin/login") || nextPath.includes("/lp/login"))) {
      nextPath = null;
    }

    // Admin login always goes to hub, investor login goes to viewer-redirect
    const defaultRedirect = path === "/admin/login" ? "/hub" : "/viewer-redirect";
    const finalPath = nextPath || defaultRedirect;
    console.log(`[MIDDLEWARE][${requestId}] Authenticated user on login page - redirecting to: ${finalPath}`);
    return NextResponse.redirect(
      new URL(finalPath, req.url),
    );
  }

  // Allow viewer-portal access for all authenticated users
  if (userEmail && path === "/viewer-portal") {
    return NextResponse.next();
  }
}
