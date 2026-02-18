import prisma from "@/lib/prisma";
import { isAdminEmail } from "@/lib/constants/admins";

export interface AuthorizationResult {
  allowed: boolean;
  reason?: string;
  redirectUrl?: string;
  accessMethod?: string;
}

export async function checkIsAdmin(email: string): Promise<boolean> {
  const emailLower = email.toLowerCase();
  
  if (isAdminEmail(emailLower)) {
    return true;
  }
  
  const adminTeam = await prisma.userTeam.findFirst({
    where: {
      user: { email: { equals: emailLower, mode: "insensitive" } },
      role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
      status: "ACTIVE",
    },
  });
  
  return !!adminTeam;
}

export async function checkViewerAccess(email: string): Promise<{ hasAccess: boolean; accessMethod: string | null }> {
  const emailLower = email.toLowerCase();
  
  const [existingViewer, viewerWithGroups, linkWithEmail] = await prisma.$transaction([
    prisma.viewer.findFirst({
      where: {
        email: { equals: emailLower, mode: "insensitive" },
        accessRevokedAt: null,
      },
      select: { id: true },
    }),
    prisma.viewer.findFirst({
      where: {
        email: { equals: emailLower, mode: "insensitive" },
        groups: { some: {} },
      },
      select: { id: true },
    }),
    prisma.link.findFirst({
      where: {
        allowList: { has: emailLower },
        deletedAt: null,
        isArchived: false,
      },
      select: { id: true },
    }),
  ]);
  
  if (existingViewer) {
    return { hasAccess: true, accessMethod: "viewer record" };
  }
  if (viewerWithGroups) {
    return { hasAccess: true, accessMethod: "group membership" };
  }
  if (linkWithEmail) {
    return { hasAccess: true, accessMethod: "link allowList" };
  }
  
  return { hasAccess: false, accessMethod: null };
}

export async function authorizeAdminPortal(email: string): Promise<AuthorizationResult> {
  const isAdmin = await checkIsAdmin(email);
  
  if (!isAdmin) {
    return {
      allowed: false,
      reason: "Non-admin attempting admin portal access",
      redirectUrl: "/admin/login?error=AccessDenied&message=You+do+not+have+admin+access.+Please+use+the+investor+portal.",
    };
  }
  
  return { allowed: true, accessMethod: "admin role" };
}

export async function authorizeVisitorPortal(email: string): Promise<AuthorizationResult> {
  const [isAdmin, viewerResult] = await Promise.all([
    checkIsAdmin(email),
    checkViewerAccess(email),
  ]);
  
  if (!viewerResult.hasAccess && !isAdmin) {
    return {
      allowed: false,
      reason: "No viewer access or admin role",
      redirectUrl: "/login?error=AccessDenied&message=You+do+not+have+access+to+this+portal.+Please+contact+an+administrator.",
    };
  }
  
  return {
    allowed: true,
    accessMethod: viewerResult.hasAccess ? viewerResult.accessMethod! : "admin role",
  };
}
