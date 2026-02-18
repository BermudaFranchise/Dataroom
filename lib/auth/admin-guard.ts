import { GetServerSidePropsContext, GetServerSidePropsResult } from "next";
import { getServerSession } from "next-auth/next";
import { getToken } from "next-auth/jwt";
import { redirect } from "next/navigation";
import { cookies, headers } from "next/headers";

import prisma from "@/lib/prisma";
import { CustomUser } from "@/lib/types";

import { authOptions } from "@/lib/auth/auth-options";

export interface AdminPortalGuardResult {
  session: any;
  user: CustomUser;
  userTeam: any;
  loginPortal: "ADMIN" | "VISITOR";
}

export async function requireAdminPortalAccess(): Promise<AdminPortalGuardResult> {
  const session = await getServerSession(authOptions);

  if (!session) {
    redirect("/admin/login");
  }

  const user = session.user as CustomUser;

  // Check admin team membership first - this is the primary access check
  const userTeam = await prisma.userTeam.findFirst({
    where: {
      userId: user.id,
      role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
      status: "ACTIVE",
    },
  });

  if (!userTeam) {
    redirect("/viewer-portal");
  }

  // For JWT strategy, loginPortal is stored in the JWT token
  // We decode the JWT to check if user explicitly came through visitor portal
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("next-auth.session-token")?.value;

  let loginPortal: "ADMIN" | "VISITOR" = "ADMIN";

  if (sessionToken) {
    try {
      const { decode } = await import("next-auth/jwt");
      const token = await decode({
        token: sessionToken,
        secret: process.env.NEXTAUTH_SECRET!,
      });
      // Only block if loginPortal is explicitly "VISITOR" (came through visitor portal).
      // If undefined/null (standard NextAuth flow) or "ADMIN", allow access since
      // the user has already passed the admin team membership check above.
      const portalClaim = token?.loginPortal as string | undefined;
      if (portalClaim === "VISITOR") {
        loginPortal = "VISITOR";
      } else {
        loginPortal = "ADMIN";
      }
    } catch (e) {
      console.error("[ADMIN-GUARD] Failed to decode JWT:", e);
      // On decode failure, allow access since user has valid session + admin team role
    }
  }

  if (loginPortal === "VISITOR") {
    redirect("/viewer-portal?error=wrong_portal");
  }

  return { session, user, userTeam, loginPortal };
}

export type AdminGuardResult =
  | { redirect: { destination: string; permanent: boolean } }
  | { props: Record<string, unknown> };

export async function requireAdminAccess(
  context: GetServerSidePropsContext
): Promise<AdminGuardResult> {
  const session = await getServerSession(context.req, context.res, authOptions);

  if (!session) {
    return {
      redirect: {
        destination: "/admin/login",
        permanent: false,
      },
    };
  }

  const user = session.user as CustomUser;

  const userTeam = await prisma.userTeam.findFirst({
    where: {
      userId: user.id,
    },
  });

  if (!userTeam) {
    return {
      redirect: {
        destination: "/viewer-portal",
        permanent: false,
      },
    };
  }

  return {
    props: {},
  };
}

export function withAdminGuard<P extends { [key: string]: unknown } = {}>(
  getServerSidePropsFunc?: (
    context: GetServerSidePropsContext
  ) => Promise<GetServerSidePropsResult<P>>
) {
  return async function getServerSideProps(
    context: GetServerSidePropsContext
  ): Promise<GetServerSidePropsResult<P>> {
    const guardResult = await requireAdminAccess(context);

    if ("redirect" in guardResult) {
      return guardResult;
    }

    if (getServerSidePropsFunc) {
      return getServerSidePropsFunc(context);
    }

    return { props: {} as P };
  };
}
