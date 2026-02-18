import { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth/auth-options";
import prisma from "@/lib/prisma";
import { CustomUser } from "@/lib/types";

export type LPDocumentPermission =
  | "documents:upload_own"
  | "documents:view_own"
  | "documents:review"
  | "documents:approve"
  | "documents:reject"
  | "documents:view_pending";

export interface LPDocumentAuthContext {
  user: CustomUser;
  investorId: string | null;
  fundIds: string[];
  teamIds: string[];
  permissions: LPDocumentPermission[];
  isGP: boolean;
  isLP: boolean;
}

export async function getLPDocumentAuthContext(
  req: NextApiRequest,
  res: NextApiResponse
): Promise<LPDocumentAuthContext | null> {
  const session = await getServerSession(req, res, authOptions);

  if (!session?.user?.email) {
    return null;
  }

  const user = session.user as CustomUser;

  const dbUser = await prisma.user.findUnique({
    where: { id: user.id },
    select: {
      id: true,
      email: true,
      role: true,
      investorProfile: {
        select: { 
          id: true,
          fundId: true,
        },
      },
      teams: {
        where: { status: "ACTIVE" },
        select: { 
          teamId: true,
          role: true,
          team: {
            select: {
              funds: {
                select: { id: true },
              },
            },
          },
        },
      },
    },
  });

  if (!dbUser) {
    return null;
  }

  const isGP = dbUser.teams.some((t) =>
    ["OWNER", "ADMIN", "SUPER_ADMIN", "MEMBER"].includes(t.role)
  );
  const isAdmin = dbUser.teams.some((t) =>
    ["OWNER", "ADMIN", "SUPER_ADMIN"].includes(t.role)
  );
  const isLP = !!dbUser.investorProfile;

  const teamIds = dbUser.teams.map((t) => t.teamId);
  const fundIds = dbUser.teams.flatMap((t) => t.team.funds.map((f) => f.id));
  
  if (dbUser.investorProfile?.fundId) {
    fundIds.push(dbUser.investorProfile.fundId);
  }

  const permissions: LPDocumentPermission[] = [];

  if (isLP) {
    permissions.push("documents:upload_own", "documents:view_own");
  }

  if (isAdmin) {
    permissions.push(
      "documents:review",
      "documents:approve",
      "documents:reject",
      "documents:view_pending"
    );
  }

  return {
    user,
    investorId: dbUser.investorProfile?.id || null,
    fundIds: [...new Set(fundIds)],
    teamIds,
    permissions,
    isGP,
    isLP,
  };
}

export function hasPermission(
  context: LPDocumentAuthContext,
  permission: LPDocumentPermission
): boolean {
  return context.permissions.includes(permission);
}

export function requirePermission(
  context: LPDocumentAuthContext | null,
  permission: LPDocumentPermission,
  res: NextApiResponse
): boolean {
  if (!context) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }

  if (!hasPermission(context, permission)) {
    res.status(403).json({ error: "Forbidden - insufficient permissions" });
    return false;
  }

  return true;
}

export function canAccessLPDocument(
  context: LPDocumentAuthContext,
  document: { investorId: string; fundId: string }
): boolean {
  if (context.permissions.includes("documents:view_pending")) {
    return context.fundIds.includes(document.fundId);
  }

  if (context.permissions.includes("documents:view_own")) {
    return context.investorId === document.investorId;
  }

  return false;
}

export function canReviewLPDocument(
  context: LPDocumentAuthContext,
  document: { fundId: string }
): boolean {
  return (
    context.permissions.includes("documents:review") &&
    context.fundIds.includes(document.fundId)
  );
}
