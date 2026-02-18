import prisma from "@/lib/prisma";
import { LoginPortal } from "@prisma/client";

const PENDING_EXPIRY_MS = 30000;

export async function setPendingPortal(userId: string, portal: "ADMIN" | "VISITOR"): Promise<void> {
  const expiresAt = new Date(Date.now() + PENDING_EXPIRY_MS);
  
  await prisma.pendingPortalUpdate.upsert({
    where: { id: `pending_${userId}` },
    create: {
      id: `pending_${userId}`,
      userId,
      portal: portal as LoginPortal,
      expiresAt,
    },
    update: {
      portal: portal as LoginPortal,
      expiresAt,
    },
  });
}

export async function consumePendingPortal(userId: string): Promise<"ADMIN" | "VISITOR" | null> {
  const pending = await prisma.pendingPortalUpdate.findFirst({
    where: {
      userId,
      expiresAt: { gt: new Date() },
    },
  });
  
  if (!pending) return null;
  
  await prisma.pendingPortalUpdate.delete({
    where: { id: pending.id },
  }).catch(() => {});
  
  return pending.portal as "ADMIN" | "VISITOR";
}

export async function cleanupExpiredPendingPortals(): Promise<void> {
  await prisma.pendingPortalUpdate.deleteMany({
    where: {
      expiresAt: { lt: new Date() },
    },
  }).catch(() => {});
}
