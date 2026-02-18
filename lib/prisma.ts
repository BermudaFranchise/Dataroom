import { PrismaClient } from "@prisma/client";
import { softDeleteExtension } from "./prisma/extensions/soft-delete";
import { auditLogExtension } from "./prisma/extensions/audit-log";

declare global {
  var prisma: ReturnType<typeof createPrismaClient> | undefined;
}

function createPrismaClient() {
  const baseClient = new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"],
  });

  return baseClient
    .$extends(softDeleteExtension)
    .$extends(auditLogExtension);
}

const prisma = global.prisma || createPrismaClient();

if (process.env.NODE_ENV === "development") global.prisma = prisma;

export default prisma;

export { runWithAuditContext, getAuditContext } from "./prisma/extensions/audit-log";
export { createRawPrismaClient } from "./prisma/extensions/soft-delete";
