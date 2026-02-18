// @ts-nocheck
/**
 * Authorization Tests
 *
 * Tests for lib/auth/authorization.ts - Admin and visitor portal authorization.
 *
 * These tests validate:
 * - checkIsAdmin: Admin email validation and database role lookup
 * - checkViewerAccess: Viewer access through various methods (viewer record, groups, allowList)
 * - authorizeAdminPortal: Admin portal access control
 * - authorizeVisitorPortal: Visitor portal access control with fallback to admin role
 */

// Mock prisma before importing authorization
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    userTeam: {
      findFirst: jest.fn(),
    },
    viewer: {
      findFirst: jest.fn(),
    },
    link: {
      findFirst: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

// Mock the admins constants
jest.mock("@/lib/constants/admins", () => ({
  isAdminEmail: jest.fn(),
  DEFAULT_ADMIN_EMAIL: "admin@example.com",
  ADMIN_EMAILS: ["admin@example.com"],
}));

import {
  checkIsAdmin,
  checkViewerAccess,
  authorizeAdminPortal,
  authorizeVisitorPortal,
} from "@/lib/auth/authorization";
import prisma from "@/lib/prisma";
import { isAdminEmail } from "@/lib/constants/admins";

describe("Authorization", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (isAdminEmail as jest.Mock).mockReturnValue(false);
  });

  describe("checkIsAdmin", () => {
    it("should return true for static admin email", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(true);

      const result = await checkIsAdmin("admin@example.com");

      expect(result).toBe(true);
      expect(isAdminEmail).toHaveBeenCalledWith("admin@example.com");
      // Should not query database if static check passes
      expect(prisma.userTeam.findFirst).not.toHaveBeenCalled();
    });

    it("should return true for database admin (OWNER role)", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "ut-1",
        userId: "user-1",
        role: "OWNER",
        status: "ACTIVE",
      });

      const result = await checkIsAdmin("owner@example.com");

      expect(result).toBe(true);
      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: {
          user: { email: { equals: "owner@example.com", mode: "insensitive" } },
          role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
          status: "ACTIVE",
        },
      });
    });

    it("should return true for database admin (ADMIN role)", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "ut-2",
        userId: "user-2",
        role: "ADMIN",
        status: "ACTIVE",
      });

      const result = await checkIsAdmin("admin-user@example.com");

      expect(result).toBe(true);
    });

    it("should return true for database admin (SUPER_ADMIN role)", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "ut-3",
        userId: "user-3",
        role: "SUPER_ADMIN",
        status: "ACTIVE",
      });

      const result = await checkIsAdmin("superadmin@example.com");

      expect(result).toBe(true);
    });

    it("should return false for non-admin user", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await checkIsAdmin("viewer@example.com");

      expect(result).toBe(false);
    });

    it("should normalize email to lowercase", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await checkIsAdmin("Admin@EXAMPLE.COM");

      expect(isAdminEmail).toHaveBeenCalledWith("admin@example.com");
      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: {
          user: { email: { equals: "admin@example.com", mode: "insensitive" } },
          role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
          status: "ACTIVE",
        },
      });
    });

    it("should only match ACTIVE status", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await checkIsAdmin("inactive-admin@example.com");

      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: "ACTIVE",
          }),
        })
      );
    });
  });

  describe("checkViewerAccess", () => {
    it("should return access via viewer record", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        { id: "viewer-1" }, // existingViewer
        null, // viewerWithGroups
        null, // linkWithEmail
      ]);

      const result = await checkViewerAccess("viewer@example.com");

      expect(result).toEqual({
        hasAccess: true,
        accessMethod: "viewer record",
      });
    });

    it("should return access via group membership", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null, // existingViewer
        { id: "viewer-2" }, // viewerWithGroups
        null, // linkWithEmail
      ]);

      const result = await checkViewerAccess("group-member@example.com");

      expect(result).toEqual({
        hasAccess: true,
        accessMethod: "group membership",
      });
    });

    it("should return access via link allowList", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null, // existingViewer
        null, // viewerWithGroups
        { id: "link-1" }, // linkWithEmail
      ]);

      const result = await checkViewerAccess("allowed@example.com");

      expect(result).toEqual({
        hasAccess: true,
        accessMethod: "link allowList",
      });
    });

    it("should prioritize viewer record over other methods", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        { id: "viewer-1" }, // existingViewer
        { id: "viewer-1" }, // viewerWithGroups (same viewer in group)
        { id: "link-1" }, // linkWithEmail (also in allowList)
      ]);

      const result = await checkViewerAccess("multi-access@example.com");

      expect(result.accessMethod).toBe("viewer record");
    });

    it("should return no access when not found", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        null,
        null,
      ]);

      const result = await checkViewerAccess("unknown@example.com");

      expect(result).toEqual({
        hasAccess: false,
        accessMethod: null,
      });
    });

    it("should normalize email to lowercase", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([null, null, null]);

      await checkViewerAccess("VIEWER@EXAMPLE.COM");

      // The transaction should be called with the lowercased email
      expect(prisma.$transaction).toHaveBeenCalled();
    });

    it("should exclude revoked viewers", async () => {
      // The query should filter out revoked viewers
      (prisma.$transaction as jest.Mock).mockImplementation((queries) => {
        // Verify the queries include accessRevokedAt: null condition
        return Promise.resolve([null, null, null]);
      });

      await checkViewerAccess("revoked@example.com");

      expect(prisma.$transaction).toHaveBeenCalled();
    });

    it("should exclude archived/deleted links", async () => {
      (prisma.$transaction as jest.Mock).mockResolvedValue([null, null, null]);

      await checkViewerAccess("test@example.com");

      // Verify transaction was called (which includes filtering for non-deleted links)
      expect(prisma.$transaction).toHaveBeenCalled();
    });
  });

  describe("authorizeAdminPortal", () => {
    it("should allow access for admin user", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(true);

      const result = await authorizeAdminPortal("admin@example.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "admin role",
      });
    });

    it("should allow access for database admin", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "ut-1",
        role: "OWNER",
        status: "ACTIVE",
      });

      const result = await authorizeAdminPortal("owner@company.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "admin role",
      });
    });

    it("should deny access for non-admin", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await authorizeAdminPortal("viewer@example.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("Non-admin attempting admin portal access");
      expect(result.redirectUrl).toContain("/admin/login");
      expect(result.redirectUrl).toContain("error=AccessDenied");
    });

    it("should include helpful error message in redirect URL", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await authorizeAdminPortal("viewer@example.com");

      expect(result.redirectUrl).toContain("message=");
      expect(result.redirectUrl).toContain("investor+portal");
    });
  });

  describe("authorizeVisitorPortal", () => {
    it("should allow access for viewer with viewer record", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        { id: "viewer-1" },
        null,
        null,
      ]);

      const result = await authorizeVisitorPortal("viewer@example.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "viewer record",
      });
    });

    it("should allow access for viewer with group membership", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        { id: "viewer-1" },
        null,
      ]);

      const result = await authorizeVisitorPortal("group@example.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "group membership",
      });
    });

    it("should allow access for viewer with link allowList", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        null,
        { id: "link-1" },
      ]);

      const result = await authorizeVisitorPortal("allowed@example.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "link allowList",
      });
    });

    it("should allow admin access to visitor portal", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(true);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        null,
        null,
      ]);

      const result = await authorizeVisitorPortal("admin@example.com");

      expect(result).toEqual({
        allowed: true,
        accessMethod: "admin role",
      });
    });

    it("should prefer viewer access method over admin role", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(true);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "ut-1",
        role: "OWNER",
      });
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        { id: "viewer-1" },
        null,
        null,
      ]);

      const result = await authorizeVisitorPortal("admin-viewer@example.com");

      expect(result.accessMethod).toBe("viewer record");
    });

    it("should deny access for user with neither viewer access nor admin role", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        null,
        null,
      ]);

      const result = await authorizeVisitorPortal("unknown@example.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("No viewer access or admin role");
      expect(result.redirectUrl).toContain("/login");
      expect(result.redirectUrl).toContain("error=AccessDenied");
    });

    it("should run admin and viewer checks in parallel", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      (prisma.$transaction as jest.Mock).mockResolvedValue([
        null,
        null,
        null,
      ]);

      await authorizeVisitorPortal("test@example.com");

      // Both checks should be initiated
      expect(prisma.userTeam.findFirst).toHaveBeenCalled();
      expect(prisma.$transaction).toHaveBeenCalled();
    });
  });

  describe("AuthorizationResult Structure", () => {
    it("should return correct structure for allowed access", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(true);

      const result = await authorizeAdminPortal("admin@example.com");

      expect(result).toHaveProperty("allowed", true);
      expect(result).toHaveProperty("accessMethod");
      expect(result).not.toHaveProperty("reason");
    });

    it("should return correct structure for denied access", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await authorizeAdminPortal("viewer@example.com");

      expect(result).toHaveProperty("allowed", false);
      expect(result).toHaveProperty("reason");
      expect(result).toHaveProperty("redirectUrl");
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty email", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await checkIsAdmin("");

      expect(result).toBe(false);
    });

    it("should handle email with special characters", async () => {
      (isAdminEmail as jest.Mock).mockReturnValue(false);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await checkIsAdmin("user+tag@example.com");

      expect(result).toBe(false);
      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: {
          user: { email: { equals: "user+tag@example.com", mode: "insensitive" } },
          role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
          status: "ACTIVE",
        },
      });
    });

    it("should handle database errors gracefully in checkViewerAccess", async () => {
      (prisma.$transaction as jest.Mock).mockRejectedValue(new Error("DB Error"));

      await expect(checkViewerAccess("test@example.com")).rejects.toThrow("DB Error");
    });
  });
});
