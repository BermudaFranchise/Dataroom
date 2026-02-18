/**
 * Admin Guard Tests
 *
 * Tests for lib/auth/admin-guard.ts - Admin portal access control,
 * JWT token parsing, and role-based route protection.
 *
 * Security-critical tests for admin access enforcement.
 */

import { GetServerSidePropsContext } from "next";

// Mock next-auth modules
const mockSession = {
  user: {
    id: "user-123",
    email: "admin@example.com",
    name: "Admin User",
  },
  expires: "2099-01-01",
};

jest.mock("next-auth/next", () => ({
  getServerSession: jest.fn(),
}));

jest.mock("next-auth/jwt", () => ({
  getToken: jest.fn(),
  decode: jest.fn(),
}));

jest.mock("next/navigation", () => ({
  redirect: jest.fn((url: string) => {
    throw new Error(`REDIRECT:${url}`);
  }),
}));

jest.mock("next/headers", () => ({
  cookies: jest.fn(() =>
    Promise.resolve({
      get: jest.fn((name: string) => {
        if (name === "next-auth.session-token") {
          return { value: "mock-jwt-token" };
        }
        return undefined;
      }),
    })
  ),
  headers: jest.fn(() => new Map()),
}));

// Mock prisma
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    userTeam: {
      findFirst: jest.fn(),
    },
  },
}));

// Mock auth options
jest.mock("@/lib/auth/auth-options", () => ({
  authOptions: {
    providers: [],
    callbacks: {},
  },
}));

import { getServerSession } from "next-auth/next";
import { decode } from "next-auth/jwt";
import { redirect } from "next/navigation";
import prisma from "@/lib/prisma";

import {
  requireAdminPortalAccess,
  requireAdminAccess,
  withAdminGuard,
  AdminPortalGuardResult,
} from "@/lib/auth/admin-guard";

describe("Admin Guard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NEXTAUTH_SECRET = "test-secret";
  });

  describe("requireAdminPortalAccess", () => {
    it("should redirect to login when no session", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(null);

      await expect(requireAdminPortalAccess()).rejects.toThrow(
        "REDIRECT:/admin/login"
      );
    });

    it("should redirect to viewer portal when user has no admin team", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(requireAdminPortalAccess()).rejects.toThrow(
        "REDIRECT:/viewer-portal"
      );
    });

    it("should redirect when loginPortal is not ADMIN", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "VISITOR" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "ADMIN",
        status: "ACTIVE",
      });

      await expect(requireAdminPortalAccess()).rejects.toThrow(
        "REDIRECT:/viewer-portal?error=wrong_portal"
      );
    });

    it("should allow access for valid admin with ADMIN portal login", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "ADMIN",
        status: "ACTIVE",
      });

      const result = await requireAdminPortalAccess();

      expect(result).toHaveProperty("session");
      expect(result).toHaveProperty("user");
      expect(result).toHaveProperty("userTeam");
      expect(result.loginPortal).toBe("ADMIN");
    });

    it("should allow OWNER role", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "OWNER",
        status: "ACTIVE",
      });

      const result = await requireAdminPortalAccess();

      expect(result.userTeam.role).toBe("OWNER");
    });

    it("should allow SUPER_ADMIN role", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "SUPER_ADMIN",
        status: "ACTIVE",
      });

      const result = await requireAdminPortalAccess();

      expect(result.userTeam.role).toBe("SUPER_ADMIN");
    });

    it("should only check for ACTIVE user teams", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(requireAdminPortalAccess()).rejects.toThrow("REDIRECT");

      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: expect.objectContaining({
          status: "ACTIVE",
        }),
      });
    });

    it("should handle JWT decode errors gracefully", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockRejectedValue(new Error("Invalid token"));
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "ADMIN",
        status: "ACTIVE",
      });

      // Should default to VISITOR portal when decode fails
      await expect(requireAdminPortalAccess()).rejects.toThrow(
        "REDIRECT:/viewer-portal?error=wrong_portal"
      );
    });

    it("should check correct admin roles", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      try {
        await requireAdminPortalAccess();
      } catch {
        // Expected redirect
      }

      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: expect.objectContaining({
          role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
        }),
      });
    });
  });

  describe("requireAdminAccess", () => {
    const createMockContext = (
      overrides: Partial<GetServerSidePropsContext> = {}
    ): GetServerSidePropsContext => ({
      req: {
        headers: {},
        cookies: {},
      } as any,
      res: {
        setHeader: jest.fn(),
      } as any,
      query: {},
      resolvedUrl: "/admin",
      ...overrides,
    });

    it("should redirect to login when no session", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(null);
      const context = createMockContext();

      const result = await requireAdminAccess(context);

      expect(result).toEqual({
        redirect: {
          destination: "/login",
          permanent: false,
        },
      });
    });

    it("should redirect to viewer portal when no userTeam", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);
      const context = createMockContext();

      const result = await requireAdminAccess(context);

      expect(result).toEqual({
        redirect: {
          destination: "/viewer-portal",
          permanent: false,
        },
      });
    });

    it("should return props for valid admin", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        userId: "user-123",
        role: "ADMIN",
      });
      const context = createMockContext();

      const result = await requireAdminAccess(context);

      expect(result).toEqual({ props: {} });
    });

    it("should check user by userId from session", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
      });
      const context = createMockContext();

      await requireAdminAccess(context);

      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: {
          userId: "user-123",
        },
      });
    });
  });

  describe("withAdminGuard", () => {
    const createMockContext = (): GetServerSidePropsContext => ({
      req: { headers: {}, cookies: {} } as any,
      res: { setHeader: jest.fn() } as any,
      query: {},
      resolvedUrl: "/admin",
    });

    it("should redirect when guard fails", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(null);

      const wrappedHandler = withAdminGuard();
      const context = createMockContext();

      const result = await wrappedHandler(context);

      expect(result).toHaveProperty("redirect");
    });

    it("should call wrapped function when guard passes", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
      });

      const mockHandler = jest.fn().mockResolvedValue({
        props: { customData: "test" },
      });
      const wrappedHandler = withAdminGuard(mockHandler);
      const context = createMockContext();

      const result = await wrappedHandler(context);

      expect(mockHandler).toHaveBeenCalledWith(context);
      expect(result).toEqual({ props: { customData: "test" } });
    });

    it("should return empty props when no handler provided", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
      });

      const wrappedHandler = withAdminGuard();
      const context = createMockContext();

      const result = await wrappedHandler(context);

      expect(result).toEqual({ props: {} });
    });
  });

  describe("Security Requirements", () => {
    it("should not allow MEMBER role as admin", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      // MEMBER role should not be returned by the query
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(requireAdminPortalAccess()).rejects.toThrow("REDIRECT");
    });

    it("should not allow VIEWER role as admin", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      // VIEWER role should not be returned by the query
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(requireAdminPortalAccess()).rejects.toThrow("REDIRECT");
    });

    it("should not allow INACTIVE user teams", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });

      // Query should filter by ACTIVE status
      try {
        await requireAdminPortalAccess();
      } catch {
        // Expected
      }

      expect(prisma.userTeam.findFirst).toHaveBeenCalledWith({
        where: expect.objectContaining({
          status: "ACTIVE",
        }),
      });
    });

    it("should validate JWT token from session cookie", async () => {
      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (decode as jest.Mock).mockResolvedValue({ loginPortal: "ADMIN" });
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        role: "ADMIN",
        status: "ACTIVE",
      });

      await requireAdminPortalAccess();

      expect(decode).toHaveBeenCalledWith({
        token: "mock-jwt-token",
        secret: "test-secret",
      });
    });

    it("should default to VISITOR portal when no token", async () => {
      const mockCookies = jest.requireMock("next/headers").cookies;
      mockCookies.mockImplementationOnce(() =>
        Promise.resolve({
          get: jest.fn().mockReturnValue(undefined),
        })
      );

      (getServerSession as jest.Mock).mockResolvedValue(mockSession);
      (prisma.userTeam.findFirst as jest.Mock).mockResolvedValue({
        id: "team-1",
        role: "ADMIN",
        status: "ACTIVE",
      });

      // Should redirect because loginPortal defaults to VISITOR
      await expect(requireAdminPortalAccess()).rejects.toThrow("REDIRECT");
    });
  });
});
