// @ts-nocheck
/**
 * Admin Magic Link Verify API Tests
 *
 * Tests for pages/api/auth/admin-magic-verify.ts - Magic link verification.
 *
 * These tests validate:
 * - Method validation (GET only)
 * - Rate limiting
 * - Token and email validation
 * - Magic link verification
 * - User lookup and JWT creation
 * - Cookie setting with proper attributes
 * - Redirect path validation (open redirect protection)
 * - Error handling and redirects
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions
const mockVerifyAdminMagicLink = jest.fn();
const mockAuthRateLimiter = jest.fn();
const mockEncode = jest.fn();
const mockUserUpsert = jest.fn();
const mockRollbarInfo = jest.fn();
const mockRollbarError = jest.fn();

// Mock dependencies
jest.mock("@/lib/auth/admin-magic-link", () => ({
  verifyAdminMagicLink: (...args: any[]) => mockVerifyAdminMagicLink(...args),
}));

jest.mock("@/lib/security/rate-limiter", () => ({
  authRateLimiter: (...args: any[]) => mockAuthRateLimiter(...args),
}));

jest.mock("next-auth/jwt", () => ({
  encode: (...args: any[]) => mockEncode(...args),
}));

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    user: {
      upsert: (...args: any[]) => mockUserUpsert(...args),
    },
  },
}));

jest.mock("@/lib/rollbar", () => ({
  serverInstance: {
    info: (...args: any[]) => mockRollbarInfo(...args),
    error: (...args: any[]) => mockRollbarError(...args),
  },
}));

import handler from "@/pages/api/auth/admin-magic-verify";

describe("Admin Magic Verify API", () => {
  const mockUser = {
    id: "user-123",
    email: "admin@example.com",
    name: "Admin User",
    image: "https://example.com/avatar.jpg",
    role: "GP",
    createdAt: new Date("2024-01-01"),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockAuthRateLimiter.mockResolvedValue(true);
    mockVerifyAdminMagicLink.mockResolvedValue(true);
    mockUserUpsert.mockResolvedValue(mockUser);
    mockEncode.mockResolvedValue("mock-jwt-token");
    process.env.NEXTAUTH_SECRET = "test-secret";
  });

  describe("Method Validation", () => {
    it("should reject POST requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
      expect(res._getJSONData()).toEqual({ message: "Method not allowed" });
    });

    it("should reject PUT requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "PUT",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
    });

    it("should accept GET requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).not.toBe(405);
    });
  });

  describe("Rate Limiting", () => {
    it("should check rate limiter", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockAuthRateLimiter).toHaveBeenCalledWith(req, res);
    });

    it("should stop processing if rate limited", async () => {
      mockAuthRateLimiter.mockResolvedValue(false);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockVerifyAdminMagicLink).not.toHaveBeenCalled();
    });
  });

  describe("Token and Email Validation", () => {
    it("should redirect on missing token", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toContain("/login?error=InvalidLink");
    });

    it("should redirect on missing email", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toContain("/login?error=InvalidLink");
    });

    it("should redirect on missing both token and email", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {},
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toContain("/login?error=InvalidLink");
    });

    it("should handle array query params (take first)", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: ["token1", "token2"],
          email: ["email1@example.com", "email2@example.com"],
        },
      });

      await handler(req, res);

      expect(mockVerifyAdminMagicLink).toHaveBeenCalledWith({
        token: "token1",
        email: "email1@example.com",
      });
    });
  });

  describe("Magic Link Verification", () => {
    it("should verify the magic link", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "my-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockVerifyAdminMagicLink).toHaveBeenCalledWith({
        token: "my-token",
        email: "admin@example.com",
      });
    });

    it("should redirect on invalid token", async () => {
      mockVerifyAdminMagicLink.mockResolvedValue(false);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "invalid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toContain("/login?error=ExpiredLink");
    });

    it("should redirect on expired token", async () => {
      mockVerifyAdminMagicLink.mockResolvedValue(false);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "expired-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toContain("/login?error=ExpiredLink");
    });
  });

  describe("User Upsert", () => {
    it("should upsert user by email (lowercased)", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "ADMIN@EXAMPLE.COM" },
      });

      await handler(req, res);

      expect(mockUserUpsert).toHaveBeenCalledWith({
        where: { email: "admin@example.com" },
        update: { role: "GP" },
        create: {
          email: "admin@example.com",
          emailVerified: expect.any(Date),
          role: "GP",
        },
      });
    });

    it("should create new user if not exists", async () => {
      const newUser = {
        id: "new-user-456",
        email: "newadmin@example.com",
        role: "GP",
        createdAt: new Date(), // Recent creation time
      };
      mockUserUpsert.mockResolvedValue(newUser);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "newadmin@example.com" },
      });

      await handler(req, res);

      // Should redirect to hub (not error)
      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should update existing user role to GP", async () => {
      // Existing user with LP role - upsert will set to GP
      const existingUser = { ...mockUser, role: "GP" };
      mockUserUpsert.mockResolvedValue(existingUser);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      // Upsert should always set role to GP in update clause
      expect(mockUserUpsert).toHaveBeenCalledWith(
        expect.objectContaining({
          update: { role: "GP" },
        })
      );
    });
  });

  describe("JWT Token Creation", () => {
    it("should create JWT with correct payload", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockEncode).toHaveBeenCalledWith({
        token: expect.objectContaining({
          sub: mockUser.id,
          id: mockUser.id,
          email: mockUser.email,
          name: mockUser.name,
          picture: mockUser.image,
          role: "GP",
          loginPortal: "ADMIN",
        }),
        secret: process.env.NEXTAUTH_SECRET,
        maxAge: 30 * 24 * 60 * 60,
      });
    });

    it("should set GP role for admin users", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockEncode).toHaveBeenCalledWith(
        expect.objectContaining({
          token: expect.objectContaining({
            role: "GP",
          }),
        })
      );
    });

    it("should set loginPortal to ADMIN", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockEncode).toHaveBeenCalledWith(
        expect.objectContaining({
          token: expect.objectContaining({
            loginPortal: "ADMIN",
          }),
        })
      );
    });
  });

  describe("Cookie Setting", () => {
    it("should set session cookie with proper name", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
        headers: { "x-forwarded-proto": "https" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("next-auth.session-token=");
    });

    it("should set HttpOnly flag", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("HttpOnly");
    });

    it("should set SameSite=Lax", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("SameSite=Lax");
    });

    it("should set Path=/", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("Path=/");
    });

    it("should set Secure flag when NODE_ENV is production", async () => {
      // Save original NODE_ENV
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
        headers: { "x-forwarded-proto": "https" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("Secure");

      // Restore original NODE_ENV
      process.env.NODE_ENV = originalEnv;
    });

    it("should not set Secure flag when NODE_ENV is not production", async () => {
      // Save original NODE_ENV
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
        headers: { "x-forwarded-proto": "https" },  // Even with HTTPS, no Secure flag in dev
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie") as string;
      // Split by ; and check none of the parts is exactly "Secure"
      const parts = cookie.split(";").map((p) => p.trim());
      expect(parts).not.toContain("Secure");

      // Restore original NODE_ENV
      process.env.NODE_ENV = originalEnv;
    });

    it("should set 30-day Max-Age", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      const cookie = res.getHeader("Set-Cookie");
      expect(cookie).toContain("Max-Age=2592000"); // 30 * 24 * 60 * 60
    });
  });

  describe("Redirect Path Validation (Open Redirect Protection)", () => {
    it("should redirect to /hub by default", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should allow /hub redirect", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com", redirect: "/hub" },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should allow /datarooms redirect", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "/datarooms/123",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/datarooms/123");
    });

    it("should allow /admin redirect", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "/admin/users",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/admin/users");
    });

    it("should allow /dashboard redirect", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "/dashboard",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/dashboard");
    });

    it("should allow /settings redirect", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "/settings/profile",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/settings/profile");
    });

    it("should block absolute URL redirects (open redirect)", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "https://evil.com",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should block protocol-relative URL redirects", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "//evil.com",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should block non-allowed paths", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "/api/secret",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/hub");
    });

    it("should block paths without leading slash", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: {
          token: "valid-token",
          email: "admin@example.com",
          redirect: "hub",
        },
      });

      await handler(req, res);

      expect(res._getRedirectUrl()).toBe("/hub");
    });
  });

  describe("Error Handling", () => {
    it("should redirect on verification error", async () => {
      mockVerifyAdminMagicLink.mockRejectedValue(new Error("Verification failed"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(302);
      expect(res._getRedirectUrl()).toContain("/login?error=VerificationFailed");
    });

    it("should log errors to Rollbar", async () => {
      mockVerifyAdminMagicLink.mockRejectedValue(new Error("Some error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockRollbarError).toHaveBeenCalledWith(
        "[ADMIN_MAGIC_VERIFY] Error",
        expect.any(Object)
      );
    });

    it("should log successful sign-ins to Rollbar", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        query: { token: "valid-token", email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockRollbarInfo).toHaveBeenCalledWith(
        "[ADMIN_MAGIC_VERIFY] Sign-in completed successfully",
        expect.objectContaining({
          userId: mockUser.id,
        })
      );
    });
  });
});
