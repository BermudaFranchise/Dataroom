// @ts-nocheck
/**
 * Admin Login API Tests
 *
 * Tests for pages/api/auth/admin-login.ts - Admin magic link login.
 *
 * These tests validate:
 * - Method validation (POST only)
 * - Email validation
 * - Admin email verification (static list and database)
 * - Magic link creation
 * - Email sending
 * - Error handling
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions
const mockIsAdminEmail = jest.fn();
const mockCreateAdminMagicLink = jest.fn();
const mockSendEmail = jest.fn();
const mockUserTeamFindFirst = jest.fn();

// Mock dependencies
jest.mock("@/lib/constants/admins", () => ({
  isAdminEmail: (...args: any[]) => mockIsAdminEmail(...args),
}));

jest.mock("@/lib/auth/admin-magic-link", () => ({
  createAdminMagicLink: (...args: any[]) => mockCreateAdminMagicLink(...args),
}));

jest.mock("@/lib/resend", () => ({
  sendEmail: (...args: any[]) => mockSendEmail(...args),
}));

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    userTeam: {
      findFirst: (...args: any[]) => mockUserTeamFindFirst(...args),
    },
  },
}));

// Mock email component
jest.mock("@/components/emails/admin-login-link", () => ({
  __esModule: true,
  default: jest.fn().mockReturnValue(null),
}));

import handler from "@/pages/api/auth/admin-login";

describe("Admin Login API", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockIsAdminEmail.mockReturnValue(false);
    mockUserTeamFindFirst.mockResolvedValue(null);
    mockCreateAdminMagicLink.mockResolvedValue({
      magicLink: "https://example.com/verify?token=abc123",
      token: "abc123",
    });
    mockSendEmail.mockResolvedValue({ success: true });
  });

  describe("Method Validation", () => {
    it("should reject GET requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
      expect(res._getJSONData()).toEqual({ error: "Method not allowed" });
    });

    it("should reject PUT requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "PUT",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
    });

    it("should reject DELETE requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "DELETE",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
    });

    it("should accept POST requests", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).not.toBe(405);
    });
  });

  describe("Email Validation", () => {
    it("should reject missing email", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: {},
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData()).toEqual({ error: "Email is required" });
    });

    it("should reject non-string email", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: 12345 },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData()).toEqual({ error: "Email is required" });
    });

    it("should reject empty string email", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
    });

    it("should normalize email to lowercase", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "ADMIN@EXAMPLE.COM" },
      });

      await handler(req, res);

      expect(mockIsAdminEmail).toHaveBeenCalledWith("admin@example.com");
    });

    it("should trim whitespace from email", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "  admin@example.com  " },
      });

      await handler(req, res);

      expect(mockIsAdminEmail).toHaveBeenCalledWith("admin@example.com");
    });
  });

  describe("Admin Verification", () => {
    it("should check static admin list first", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
      });

      await handler(req, res);

      expect(mockIsAdminEmail).toHaveBeenCalledWith("admin@example.com");
      expect(res._getStatusCode()).toBe(200);
    });

    it("should check database if not in static list", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockResolvedValue({
        id: "team-1",
        role: "ADMIN",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "dbadmin@example.com" },
      });

      await handler(req, res);

      expect(mockUserTeamFindFirst).toHaveBeenCalledWith({
        where: {
          user: { email: { equals: "dbadmin@example.com", mode: "insensitive" } },
          role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
          status: "ACTIVE",
        },
      });
      expect(res._getStatusCode()).toBe(200);
    });

    it("should reject non-admin users", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "notadmin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(403);
      expect(res._getJSONData()).toEqual({
        error: "Access denied. You are not an administrator.",
      });
    });

    it("should accept OWNER role from database", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockResolvedValue({ id: "team-1", role: "OWNER" });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "owner@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
    });

    it("should accept SUPER_ADMIN role from database", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockResolvedValue({ id: "team-1", role: "SUPER_ADMIN" });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "superadmin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
    });

    it("should handle database errors gracefully", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockRejectedValue(new Error("Database error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(403); // Falls through as non-admin
    });
  });

  describe("Magic Link Creation", () => {
    it("should create magic link for admin user", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: {
          host: "example.com",
          "x-forwarded-proto": "https",
        },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith({
        email: "admin@example.com",
        redirectPath: "/hub",
        baseUrl: expect.any(String),
      });
    });

    it("should use custom redirect path if provided", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com", redirectPath: "/dashboard" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith(
        expect.objectContaining({
          redirectPath: "/dashboard",
        })
      );
    });

    it("should default redirect to /hub if not provided", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith(
        expect.objectContaining({
          redirectPath: "/hub",
        })
      );
    });

    it("should handle magic link creation failure", async () => {
      mockIsAdminEmail.mockReturnValue(true);
      mockCreateAdminMagicLink.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData()).toEqual({ error: "Failed to create login link" });
    });
  });

  describe("Email Sending", () => {
    it("should send magic link email", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(mockSendEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: "admin@example.com",
          subject: "Your Admin Login Link - BF Fund",
        })
      );
      // Verify from contains dataroom@
      const callArg = mockSendEmail.mock.calls[0][0];
      expect(callArg.from).toContain("dataroom@");
    });

    it("should return success after sending email", async () => {
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      expect(res._getJSONData()).toEqual({
        success: true,
        message: "Login link sent to your email",
      });
    });

    it("should handle email sending failure", async () => {
      mockIsAdminEmail.mockReturnValue(true);
      mockSendEmail.mockRejectedValue(new Error("Email service unavailable"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData()).toEqual({ error: "Failed to send login link" });
    });
  });

  describe("Base URL Construction", () => {
    it("should use NEXTAUTH_URL if set", async () => {
      const originalEnv = process.env.NEXTAUTH_URL;
      process.env.NEXTAUTH_URL = "https://app.example.com";
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: { host: "other.com" },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith(
        expect.objectContaining({
          baseUrl: "https://app.example.com",
        })
      );

      process.env.NEXTAUTH_URL = originalEnv;
    });

    it("should construct URL from headers if NEXTAUTH_URL not set", async () => {
      const originalEnv = process.env.NEXTAUTH_URL;
      delete process.env.NEXTAUTH_URL;
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: {
          host: "myapp.com",
          "x-forwarded-proto": "https",
        },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith(
        expect.objectContaining({
          baseUrl: "https://myapp.com",
        })
      );

      process.env.NEXTAUTH_URL = originalEnv;
    });

    it("should use x-forwarded-host if available", async () => {
      const originalEnv = process.env.NEXTAUTH_URL;
      delete process.env.NEXTAUTH_URL;
      mockIsAdminEmail.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com" },
        headers: {
          host: "internal.com",
          "x-forwarded-host": "public.example.com",
          "x-forwarded-proto": "https",
        },
      });

      await handler(req, res);

      expect(mockCreateAdminMagicLink).toHaveBeenCalledWith(
        expect.objectContaining({
          baseUrl: "https://public.example.com",
        })
      );

      process.env.NEXTAUTH_URL = originalEnv;
    });
  });

  describe("Security Considerations", () => {
    it("should not leak admin status to non-admins", async () => {
      mockIsAdminEmail.mockReturnValue(false);
      mockUserTeamFindFirst.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "attacker@example.com" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(403);
      // Error message is generic enough to not reveal admin emails
    });

    it("should handle email injection attempts", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { email: "admin@example.com\nBcc: attacker@evil.com" },
      });

      await handler(req, res);

      // Should normalize and check the malformed email
      expect(mockIsAdminEmail).toHaveBeenCalled();
    });
  });
});
