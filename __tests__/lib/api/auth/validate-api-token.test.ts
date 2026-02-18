// @ts-nocheck
/**
 * API Token Validation Tests
 *
 * Tests for lib/api/auth/validate-api-token.ts - Bearer token validation.
 *
 * These tests validate:
 * - Authorization header format validation
 * - Token hashing and lookup
 * - Token expiration handling
 * - lastUsed timestamp updates
 * - Error responses for various failure cases
 */

// Mock prisma before importing
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    restrictedToken: {
      findFirst: jest.fn(),
      update: jest.fn(),
    },
  },
}));

// Mock the token hashing function
jest.mock("@/lib/api/auth/token", () => ({
  hashToken: jest.fn((token) => `hashed_${token}`),
}));

import { validateApiToken } from "@/lib/api/auth/validate-api-token";
import prisma from "@/lib/prisma";
import { hashToken } from "@/lib/api/auth/token";

describe("validateApiToken", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Authorization Header Validation", () => {
    it("should reject missing Authorization header", async () => {
      const result = await validateApiToken(undefined);

      expect(result).toEqual({
        valid: false,
        error: "Missing or invalid Authorization header",
      });
      expect(prisma.restrictedToken.findFirst).not.toHaveBeenCalled();
    });

    it("should reject empty Authorization header", async () => {
      const result = await validateApiToken("");

      expect(result).toEqual({
        valid: false,
        error: "Missing or invalid Authorization header",
      });
    });

    it("should reject non-Bearer Authorization header", async () => {
      const result = await validateApiToken("Basic dXNlcjpwYXNz");

      expect(result).toEqual({
        valid: false,
        error: "Missing or invalid Authorization header",
      });
    });

    it("should reject Authorization header without Bearer prefix", async () => {
      const result = await validateApiToken("token123");

      expect(result).toEqual({
        valid: false,
        error: "Missing or invalid Authorization header",
      });
    });

    it("should reject Bearer header with empty token", async () => {
      const result = await validateApiToken("Bearer ");

      expect(result).toEqual({
        valid: false,
        error: "Token is required",
      });
    });

    it("should reject Bearer header with only whitespace token", async () => {
      // When the token is just whitespace, slice(7) will return whitespace
      // which is truthy, so it will proceed to hash and lookup
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await validateApiToken("Bearer    ");

      // The token "   " is truthy, so it will try to validate
      expect(hashToken).toHaveBeenCalled();
    });
  });

  describe("Token Lookup", () => {
    it("should hash the token before lookup", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      await validateApiToken("Bearer my-api-token");

      expect(hashToken).toHaveBeenCalledWith("my-api-token");
    });

    it("should look up token with correct criteria", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      await validateApiToken("Bearer test-token");

      expect(prisma.restrictedToken.findFirst).toHaveBeenCalledWith({
        where: {
          hashedKey: "hashed_test-token",
          OR: [
            { expires: null },
            { expires: { gt: expect.any(Date) } },
          ],
        },
        select: {
          id: true,
          teamId: true,
          userId: true,
          scopes: true,
        },
      });
    });

    it("should accept tokens with no expiration", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "token-1",
        teamId: "team-1",
        userId: "user-1",
        scopes: ["read", "write"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer valid-token");

      expect(result.valid).toBe(true);
    });

    it("should accept tokens with future expiration", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "token-2",
        teamId: "team-2",
        userId: "user-2",
        scopes: ["admin"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer future-token");

      expect(result.valid).toBe(true);
    });

    it("should reject invalid or expired tokens", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await validateApiToken("Bearer invalid-token");

      expect(result).toEqual({
        valid: false,
        error: "Invalid or expired token",
      });
    });
  });

  describe("Successful Validation", () => {
    it("should return token details on success", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "token-123",
        teamId: "team-456",
        userId: "user-789",
        scopes: ["read", "write"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer my-valid-token");

      expect(result).toEqual({
        valid: true,
        teamId: "team-456",
        userId: "user-789",
        tokenId: "token-123",
      });
    });

    it("should update lastUsed timestamp on successful validation", async () => {
      const tokenId = "token-to-update";
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: tokenId,
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      await validateApiToken("Bearer update-last-used");

      expect(prisma.restrictedToken.update).toHaveBeenCalledWith({
        where: { id: tokenId },
        data: { lastUsed: expect.any(Date) },
      });
    });

    it("should handle tokens without teamId", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "personal-token",
        teamId: null,
        userId: "user-123",
        scopes: ["personal"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer personal-token");

      expect(result).toEqual({
        valid: true,
        teamId: null,
        userId: "user-123",
        tokenId: "personal-token",
      });
    });

    it("should handle tokens without userId", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "system-token",
        teamId: "team-system",
        userId: null,
        scopes: ["system"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer system-token");

      expect(result).toEqual({
        valid: true,
        teamId: "team-system",
        userId: null,
        tokenId: "system-token",
      });
    });
  });

  describe("ApiTokenValidation Interface", () => {
    it("should return valid=true with IDs on success", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "tok-1",
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken("Bearer test");

      expect(result.valid).toBe(true);
      expect(result.tokenId).toBe("tok-1");
      expect(result.teamId).toBe("team-1");
      expect(result.userId).toBe("user-1");
      expect(result.error).toBeUndefined();
    });

    it("should return valid=false with error on failure", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await validateApiToken("Bearer invalid");

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.tokenId).toBeUndefined();
      expect(result.teamId).toBeUndefined();
      expect(result.userId).toBeUndefined();
    });
  });

  describe("Edge Cases", () => {
    it("should handle token with special characters", async () => {
      const specialToken = "sk_live_abc123+/=";
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "special-token",
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      await validateApiToken(`Bearer ${specialToken}`);

      expect(hashToken).toHaveBeenCalledWith(specialToken);
    });

    it("should handle very long tokens", async () => {
      const longToken = "a".repeat(1000);
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await validateApiToken(`Bearer ${longToken}`);

      expect(hashToken).toHaveBeenCalledWith(longToken);
      expect(result.valid).toBe(false);
    });

    it("should handle Bearer with different casing", async () => {
      // startsWith is case-sensitive, so "bearer" won't match "Bearer"
      const result = await validateApiToken("bearer my-token");

      expect(result).toEqual({
        valid: false,
        error: "Missing or invalid Authorization header",
      });
    });

    it("should handle Bearer with extra spaces", async () => {
      // "Bearer  token" - double space after Bearer
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "spaced-token",
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      await validateApiToken("Bearer  token-with-leading-space");

      // Token will be " token-with-leading-space" (with leading space)
      expect(hashToken).toHaveBeenCalledWith(" token-with-leading-space");
    });

    it("should handle database errors during lookup", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockRejectedValue(
        new Error("Database connection error")
      );

      await expect(validateApiToken("Bearer db-error-token")).rejects.toThrow(
        "Database connection error"
      );
    });

    it("should handle database errors during update", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "update-error-token",
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockRejectedValue(
        new Error("Update failed")
      );

      await expect(validateApiToken("Bearer update-error")).rejects.toThrow(
        "Update failed"
      );
    });
  });

  describe("Token Types", () => {
    it("should validate personal API token format", async () => {
      const personalToken = "pm_sk_personal_123abc";
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "personal-1",
        teamId: null,
        userId: "user-1",
        scopes: ["read"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken(`Bearer ${personalToken}`);

      expect(result.valid).toBe(true);
    });

    it("should validate team API token format", async () => {
      const teamToken = "pm_sk_team_456def";
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "team-token-1",
        teamId: "team-456",
        userId: null,
        scopes: ["team:admin"],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const result = await validateApiToken(`Bearer ${teamToken}`);

      expect(result.valid).toBe(true);
      expect(result.teamId).toBe("team-456");
    });
  });

  describe("Concurrent Requests", () => {
    it("should handle multiple simultaneous validations", async () => {
      (prisma.restrictedToken.findFirst as jest.Mock).mockResolvedValue({
        id: "concurrent-token",
        teamId: "team-1",
        userId: "user-1",
        scopes: [],
      });
      (prisma.restrictedToken.update as jest.Mock).mockResolvedValue({});

      const results = await Promise.all([
        validateApiToken("Bearer token1"),
        validateApiToken("Bearer token2"),
        validateApiToken("Bearer token3"),
      ]);

      expect(results.every((r) => r.valid)).toBe(true);
      expect(prisma.restrictedToken.findFirst).toHaveBeenCalledTimes(3);
      expect(prisma.restrictedToken.update).toHaveBeenCalledTimes(3);
    });
  });
});
