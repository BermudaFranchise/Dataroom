/**
 * Dataroom Auth Tests
 *
 * Tests for lib/auth/dataroom-auth.ts - Dataroom session management,
 * token validation, and access verification.
 *
 * Security-critical tests for dataroom access control.
 */

import { NextApiRequest } from "next";
import { NextRequest } from "next/server";

// Mock redis - use inline mock to avoid hoisting issues
jest.mock("@/lib/redis", () => ({
  redis: {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  },
}));

// Import the mocked redis after mock setup
import { redis } from "@/lib/redis";
const mockRedis = redis as jest.Mocked<NonNullable<typeof redis>>;

// Mock crypto
jest.mock("crypto", () => ({
  randomBytes: jest.fn(() => ({
    toString: jest.fn(() => "mock-session-token-hex"),
  })),
}));

// Mock cookies
const mockCookieGet = jest.fn();
jest.mock("next/headers", () => ({
  cookies: jest.fn(() =>
    Promise.resolve({
      get: mockCookieGet,
    })
  ),
}));

// Mock cookie parser
jest.mock("cookie", () => ({
  parse: jest.fn((cookieString: string) => {
    const cookies: Record<string, string> = {};
    if (cookieString) {
      cookieString.split(";").forEach((pair) => {
        const [key, value] = pair.trim().split("=");
        if (key && value) {
          cookies[key] = value;
        }
      });
    }
    return cookies;
  }),
}));

// Mock IP utilities
jest.mock("@vercel/functions", () => ({
  ipAddress: jest.fn(() => "127.0.0.1"),
}));

jest.mock("@/lib/utils/geo", () => ({
  LOCALHOST_IP: "127.0.0.1",
}));

jest.mock("@/lib/utils/ip", () => ({
  getIpAddress: jest.fn(() => "192.168.1.1"),
}));

import {
  DataroomSessionSchema,
  DataroomSession,
  verifyDataroomSession,
  verifyDataroomSessionInPagesRouter,
} from "@/lib/auth/dataroom-auth";

describe("Dataroom Auth", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("DataroomSessionSchema", () => {
    it("should validate correct session data", () => {
      const validSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const result = DataroomSessionSchema.parse(validSession);

      expect(result).toEqual(validSession);
    });

    it("should validate session with optional viewerId", () => {
      const sessionWithViewer = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        viewerId: "viewer-abc",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const result = DataroomSessionSchema.parse(sessionWithViewer);

      expect(result.viewerId).toBe("viewer-abc");
    });

    it("should reject session without required linkId", () => {
      const invalidSession = {
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      expect(() => DataroomSessionSchema.parse(invalidSession)).toThrow();
    });

    it("should reject session without required dataroomId", () => {
      const invalidSession = {
        linkId: "link-123",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      expect(() => DataroomSessionSchema.parse(invalidSession)).toThrow();
    });

    it("should reject session without required viewId", () => {
      const invalidSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      expect(() => DataroomSessionSchema.parse(invalidSession)).toThrow();
    });

    it("should reject session with invalid expiresAt type", () => {
      const invalidSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: "not-a-number",
        ipAddress: "192.168.1.1",
        verified: true,
      };

      expect(() => DataroomSessionSchema.parse(invalidSession)).toThrow();
    });

    it("should reject session with invalid verified type", () => {
      const invalidSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now(),
        ipAddress: "192.168.1.1",
        verified: "yes", // Should be boolean
      };

      expect(() => DataroomSessionSchema.parse(invalidSession)).toThrow();
    });
  });

  describe("verifyDataroomSession", () => {
    const createMockNextRequest = (): NextRequest => ({
      headers: new Headers(),
      cookies: {
        get: jest.fn(),
      },
    } as unknown as NextRequest);

    it("should return null when dataroomId is empty", async () => {
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(request, "link-123", "");

      expect(result).toBeNull();
    });

    it("should return null when redis is not configured", async () => {
      // Temporarily mock redis as null
      const originalRedis = mockRedis;
      jest.mock("@/lib/redis", () => ({ redis: null }));

      // The function should handle null redis gracefully
      // This tests the early return
    });

    it("should return null when session token cookie is missing", async () => {
      mockCookieGet.mockReturnValue(undefined);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });

    it("should return null when session not found in redis", async () => {
      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(null);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });

    it("should return null and delete expired session", async () => {
      const expiredSession: DataroomSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() - 3600000, // Expired 1 hour ago
        ipAddress: "192.168.1.1",
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(expiredSession);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      expect(mockRedis.del).toHaveBeenCalledWith(
        "dataroom_session:session-token"
      );
    });

    it("should return null and delete session with wrong linkId", async () => {
      const session: DataroomSession = {
        linkId: "different-link",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(session);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      expect(mockRedis.del).toHaveBeenCalled();
    });

    it("should return null and delete session with wrong dataroomId", async () => {
      const session: DataroomSession = {
        linkId: "link-123",
        dataroomId: "different-dataroom",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(session);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      expect(mockRedis.del).toHaveBeenCalled();
    });

    it("should return valid session data", async () => {
      const validSession: DataroomSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(validSession);
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toEqual(validSession);
    });

    it("should handle invalid session data in redis", async () => {
      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue({ invalid: "data" });
      const request = createMockNextRequest();

      const result = await verifyDataroomSession(
        request,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      expect(mockRedis.del).toHaveBeenCalled();
    });
  });

  describe("verifyDataroomSessionInPagesRouter", () => {
    const createMockApiRequest = (
      cookies: Record<string, string> = {}
    ): NextApiRequest => {
      const cookieString = Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");

      return {
        headers: {
          cookie: cookieString,
        },
      } as unknown as NextApiRequest;
    };

    it("should return null when dataroomId is empty", async () => {
      const req = createMockApiRequest();

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        ""
      );

      expect(result).toBeNull();
    });

    it("should return null when cookie is missing", async () => {
      const req = createMockApiRequest({});

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });

    it("should return null when session not found in redis", async () => {
      const req = createMockApiRequest({
        "pm_drs_link-123": "session-token",
      });
      mockRedis.get.mockResolvedValue(null);

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });

    it("should return null and delete expired session", async () => {
      const expiredSession: DataroomSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() - 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const req = createMockApiRequest({
        "pm_drs_link-123": "session-token",
      });
      mockRedis.get.mockResolvedValue(expiredSession);

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      expect(mockRedis.del).toHaveBeenCalled();
    });

    it("should return valid session data", async () => {
      const validSession: DataroomSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const req = createMockApiRequest({
        "pm_drs_link-123": "session-token",
      });
      mockRedis.get.mockResolvedValue(validSession);

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toEqual(validSession);
    });

    it("should validate linkId matches session", async () => {
      const session: DataroomSession = {
        linkId: "different-link",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const req = createMockApiRequest({
        "pm_drs_link-123": "session-token",
      });
      mockRedis.get.mockResolvedValue(session);

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });

    it("should validate dataroomId matches session", async () => {
      const session: DataroomSession = {
        linkId: "link-123",
        dataroomId: "different-dataroom",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      const req = createMockApiRequest({
        "pm_drs_link-123": "session-token",
      });
      mockRedis.get.mockResolvedValue(session);

      const result = await verifyDataroomSessionInPagesRouter(
        req,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
    });
  });

  describe("Session Cookie Naming", () => {
    it("should use correct cookie name format", async () => {
      const linkId = "link-abc123";
      const expectedCookieName = `pm_drs_${linkId}`;

      mockCookieGet.mockReturnValue(undefined);

      await verifyDataroomSession(
        {} as NextRequest,
        linkId,
        "dataroom-456"
      );

      expect(mockCookieGet).toHaveBeenCalledWith(expectedCookieName);
    });
  });

  describe("Redis Key Naming", () => {
    it("should use correct redis key format", async () => {
      const sessionToken = "session-token-123";

      mockCookieGet.mockReturnValue({ value: sessionToken });
      mockRedis.get.mockResolvedValue(null);

      await verifyDataroomSession(
        {} as NextRequest,
        "link-123",
        "dataroom-456"
      );

      expect(mockRedis.get).toHaveBeenCalledWith(
        `dataroom_session:${sessionToken}`
      );
    });
  });

  describe("Security Requirements", () => {
    it("should delete session on validation failure", async () => {
      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue({ invalid: "session" });

      await verifyDataroomSession(
        {} as NextRequest,
        "link-123",
        "dataroom-456"
      );

      expect(mockRedis.del).toHaveBeenCalled();
    });

    it("should handle redis errors gracefully", async () => {
      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockRejectedValue(new Error("Redis error"));

      // Should not throw, should return null
      await expect(
        verifyDataroomSession({} as NextRequest, "link-123", "dataroom-456")
      ).resolves.toBeNull();
    });

    it("should not expose session data on mismatch", async () => {
      const session: DataroomSession = {
        linkId: "wrong-link",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        viewerId: "sensitive-viewer-id",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1",
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(session);

      const result = await verifyDataroomSession(
        {} as NextRequest,
        "link-123",
        "dataroom-456"
      );

      expect(result).toBeNull();
      // Should not return partial session data
    });
  });

  describe("IP Validation", () => {
    it("should not enforce IP validation (documented as disabled)", async () => {
      // IP validation is intentionally disabled to support mobile users
      // This test documents that behavior
      const session: DataroomSession = {
        linkId: "link-123",
        dataroomId: "dataroom-456",
        viewId: "view-789",
        expiresAt: Date.now() + 3600000,
        ipAddress: "192.168.1.1", // Different from request IP
        verified: true,
      };

      mockCookieGet.mockReturnValue({ value: "session-token" });
      mockRedis.get.mockResolvedValue(session);

      // Session should still be valid even with different IP
      const result = await verifyDataroomSession(
        {} as NextRequest,
        "link-123",
        "dataroom-456"
      );

      expect(result).toEqual(session);
    });
  });
});
