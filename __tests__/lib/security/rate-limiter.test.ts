// @ts-nocheck
/**
 * Rate Limiter Tests
 *
 * Tests for lib/security/rate-limiter.ts - Rate limiting middleware for API protection.
 *
 * These tests validate:
 * - Rate limit enforcement at various thresholds
 * - IP extraction from different header formats
 * - Rate limit window expiration and reset
 * - Response header setting (X-RateLimit-*)
 * - Rate limit violation logging
 * - Different rate limiter configurations (signature, auth, api, strict)
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock prisma before importing rate limiter
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    signatureAuditLog: {
      create: jest.fn().mockResolvedValue({ id: "log-1" }),
    },
  },
}));

import {
  createRateLimiter,
  signatureRateLimiter,
  authRateLimiter,
  apiRateLimiter,
  strictRateLimiter,
  withRateLimit,
} from "@/lib/security/rate-limiter";
import prisma from "@/lib/prisma";

describe("Rate Limiter", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear rate limit store between tests by creating fresh limiters
  });

  describe("createRateLimiter", () => {
    it("should allow requests under the limit", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-allow",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-allow",
        headers: {
          "x-forwarded-for": "192.168.1.1",
        },
      });

      const allowed = await limiter(req, res);

      expect(allowed).toBe(true);
      expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
      expect(res.getHeader("X-RateLimit-Remaining")).toBe(4);
    });

    it("should decrement remaining count on each request", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-decrement",
      });

      // First request
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-decrement",
        headers: { "x-forwarded-for": "192.168.1.10" },
      });
      await limiter(req1, res1);
      expect(res1.getHeader("X-RateLimit-Remaining")).toBe(4);

      // Second request
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-decrement",
        headers: { "x-forwarded-for": "192.168.1.10" },
      });
      await limiter(req2, res2);
      expect(res2.getHeader("X-RateLimit-Remaining")).toBe(3);

      // Third request
      const { req: req3, res: res3 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-decrement",
        headers: { "x-forwarded-for": "192.168.1.10" },
      });
      await limiter(req3, res3);
      expect(res3.getHeader("X-RateLimit-Remaining")).toBe(2);
    });

    it("should block requests exceeding the limit", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 2,
        keyPrefix: "test-block",
      });

      const ip = "192.168.1.20";
      const url = "/api/test-block";

      // Request 1 - allowed
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req1, res1)).toBe(true);

      // Request 2 - allowed
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req2, res2)).toBe(true);

      // Request 3 - should be blocked
      const { req: req3, res: res3 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req3, res3)).toBe(false);
      expect(res3.statusCode).toBe(429);
    });

    it("should return 429 status with error message when blocked", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 1,
        keyPrefix: "test-429",
      });

      const ip = "192.168.1.30";

      // First request - allowed
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-429",
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req1, res1);

      // Second request - blocked
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-429",
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req2, res2);

      expect(res2.statusCode).toBe(429);
      const body = res2._getJSONData();
      expect(body.error).toBe("Too many requests");
      expect(body.message).toContain("Rate limit exceeded");
      expect(body.retryAfter).toBeDefined();
    });

    it("should call onLimitReached callback when limit exceeded", async () => {
      const onLimitReached = jest.fn();
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 1,
        keyPrefix: "test-callback",
        onLimitReached,
      });

      const ip = "192.168.1.40";
      const url = "/api/test-callback";

      // First request
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req1, res1);

      // Second request - triggers callback
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req2, res2);

      expect(onLimitReached).toHaveBeenCalledWith(ip, url);
    });

    it("should log rate limit violations to database", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 1,
        keyPrefix: "test-log",
      });

      const ip = "192.168.1.50";
      const url = "/api/test-log";

      // First request
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req1, res1);

      // Second request - should log
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req2, res2);

      expect(prisma.signatureAuditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          documentId: "SECURITY_LOG",
          event: "RATE_LIMIT_EXCEEDED",
          ipAddress: ip,
          metadata: expect.objectContaining({
            endpoint: url,
            severity: "WARNING",
          }),
        }),
      });
    });

    it("should set X-RateLimit-Reset header", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-reset",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-reset",
        headers: { "x-forwarded-for": "192.168.1.60" },
      });

      await limiter(req, res);

      const reset = res.getHeader("X-RateLimit-Reset");
      expect(typeof reset).toBe("number");
      expect(reset).toBeGreaterThan(0);
      expect(reset).toBeLessThanOrEqual(60); // Should be less than windowMs in seconds
    });
  });

  describe("IP Extraction", () => {
    it("should extract IP from x-forwarded-for header (string)", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-ip-xff",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-ip-xff",
        headers: {
          "x-forwarded-for": "10.0.0.1, 10.0.0.2, 10.0.0.3",
        },
      });

      await limiter(req, res);

      // The first IP in the chain should be used
      expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
    });

    it("should extract IP from x-forwarded-for header (array)", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-ip-xff-array",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-ip-xff-array",
        headers: {
          "x-forwarded-for": ["10.0.0.10", "10.0.0.11"],
        },
      });

      await limiter(req, res);

      expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
    });

    it("should fall back to socket remoteAddress when no forwarded header", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-ip-socket",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-ip-socket",
      });

      // node-mocks-http doesn't set socket by default, so IP will be "unknown"
      await limiter(req, res);

      expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
    });

    it("should trim whitespace from IP addresses", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-ip-trim",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-ip-trim",
        headers: {
          "x-forwarded-for": "  10.0.0.20  , 10.0.0.21",
        },
      });

      await limiter(req, res);

      expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
    });
  });

  describe("Pre-configured Rate Limiters", () => {
    describe("signatureRateLimiter", () => {
      it("should be configured with 5 max requests in 15 minutes", async () => {
        const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
          method: "POST",
          url: "/api/sign/token123",
          headers: { "x-forwarded-for": "10.1.0.1" },
        });

        await signatureRateLimiter(req, res);

        expect(res.getHeader("X-RateLimit-Limit")).toBe(5);
      });
    });

    describe("authRateLimiter", () => {
      it("should be configured with 10 max requests in 1 hour", async () => {
        const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
          method: "POST",
          url: "/api/auth/login",
          headers: { "x-forwarded-for": "10.2.0.1" },
        });

        await authRateLimiter(req, res);

        expect(res.getHeader("X-RateLimit-Limit")).toBe(10);
      });
    });

    describe("apiRateLimiter", () => {
      it("should be configured with 100 max requests in 1 minute", async () => {
        const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
          method: "GET",
          url: "/api/data",
          headers: { "x-forwarded-for": "10.3.0.1" },
        });

        await apiRateLimiter(req, res);

        expect(res.getHeader("X-RateLimit-Limit")).toBe(100);
      });
    });

    describe("strictRateLimiter", () => {
      it("should be configured with 3 max requests in 1 hour", async () => {
        const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
          method: "POST",
          url: "/api/sensitive",
          headers: { "x-forwarded-for": "10.4.0.1" },
        });

        await strictRateLimiter(req, res);

        expect(res.getHeader("X-RateLimit-Limit")).toBe(3);
      });
    });
  });

  describe("withRateLimit Wrapper", () => {
    it("should call handler when under rate limit", async () => {
      const handler = jest.fn().mockResolvedValue(undefined);
      const wrappedHandler = withRateLimit(handler, createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-wrapper-allow",
      }));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/test-wrapper-allow",
        headers: { "x-forwarded-for": "10.5.0.1" },
      });

      await wrappedHandler(req, res);

      expect(handler).toHaveBeenCalledWith(req, res);
    });

    it("should not call handler when rate limited", async () => {
      const handler = jest.fn().mockResolvedValue(undefined);
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 1,
        keyPrefix: "test-wrapper-block",
      });
      const wrappedHandler = withRateLimit(handler, limiter);

      const ip = "10.5.0.10";
      const url = "/api/test-wrapper-block";

      // First request - uses up the limit
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await wrappedHandler(req1, res1);
      expect(handler).toHaveBeenCalledTimes(1);

      // Second request - should be blocked
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await wrappedHandler(req2, res2);

      expect(handler).toHaveBeenCalledTimes(1); // Still only called once
      expect(res2.statusCode).toBe(429);
    });

    it("should use apiRateLimiter by default", async () => {
      const handler = jest.fn().mockResolvedValue(undefined);
      const wrappedHandler = withRateLimit(handler);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/default-limiter",
        headers: { "x-forwarded-for": "10.5.0.20" },
      });

      await wrappedHandler(req, res);

      // apiRateLimiter has 100 max requests
      expect(res.getHeader("X-RateLimit-Limit")).toBe(100);
    });
  });

  describe("Rate Limit Key Generation", () => {
    it("should create unique keys per IP and endpoint", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 2,
        keyPrefix: "test-key",
      });

      // Request from IP A to endpoint 1
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/endpoint1",
        headers: { "x-forwarded-for": "10.6.0.1" },
      });
      await limiter(req1, res1);
      await limiter(req1, res1);

      // Request from IP A to endpoint 2 - should have separate limit
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url: "/api/endpoint2",
        headers: { "x-forwarded-for": "10.6.0.1" },
      });
      await limiter(req2, res2);

      expect(res2.getHeader("X-RateLimit-Remaining")).toBe(1); // Fresh count for new endpoint
    });

    it("should track different IPs separately", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 2,
        keyPrefix: "test-key-ip",
      });

      const url = "/api/same-endpoint";

      // Two requests from IP A
      const { req: reqA1, res: resA1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": "10.7.0.1" },
      });
      await limiter(reqA1, resA1);
      await limiter(reqA1, resA1);

      // Request from IP B - should have full quota
      const { req: reqB, res: resB } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": "10.7.0.2" },
      });
      await limiter(reqB, resB);

      expect(resB.getHeader("X-RateLimit-Remaining")).toBe(1); // Fresh count for IP B
    });
  });

  describe("Edge Cases", () => {
    it("should handle missing URL gracefully", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyPrefix: "test-no-url",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        headers: { "x-forwarded-for": "10.8.0.1" },
      });
      // Manually remove URL
      delete (req as any).url;

      const allowed = await limiter(req, res);

      expect(allowed).toBe(true);
    });

    it("should handle exactly at maxRequests boundary", async () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 3,
        keyPrefix: "test-boundary",
      });

      const ip = "10.8.0.10";
      const url = "/api/test-boundary";

      // Request 1 - count=1, remaining=2
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req1, res1)).toBe(true);
      expect(res1.getHeader("X-RateLimit-Remaining")).toBe(2);

      // Request 2 - count=2, remaining=1
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req2, res2)).toBe(true);
      expect(res2.getHeader("X-RateLimit-Remaining")).toBe(1);

      // Request 3 - count=3, remaining=0 (at limit, still allowed)
      const { req: req3, res: res3 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req3, res3)).toBe(true);
      expect(res3.getHeader("X-RateLimit-Remaining")).toBe(0);

      // Request 4 - count=4, should be blocked
      const { req: req4, res: res4 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      expect(await limiter(req4, res4)).toBe(false);
    });

    it("should handle database errors gracefully when logging violations", async () => {
      (prisma.signatureAuditLog.create as jest.Mock).mockRejectedValueOnce(
        new Error("Database error")
      );

      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 1,
        keyPrefix: "test-db-error",
      });

      const ip = "10.8.0.20";
      const url = "/api/test-db-error";

      // First request
      const { req: req1, res: res1 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      await limiter(req1, res1);

      // Second request - should still block even if logging fails
      const { req: req2, res: res2 } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        url,
        headers: { "x-forwarded-for": ip },
      });
      const allowed = await limiter(req2, res2);

      expect(allowed).toBe(false);
      expect(res2.statusCode).toBe(429);
    });
  });
});
