// @ts-nocheck
/**
 * LP Bank Status API Tests
 *
 * Tests for pages/api/lp/bank/status.ts - Bank account status check.
 *
 * These tests validate:
 * - Method validation (GET only)
 * - Cookie-based authentication
 * - Investor lookup by session
 * - Bank link retrieval
 * - Plaid configuration check
 * - Error handling
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions
const mockIsPlaidConfigured = jest.fn();
const mockInvestorFindFirst = jest.fn();

// Mock dependencies
jest.mock("@/lib/plaid", () => ({
  isPlaidConfigured: (...args: any[]) => mockIsPlaidConfigured(...args),
}));

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    investor: {
      findFirst: (...args: any[]) => mockInvestorFindFirst(...args),
    },
  },
}));

import handler from "@/pages/api/lp/bank/status";

describe("LP Bank Status API", () => {
  const mockBankLink = {
    id: "bank-123",
    institutionName: "Chase",
    accountName: "Checking",
    accountMask: "1234",
    accountType: "checking",
    status: "ACTIVE",
    transferEnabled: true,
    lastSyncAt: new Date("2024-01-20"),
    createdAt: new Date("2024-01-01"),
  };

  const mockInvestor = {
    id: "investor-123",
    bankLinks: [mockBankLink],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockIsPlaidConfigured.mockReturnValue(true);
    mockInvestorFindFirst.mockResolvedValue(mockInvestor);
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
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).not.toBe(405);
    });
  });

  describe("Authentication", () => {
    it("should reject missing session cookie", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: {},
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
      expect(res._getJSONData()).toEqual({ message: "Not authenticated" });
    });

    it("should use lp-session cookie for auth", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "my-session-token" },
      });

      await handler(req, res);

      expect(mockInvestorFindFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            user: {
              sessions: {
                some: {
                  sessionToken: "my-session-token",
                },
              },
            },
          },
        })
      );
    });

    it("should reject if investor not found", async () => {
      mockInvestorFindFirst.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "invalid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
      expect(res._getJSONData()).toEqual({ message: "Investor not found" });
    });
  });

  describe("Bank Link Status", () => {
    it("should return bank link details when linked", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const data = res._getJSONData();
      expect(data.hasBankLink).toBe(true);
      expect(data.bankLink).toMatchObject({
        id: "bank-123",
        institutionName: "Chase",
        accountName: "Checking",
        accountMask: "1234",
        accountType: "checking",
        status: "ACTIVE",
        transferEnabled: true,
      });
    });

    it("should return null bank link when not linked", async () => {
      mockInvestorFindFirst.mockResolvedValue({
        id: "investor-123",
        bankLinks: [],
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const data = res._getJSONData();
      expect(data.hasBankLink).toBe(false);
      expect(data.bankLink).toBeNull();
    });

    it("should only return ACTIVE bank links", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(mockInvestorFindFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          include: {
            bankLinks: expect.objectContaining({
              where: { status: "ACTIVE" },
            }),
          },
        })
      );
    });

    it("should select specific bank link fields", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(mockInvestorFindFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          include: {
            bankLinks: expect.objectContaining({
              select: {
                id: true,
                institutionName: true,
                accountName: true,
                accountMask: true,
                accountType: true,
                status: true,
                transferEnabled: true,
                lastSyncAt: true,
                createdAt: true,
              },
            }),
          },
        })
      );
    });
  });

  describe("Plaid Configuration", () => {
    it("should return configured status", async () => {
      mockIsPlaidConfigured.mockReturnValue(true);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.configured).toBe(true);
    });

    it("should return not configured when Plaid disabled", async () => {
      mockIsPlaidConfigured.mockReturnValue(false);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.configured).toBe(false);
    });
  });

  describe("Error Handling", () => {
    it("should return 500 on database error", async () => {
      mockInvestorFindFirst.mockRejectedValue(new Error("Database error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        cookies: { "lp-session": "valid-token" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData()).toEqual({ message: "Failed to fetch bank status" });
    });
  });
});
