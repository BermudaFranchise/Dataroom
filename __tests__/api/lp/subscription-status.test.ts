// @ts-nocheck
/**
 * LP Subscription Status API Tests
 *
 * Tests for pages/api/lp/subscription-status.ts - Get subscription status.
 *
 * These tests validate:
 * - Method validation (GET only)
 * - Session authentication
 * - Investor profile lookup
 * - Subscription status calculation
 * - Fund details retrieval
 * - Bank account status check
 * - canSubscribe eligibility logic
 * - Error handling
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions
const mockGetServerSession = jest.fn();
const mockUserFindUnique = jest.fn();
const mockSubscriptionFindFirst = jest.fn();
const mockBankLinkFindFirst = jest.fn();
const mockSignatureDocumentFindUnique = jest.fn();

// Track subscription findFirst calls
let subscriptionFindFirstCalls = 0;

// Mock dependencies
jest.mock("next-auth", () => ({
  getServerSession: (...args: any[]) => mockGetServerSession(...args),
}));

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    user: {
      findUnique: (...args: any[]) => mockUserFindUnique(...args),
    },
    subscription: {
      findFirst: (...args: any[]) => {
        subscriptionFindFirstCalls++;
        return mockSubscriptionFindFirst(...args);
      },
    },
    bankLink: {
      findFirst: (...args: any[]) => mockBankLinkFindFirst(...args),
    },
    signatureDocument: {
      findUnique: (...args: any[]) => mockSignatureDocumentFindUnique(...args),
    },
  },
}));

jest.mock("@/pages/api/auth/[...nextauth]", () => ({
  authOptions: {},
}));

import handler from "@/pages/api/lp/subscription-status";

describe("LP Subscription Status API", () => {
  const mockFund = {
    id: "fund-123",
    name: "Test Fund",
    flatModeEnabled: false,
    minimumInvestment: "25000",
    entityMode: "FUND",
    pricingTiers: [
      {
        id: "tier-1",
        tranche: 1,
        pricePerUnit: "1",
        unitsAvailable: 1000,
        unitsTotal: 1000,
        isActive: true,
      },
    ],
  };

  const mockInvestorProfile = {
    id: "investor-123",
    entityName: "Test Entity LLC",
    ndaSigned: true,
    accreditationStatus: "SELF_CERTIFIED",
    fund: mockFund,
  };

  const mockUser = {
    id: "user-123",
    email: "investor@example.com",
    investorProfile: mockInvestorProfile,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    subscriptionFindFirstCalls = 0;
    mockGetServerSession.mockResolvedValue({
      user: { email: "investor@example.com" },
    });
    mockUserFindUnique.mockResolvedValue(mockUser);
    mockSubscriptionFindFirst.mockResolvedValue(null);
    mockBankLinkFindFirst.mockResolvedValue(null);
    mockSignatureDocumentFindUnique.mockResolvedValue(null);
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
      });

      await handler(req, res);

      expect(res._getStatusCode()).not.toBe(405);
    });
  });

  describe("Authentication", () => {
    it("should reject unauthenticated requests", async () => {
      mockGetServerSession.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
      expect(res._getJSONData()).toEqual({ message: "Unauthorized" });
    });

    it("should reject session without email", async () => {
      mockGetServerSession.mockResolvedValue({ user: {} });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
    });
  });

  describe("No Investor Profile", () => {
    it("should return default values if no investor profile", async () => {
      mockUserFindUnique.mockResolvedValue({
        id: "user-123",
        email: "investor@example.com",
        investorProfile: null,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const data = res._getJSONData();
      expect(data).toEqual({
        hasSubscription: false,
        canSubscribe: false,
        fund: null,
        pendingSubscription: null,
      });
    });
  });

  describe("canSubscribe Eligibility", () => {
    it("should return canSubscribe=true when eligible", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(true);
    });

    it("should return canSubscribe=false if NDA not signed", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          ndaSigned: false,
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });

    it("should return canSubscribe=false if not accredited", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          accreditationStatus: "PENDING",
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });

    it("should allow KYC_VERIFIED accreditation", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          accreditationStatus: "KYC_VERIFIED",
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(true);
    });

    it("should return canSubscribe=false if no fund", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          fund: null,
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      // When fund is null, canSubscribe evaluates to false (falsy null && conditions)
      expect(data.canSubscribe).toBeFalsy();
    });

    it("should return canSubscribe=false if fund entityMode is not FUND", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          fund: { ...mockFund, entityMode: "SYNDICATE" },
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });

    it("should return canSubscribe=false if pending subscription exists", async () => {
      mockSubscriptionFindFirst
        .mockResolvedValueOnce({
          id: "sub-1",
          status: "PENDING",
          amount: "50000",
          units: 50,
          signatureDocumentId: "doc-1",
          createdAt: new Date("2024-01-15"),
          fund: { name: "Test Fund" },
        }) // pending
        .mockResolvedValueOnce(null) // signed
        .mockResolvedValueOnce(null); // processing

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });

    it("should return canSubscribe=false if signed subscription exists", async () => {
      mockSubscriptionFindFirst
        .mockResolvedValueOnce(null) // pending
        .mockResolvedValueOnce({
          id: "sub-2",
          status: "SIGNED",
          amount: "50000",
          units: 50,
          createdAt: new Date("2024-01-15"),
          fund: { name: "Test Fund" },
        }) // signed
        .mockResolvedValueOnce(null); // processing

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });

    it("should return canSubscribe=false if processing subscription exists", async () => {
      mockSubscriptionFindFirst
        .mockResolvedValueOnce(null) // pending
        .mockResolvedValueOnce(null) // signed
        .mockResolvedValueOnce({
          id: "sub-3",
          status: "PAYMENT_PROCESSING",
          amount: "50000",
          units: 50,
          createdAt: new Date("2024-01-15"),
          fund: { name: "Test Fund" },
        }); // processing

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.canSubscribe).toBe(false);
    });
  });

  describe("Subscription Status", () => {
    it("should return hasSubscription=false when no subscriptions", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.hasSubscription).toBe(false);
    });

    it("should return hasSubscription=true with pending subscription", async () => {
      mockSubscriptionFindFirst
        .mockResolvedValueOnce({
          id: "sub-1",
          status: "PENDING",
          amount: "50000",
          units: 50,
          signatureDocumentId: "doc-1",
          createdAt: new Date("2024-01-15"),
          fund: { name: "Test Fund" },
        })
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.hasSubscription).toBe(true);
      expect(data.pendingSubscription).toMatchObject({
        id: "sub-1",
        fundName: "Test Fund",
        amount: "50000",
        units: 50,
        status: "PENDING",
      });
    });

    it("should include signing token for pending subscription", async () => {
      mockSubscriptionFindFirst
        .mockResolvedValueOnce({
          id: "sub-1",
          status: "PENDING",
          amount: "50000",
          units: 50,
          signatureDocumentId: "doc-1",
          createdAt: new Date("2024-01-15"),
          fund: { name: "Test Fund" },
        })
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      mockSignatureDocumentFindUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [
          { status: "PENDING", signingToken: "sign-token-123" },
        ],
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.pendingSubscription.signingToken).toBe("sign-token-123");
    });
  });

  describe("Fund Details", () => {
    it("should return fund details", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.fund).toMatchObject({
        id: "fund-123",
        name: "Test Fund",
        flatModeEnabled: false,
        minimumInvestment: "25000",
        entityMode: "FUND",
      });
    });

    it("should return pricing tiers", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.fund.pricingTiers).toHaveLength(1);
      expect(data.fund.pricingTiers[0]).toMatchObject({
        id: "tier-1",
        tranche: 1,
        pricePerUnit: "1",
        unitsAvailable: 1000,
        unitsTotal: 1000,
        isActive: true,
      });
    });

    it("should return null fund if not linked", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          fund: null,
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.fund).toBeNull();
    });
  });

  describe("Bank Account Status", () => {
    it("should return hasBankAccount=true when linked", async () => {
      mockBankLinkFindFirst.mockResolvedValue({ id: "bank-1", status: "ACTIVE" });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.hasBankAccount).toBe(true);
    });

    it("should return hasBankAccount=false when not linked", async () => {
      mockBankLinkFindFirst.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.hasBankAccount).toBe(false);
    });

    it("should only check ACTIVE bank links", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(mockBankLinkFindFirst).toHaveBeenCalledWith({
        where: {
          investorId: "investor-123",
          status: "ACTIVE",
        },
      });
    });
  });

  describe("Entity Name", () => {
    it("should return entity name", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.entityName).toBe("Test Entity LLC");
    });
  });

  describe("Error Handling", () => {
    it("should return 500 on database error", async () => {
      mockUserFindUnique.mockRejectedValue(new Error("Database error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData()).toEqual({
        message: "Failed to fetch subscription status",
      });
    });

    it("should return 500 on subscription query error", async () => {
      mockSubscriptionFindFirst.mockRejectedValue(new Error("Query error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
    });
  });
});
