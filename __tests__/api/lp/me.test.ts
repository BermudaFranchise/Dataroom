// @ts-nocheck
/**
 * LP Me API Tests
 *
 * Tests for pages/api/lp/me.ts - Get current investor profile.
 *
 * These tests validate:
 * - Method validation (GET only)
 * - Session authentication
 * - Investor profile retrieval
 * - Capital calls aggregation
 * - Fund aggregates calculation
 * - KYC status retrieval
 * - Gate progress calculation
 * - Error handling
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions
const mockGetServerSession = jest.fn();
const mockUserFindUnique = jest.fn();
const mockFundFindMany = jest.fn();
const mockQueryRaw = jest.fn();

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
    fund: {
      findMany: (...args: any[]) => mockFundFindMany(...args),
    },
    $queryRaw: (...args: any[]) => mockQueryRaw(...args),
  },
}));

jest.mock("@/pages/api/auth/[...nextauth]", () => ({
  authOptions: {},
}));

import handler from "@/pages/api/lp/me";

describe("LP Me API", () => {
  const mockInvestorProfile = {
    id: "investor-123",
    entityName: "Test Entity LLC",
    ndaSigned: true,
    ndaSignedAt: new Date("2024-01-15"),
    accreditationStatus: "SELF_CERTIFIED",
    accreditationType: "INCOME",
    fundData: { someData: true },
    signedDocs: ["doc1", "doc2"],
    documents: [
      { id: "doc-1", name: "Document 1", createdAt: new Date() },
    ],
    investments: [
      {
        id: "inv-1",
        fundId: "fund-1",
        commitmentAmount: "100000",
        fundedAmount: "50000",
        fund: { id: "fund-1", name: "Test Fund", ndaGateEnabled: true },
      },
    ],
    capitalCalls: [
      {
        id: "ccr-1",
        amountDue: "10000",
        status: "PENDING",
        capitalCall: {
          callNumber: 1,
          dueDate: new Date("2024-06-01"),
          fund: { name: "Test Fund" },
        },
      },
    ],
    accreditationAcks: [
      {
        acknowledged: true,
        completedAt: new Date("2024-01-10"),
        accreditationType: "INCOME",
        method: "SELF_CERTIFIED",
      },
    ],
  };

  const mockUser = {
    id: "user-123",
    email: "investor@example.com",
    investorProfile: mockInvestorProfile,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetServerSession.mockResolvedValue({
      user: { email: "investor@example.com" },
    });
    mockUserFindUnique.mockResolvedValue(mockUser);
    mockFundFindMany.mockResolvedValue([
      {
        id: "fund-1",
        name: "Test Fund",
        targetRaise: "1000000",
        currentRaise: "500000",
        status: "ACTIVE",
        _count: { investments: 10 },
      },
    ]);
    mockQueryRaw.mockResolvedValue([
      { personaStatus: "APPROVED", personaVerifiedAt: new Date("2024-01-20") },
    ]);
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

    it("should accept valid session", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
    });
  });

  describe("Investor Profile", () => {
    it("should return 404 if no investor profile", async () => {
      mockUserFindUnique.mockResolvedValue({
        id: "user-123",
        email: "investor@example.com",
        investorProfile: null,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(404);
      expect(res._getJSONData()).toEqual({ message: "Investor profile not found" });
    });

    it("should return investor data", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor).toBeDefined();
      expect(data.investor.id).toBe("investor-123");
      expect(data.investor.entityName).toBe("Test Entity LLC");
    });

    it("should include NDA signed status", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.ndaSigned).toBe(true);
      expect(data.investor.ndaSignedAt).toBeDefined();
    });

    it("should include accreditation status", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.accreditationStatus).toBe("SELF_CERTIFIED");
      expect(data.investor.accreditationType).toBe("INCOME");
    });
  });

  describe("Capital Calls", () => {
    it("should return capital calls", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.capitalCalls).toHaveLength(1);
      expect(data.capitalCalls[0]).toMatchObject({
        id: "ccr-1",
        callNumber: 1,
        amount: "10000",
        status: "PENDING",
        fundName: "Test Fund",
      });
    });

    it("should include due date in ISO format", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.capitalCalls[0].dueDate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it("should handle empty capital calls", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          capitalCalls: [],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.capitalCalls).toEqual([]);
    });
  });

  describe("Fund Aggregates", () => {
    it("should return fund aggregates", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.fundAggregates).toHaveLength(1);
      expect(data.fundAggregates[0]).toMatchObject({
        id: "fund-1",
        name: "Test Fund",
        targetRaise: "1000000",
        currentRaise: "500000",
        status: "ACTIVE",
        investorCount: 10,
      });
    });

    it("should handle no investments", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          investments: [],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.fundAggregates).toEqual([]);
    });
  });

  describe("Investment Calculations", () => {
    it("should calculate total commitment", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          investments: [
            { commitmentAmount: "50000", fundedAmount: "25000", fundId: "f1", fund: {} },
            { commitmentAmount: "75000", fundedAmount: "50000", fundId: "f2", fund: {} },
          ],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.totalCommitment).toBe(125000);
    });

    it("should calculate total funded", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          investments: [
            { commitmentAmount: "50000", fundedAmount: "25000", fundId: "f1", fund: {} },
            { commitmentAmount: "75000", fundedAmount: "50000", fundId: "f2", fund: {} },
          ],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.totalFunded).toBe(75000);
    });

    it("should handle null amounts", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          investments: [
            { commitmentAmount: null, fundedAmount: null, fundId: "f1", fund: {} },
          ],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.totalCommitment).toBe(0);
      expect(data.investor.totalFunded).toBe(0);
    });
  });

  describe("KYC Status", () => {
    it("should return KYC status from raw query", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.kycStatus).toBe("APPROVED");
      expect(data.investor.kycVerifiedAt).toBeDefined();
    });

    it("should default to NOT_STARTED if no KYC data", async () => {
      mockQueryRaw.mockResolvedValue([]);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.investor.kycStatus).toBe("NOT_STARTED");
      expect(data.investor.kycVerifiedAt).toBeNull();
    });
  });

  describe("Gate Progress", () => {
    it("should calculate gate progress with both completed", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.gateProgress.ndaCompleted).toBe(true);
      expect(data.gateProgress.accreditationCompleted).toBe(true);
      expect(data.gateProgress.completionPercentage).toBe(100);
    });

    it("should calculate gate progress with only NDA", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          ndaSigned: true,
          accreditationAcks: [],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.gateProgress.ndaCompleted).toBe(true);
      expect(data.gateProgress.accreditationCompleted).toBe(false);
      expect(data.gateProgress.completionPercentage).toBe(50);
    });

    it("should calculate gate progress with nothing completed", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          ndaSigned: false,
          accreditationAcks: [],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.gateProgress.completionPercentage).toBe(0);
    });

    it("should check accreditation acknowledgment is complete", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          accreditationAcks: [
            {
              acknowledged: true,
              completedAt: null, // Not fully completed
              accreditationType: "INCOME",
              method: "SELF_CERTIFIED",
            },
          ],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.gateProgress.accreditationCompleted).toBe(false);
    });
  });

  describe("NDA Gate", () => {
    it("should return ndaGateEnabled based on fund settings", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.ndaGateEnabled).toBe(true);
    });

    it("should default ndaGateEnabled to true if no investments", async () => {
      mockUserFindUnique.mockResolvedValue({
        ...mockUser,
        investorProfile: {
          ...mockInvestorProfile,
          investments: [],
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      const data = res._getJSONData();
      expect(data.ndaGateEnabled).toBe(true);
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
      expect(res._getJSONData()).toEqual({ message: "Internal server error" });
    });

    it("should return 500 on query raw error", async () => {
      mockQueryRaw.mockRejectedValue(new Error("Query error"));

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
    });
  });
});
