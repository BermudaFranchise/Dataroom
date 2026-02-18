// @ts-nocheck
/**
 * LP Process Payment API Tests
 *
 * Tests for pages/api/lp/subscription/process-payment.ts - Payment processing.
 *
 * These tests validate:
 * - Authentication requirements
 * - Subscription ownership validation
 * - Bank account requirement
 * - Signature requirement before payment
 * - Duplicate payment prevention
 * - Manual processing fallback when Plaid not configured
 * - ACH transfer authorization and creation
 * - Payment failure handling
 * - Audit logging
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Mock functions - defined at module level for hoisting
const mockGetServerSession = jest.fn();
const mockUserFindUnique = jest.fn();
const mockSubscriptionFindFirst = jest.fn();
const mockSubscriptionUpdate = jest.fn();
const mockSignatureDocumentFindUnique = jest.fn();
const mockTransactionFindMany = jest.fn();
const mockTransactionCreate = jest.fn();

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
      findFirst: (...args: any[]) => mockSubscriptionFindFirst(...args),
      update: (...args: any[]) => mockSubscriptionUpdate(...args),
    },
    signatureDocument: {
      findUnique: (...args: any[]) => mockSignatureDocumentFindUnique(...args),
    },
    transaction: {
      findMany: (...args: any[]) => mockTransactionFindMany(...args),
      create: (...args: any[]) => mockTransactionCreate(...args),
    },
  },
}));

// Convenience aliases
const mockPrismaUser = { findUnique: mockUserFindUnique };
const mockPrismaSubscription = {
  findFirst: mockSubscriptionFindFirst,
  update: mockSubscriptionUpdate,
};
const mockPrismaSignatureDocument = { findUnique: mockSignatureDocumentFindUnique };
const mockPrismaTransaction = {
  findMany: mockTransactionFindMany,
  create: mockTransactionCreate,
};

jest.mock("../../../../pages/api/auth/[...nextauth]", () => ({
  authOptions: {},
}));

// Mock Plaid functions
const mockIsPlaidConfigured = jest.fn();
const mockDecryptToken = jest.fn();
const mockCreateTransferAuthorization = jest.fn();
const mockCreateTransfer = jest.fn();

jest.mock("@/lib/plaid", () => ({
  isPlaidConfigured: () => mockIsPlaidConfigured(),
  decryptToken: (token: string) => mockDecryptToken(token),
  createTransferAuthorization: (...args: any[]) =>
    mockCreateTransferAuthorization(...args),
  createTransfer: (...args: any[]) => mockCreateTransfer(...args),
}));

jest.mock("@/lib/audit/audit-logger", () => ({
  logPaymentEvent: jest.fn().mockResolvedValue("audit-log-id"),
}));

import handler from "@/pages/api/lp/subscription/process-payment";
import { logPaymentEvent } from "@/lib/audit/audit-logger";

describe("LP Process Payment API", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("HTTP Method Validation", () => {
    it("should reject non-POST requests", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(405);
      expect(res._getJSONData().message).toBe("Method not allowed");
    });
  });

  describe("Authentication", () => {
    it("should reject unauthenticated requests", async () => {
      mockGetServerSession.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(401);
      expect(res._getJSONData().message).toBe("Unauthorized");
    });
  });

  describe("Input Validation", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });
    });

    it("should require subscriptionId", async () => {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: {},
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData().message).toBe("Subscription ID is required");
    });
  });

  describe("Investor Profile Validation", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });
    });

    it("should reject user without investor profile", async () => {
      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        investorProfile: null,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(403);
      expect(res._getJSONData().message).toBe("Investor profile not found");
    });
  });

  describe("Bank Account Validation", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });
    });

    it("should reject when no bank account linked", async () => {
      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        investorProfile: {
          id: "investor-1",
          bankLinks: [], // No bank accounts
        },
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData().code).toBe("NO_BANK_ACCOUNT");
      expect(res._getJSONData().message).toContain("No bank account connected");
    });
  });

  describe("Subscription Validation", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });

      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John Investor",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });
    });

    it("should reject when subscription not found", async () => {
      mockPrismaSubscription.findFirst.mockResolvedValue(null);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "nonexistent-sub" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(404);
      expect(res._getJSONData().message).toBe("Subscription not found");
    });

    it("should reject subscription with invalid status", async () => {
      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "CANCELLED",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        fund: { name: "Test Fund", teamId: "team-1" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "SIGNED" }],
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData().message).toContain("cannot be processed");
    });
  });

  describe("Signature Validation", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });

      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John Investor",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });
    });

    it("should reject payment when document not signed", async () => {
      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "PENDING",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        fund: { name: "Test Fund" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "PENDING" }], // Not signed
      });

      mockPrismaTransaction.findMany.mockResolvedValue([]);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData().code).toBe("NOT_SIGNED");
    });
  });

  describe("Duplicate Payment Prevention", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });

      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John Investor",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });
    });

    it("should reject duplicate payment for same subscription", async () => {
      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "SIGNED",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        createdAt: new Date("2024-01-01"),
        fund: { name: "Test Fund", teamId: "team-1" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "SIGNED" }],
      });

      // Existing transaction with same subscriptionId
      mockPrismaTransaction.findMany.mockResolvedValue([
        {
          id: "txn-existing",
          amount: 100000,
          fundId: "fund-1",
          status: "PENDING",
          createdAt: new Date("2024-01-02"),
          metadata: { subscriptionId: "sub-1" },
        },
      ]);

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(res._getJSONData().message).toContain("payment is already pending");
      expect(res._getJSONData().transactionId).toBe("txn-existing");
    });
  });

  describe("Manual Processing (Plaid Not Configured)", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });

      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John Investor",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });

      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "SIGNED",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        fund: { name: "Test Fund", teamId: "team-1" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "SIGNED" }],
      });

      mockPrismaTransaction.findMany.mockResolvedValue([]);
      mockIsPlaidConfigured.mockReturnValue(false);
    });

    it("should create pending transaction for manual processing", async () => {
      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-manual",
        status: "PENDING",
        amount: 100000,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const data = res._getJSONData();
      expect(data.success).toBe(true);
      expect(data.message).toContain("Manual processing required");
      expect(data.transaction.status).toBe("PENDING");
    });

    it("should log PAYMENT_RECORDED event for manual processing", async () => {
      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-manual",
        status: "PENDING",
        amount: 100000,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(logPaymentEvent).toHaveBeenCalledWith(
        req,
        expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_RECORDED",
        })
      );
    });
  });

  describe("ACH Transfer Processing (Plaid Configured)", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });

      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John Investor",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });

      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "SIGNED",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        fund: { name: "Test Fund", teamId: "team-1" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "SIGNED" }],
      });

      mockPrismaTransaction.findMany.mockResolvedValue([]);
      mockIsPlaidConfigured.mockReturnValue(true);
      mockDecryptToken.mockReturnValue("decrypted-access-token");
    });

    it("should process approved transfer successfully", async () => {
      mockCreateTransferAuthorization.mockResolvedValue({
        authorizationId: "auth-123",
        decision: "approved",
        decisionRationale: null,
      });

      mockCreateTransfer.mockResolvedValue({
        transferId: "transfer-123",
        status: "pending",
        created: "2024-01-15T10:00:00Z",
      });

      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-123",
        status: "PROCESSING",
        amount: 100000,
        plaidTransferId: "transfer-123",
      });

      mockPrismaSubscription.update.mockResolvedValue({
        id: "sub-1",
        status: "PAYMENT_PROCESSING",
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(200);
      const data = res._getJSONData();
      expect(data.success).toBe(true);
      expect(data.transaction.plaidTransferId).toBe("transfer-123");
      expect(data.message).toContain("Payment initiated successfully");
    });

    it("should handle declined authorization", async () => {
      mockCreateTransferAuthorization.mockResolvedValue({
        authorizationId: "auth-456",
        decision: "declined",
        decisionRationale: {
          code: "NSF",
          description: "Insufficient funds in account",
        },
      });

      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-failed",
        status: "FAILED",
        amount: 100000,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      const data = res._getJSONData();
      expect(data.success).toBe(false);
      expect(data.message).toBe("Payment authorization declined");
      expect(data.reason).toBe("Insufficient funds in account");
    });

    it("should log PAYMENT_INITIATED event on success", async () => {
      mockCreateTransferAuthorization.mockResolvedValue({
        authorizationId: "auth-123",
        decision: "approved",
      });

      mockCreateTransfer.mockResolvedValue({
        transferId: "transfer-123",
        status: "pending",
      });

      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-123",
        status: "PROCESSING",
        amount: 100000,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(logPaymentEvent).toHaveBeenCalledWith(
        req,
        expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_INITIATED",
          plaidTransferId: "transfer-123",
        })
      );
    });

    it("should update subscription status to PAYMENT_PROCESSING", async () => {
      mockCreateTransferAuthorization.mockResolvedValue({
        authorizationId: "auth-123",
        decision: "approved",
      });

      mockCreateTransfer.mockResolvedValue({
        transferId: "transfer-123",
        status: "pending",
      });

      mockPrismaTransaction.create.mockResolvedValue({
        id: "txn-123",
        status: "PROCESSING",
        amount: 100000,
      });

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(mockPrismaSubscription.update).toHaveBeenCalledWith({
        where: { id: "sub-1" },
        data: { status: "PAYMENT_PROCESSING" },
      });
    });
  });

  describe("Error Handling", () => {
    beforeEach(() => {
      mockGetServerSession.mockResolvedValue({
        user: { email: "investor@example.com" },
      });
    });

    it("should handle database errors gracefully", async () => {
      mockPrismaUser.findUnique.mockRejectedValue(
        new Error("Database connection failed")
      );

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData().message).toBe("Database connection failed");
    });

    it("should handle Plaid API errors", async () => {
      mockPrismaUser.findUnique.mockResolvedValue({
        id: "user-1",
        email: "investor@example.com",
        name: "John",
        investorProfile: {
          id: "investor-1",
          entityName: "John LLC",
          bankLinks: [
            {
              id: "bank-1",
              status: "ACTIVE",
              plaidAccessToken: "encrypted-token",
              plaidAccountId: "acc-123",
            },
          ],
        },
      });

      mockPrismaSubscription.findFirst.mockResolvedValue({
        id: "sub-1",
        status: "SIGNED",
        amount: 100000,
        fundId: "fund-1",
        signatureDocumentId: "doc-1",
        fund: { name: "Test Fund", teamId: "team-1" },
      });

      mockPrismaSignatureDocument.findUnique.mockResolvedValue({
        id: "doc-1",
        recipients: [{ status: "SIGNED" }],
      });

      mockPrismaTransaction.findMany.mockResolvedValue([]);
      mockIsPlaidConfigured.mockReturnValue(true);
      mockDecryptToken.mockReturnValue("decrypted-token");
      mockCreateTransferAuthorization.mockRejectedValue(
        new Error("Plaid API error")
      );

      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "POST",
        body: { subscriptionId: "sub-1" },
      });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(500);
      expect(res._getJSONData().message).toBe("Plaid API error");
    });
  });
});
