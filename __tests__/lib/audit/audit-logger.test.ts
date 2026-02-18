// @ts-nocheck
/**
 * Audit Logger Tests
 *
 * Tests for lib/audit/audit-logger.ts - Compliance event logging.
 *
 * These tests validate:
 * - Event type coverage for all audit events
 * - IP extraction from request headers
 * - User agent extraction
 * - Immutable chain selection logic
 * - Specialized event loggers (view, sign, subscription, payment, etc.)
 * - Error handling when database operations fail
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest } from "next";

// Mock prisma
const mockAuditLogCreate = jest.fn();

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    auditLog: {
      create: (...args: any[]) => mockAuditLogCreate(...args),
    },
  },
}));

// Mock immutable audit log
const mockCreateImmutableAuditEntry = jest.fn();

jest.mock("@/lib/audit/immutable-audit-log", () => ({
  createImmutableAuditEntry: (...args: any[]) => mockCreateImmutableAuditEntry(...args),
}));

import {
  logAuditEvent,
  logAuditEventFromRequest,
  logViewEvent,
  logSignEvent,
  logSubscriptionEvent,
  logPaymentEvent,
  logAccreditationEvent,
  logCertificateEvent,
  AuditEventType,
  ResourceType,
  AuditLogData,
} from "@/lib/audit/audit-logger";

describe("Audit Logger", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAuditLogCreate.mockReset();
    mockCreateImmutableAuditEntry.mockReset();
  });

  describe("logAuditEvent", () => {
    it("should create audit log entry without immutable chain when no teamId", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const result = await logAuditEvent({
        eventType: "USER_LOGIN",
        userId: "user-1",
      });

      expect(result).toBe("log-1");
      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: {
          eventType: "USER_LOGIN",
          userId: "user-1",
          teamId: null,
          resourceType: null,
          resourceId: null,
          metadata: undefined,
          ipAddress: null,
          userAgent: null,
        },
      });
      expect(mockCreateImmutableAuditEntry).not.toHaveBeenCalled();
    });

    it("should use immutable chain when teamId is provided", async () => {
      mockCreateImmutableAuditEntry.mockResolvedValue({ id: "immutable-log-1" });

      const result = await logAuditEvent({
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
      });

      expect(result).toBe("immutable-log-1");
      expect(mockCreateImmutableAuditEntry).toHaveBeenCalledWith({
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: undefined,
        ipAddress: undefined,
        userAgent: undefined,
      });
      expect(mockAuditLogCreate).not.toHaveBeenCalled();
    });

    it("should allow forcing non-immutable chain with option", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "regular-log-1" });

      const result = await logAuditEvent(
        {
          eventType: "ADMIN_ACTION",
          userId: "admin-1",
          teamId: "team-1",
        },
        { useImmutableChain: false }
      );

      expect(result).toBe("regular-log-1");
      expect(mockAuditLogCreate).toHaveBeenCalled();
      expect(mockCreateImmutableAuditEntry).not.toHaveBeenCalled();
    });

    it("should allow forcing immutable chain without teamId", async () => {
      // This won't actually use immutable chain because teamId check comes first
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const result = await logAuditEvent(
        {
          eventType: "ADMIN_ACTION",
          userId: "admin-1",
        },
        { useImmutableChain: true }
      );

      // Without teamId, it falls back to regular even with flag
      expect(mockAuditLogCreate).toHaveBeenCalled();
    });

    it("should include all optional fields when provided", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "full-log" });

      await logAuditEvent({
        eventType: "DOCUMENT_DOWNLOADED",
        userId: "user-1",
        teamId: null,
        resourceType: "Document",
        resourceId: "doc-123",
        metadata: { downloadFormat: "pdf" },
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          resourceType: "Document",
          resourceId: "doc-123",
          metadata: { downloadFormat: "pdf" },
          ipAddress: "192.168.1.1",
          userAgent: "Mozilla/5.0",
        }),
      });
    });

    it("should handle database errors gracefully", async () => {
      mockAuditLogCreate.mockRejectedValue(new Error("Database error"));

      const consoleSpy = jest.spyOn(console, "error").mockImplementation();

      const result = await logAuditEvent({
        eventType: "USER_LOGIN",
        userId: "user-1",
      });

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        "Failed to create audit log:",
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });

    it("should handle immutable chain errors gracefully", async () => {
      mockCreateImmutableAuditEntry.mockRejectedValue(new Error("Chain error"));

      const consoleSpy = jest.spyOn(console, "error").mockImplementation();

      const result = await logAuditEvent({
        eventType: "DOCUMENT_VIEWED",
        teamId: "team-1",
      });

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe("logAuditEventFromRequest", () => {
    it("should extract IP from x-forwarded-for header", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "203.0.113.50, 70.41.3.18, 150.172.238.178",
          "user-agent": "TestAgent/1.0",
        },
      });

      await logAuditEventFromRequest(req, {
        eventType: "USER_LOGIN",
        userId: "user-1",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ipAddress: "203.0.113.50",
          userAgent: "TestAgent/1.0",
        }),
      });
    });

    it("should extract IP from x-real-ip header when x-forwarded-for is missing", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-real-ip": "10.0.0.1",
          "user-agent": "TestAgent/1.0",
        },
      });

      await logAuditEventFromRequest(req, {
        eventType: "USER_LOGIN",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ipAddress: "10.0.0.1",
        }),
      });
    });

    it("should handle missing headers gracefully", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({
        headers: {},
      });

      await logAuditEventFromRequest(req, {
        eventType: "USER_LOGIN",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ipAddress: null,
          userAgent: null,
        }),
      });
    });

    it("should trim whitespace from IP addresses", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "  192.168.1.1  ,  10.0.0.1  ",
        },
      });

      await logAuditEventFromRequest(req, {
        eventType: "USER_LOGIN",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ipAddress: "192.168.1.1",
        }),
      });
    });
  });

  describe("logViewEvent", () => {
    it("should log document view with correct fields", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "view-log" });

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
          "user-agent": "Mozilla/5.0",
        },
      });

      await logViewEvent(req, {
        userId: "user-1",
        teamId: null,
        documentId: "doc-123",
        viewerEmail: "viewer@example.com",
        linkId: "link-456",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "DOCUMENT_VIEWED",
          resourceType: "Document",
          resourceId: "doc-123",
          metadata: expect.objectContaining({
            viewerEmail: "viewer@example.com",
            linkId: "link-456",
            timestamp: expect.any(String),
          }),
        }),
      });
    });

    it("should handle missing optional fields", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "view-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logViewEvent(req, {
        documentId: "doc-123",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "DOCUMENT_VIEWED",
          resourceId: "doc-123",
        }),
      });
    });
  });

  describe("logSignEvent", () => {
    it("should log document signature with correct fields", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "sign-log" });

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
        },
      });

      await logSignEvent(req, {
        userId: "user-1",
        teamId: null,
        documentId: "doc-123",
        signerEmail: "signer@example.com",
        signerName: "John Doe",
        recipientId: "recipient-456",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "DOCUMENT_SIGNED",
          resourceType: "SignatureDocument",
          resourceId: "doc-123",
          metadata: expect.objectContaining({
            signerEmail: "signer@example.com",
            signerName: "John Doe",
            recipientId: "recipient-456",
            timestamp: expect.any(String),
          }),
        }),
      });
    });
  });

  describe("logSubscriptionEvent", () => {
    it("should log subscription created event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "sub-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logSubscriptionEvent(req, {
        eventType: "SUBSCRIPTION_CREATED",
        userId: "user-1",
        teamId: null,
        subscriptionId: "sub-123",
        investorId: "investor-456",
        fundId: "fund-789",
        amount: 100000,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_CREATED",
          resourceType: "Subscription",
          resourceId: "sub-123",
          metadata: expect.objectContaining({
            investorId: "investor-456",
            fundId: "fund-789",
            amount: "100000",
          }),
        }),
      });
    });

    it("should log subscription signed event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "sub-sign-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logSubscriptionEvent(req, {
        eventType: "SUBSCRIPTION_SIGNED",
        subscriptionId: "sub-123",
        investorId: "investor-456",
        fundId: "fund-789",
        amount: "250000",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_SIGNED",
        }),
      });
    });

    it("should convert numeric amount to string", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "sub-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logSubscriptionEvent(req, {
        eventType: "SUBSCRIPTION_CREATED",
        subscriptionId: "sub-123",
        investorId: "investor-456",
        fundId: "fund-789",
        amount: 50000.50,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          metadata: expect.objectContaining({
            amount: "50000.5",
          }),
        }),
      });
    });
  });

  describe("logPaymentEvent", () => {
    it("should log payment initiated event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "payment-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logPaymentEvent(req, {
        eventType: "SUBSCRIPTION_PAYMENT_INITIATED",
        userId: "user-1",
        teamId: null,
        transactionId: "txn-123",
        subscriptionId: "sub-456",
        investorId: "investor-789",
        fundId: "fund-001",
        amount: 100000,
        plaidTransferId: "plaid-transfer-123",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_INITIATED",
          resourceType: "Transaction",
          resourceId: "txn-123",
          metadata: expect.objectContaining({
            subscriptionId: "sub-456",
            investorId: "investor-789",
            fundId: "fund-001",
            amount: "100000",
            plaidTransferId: "plaid-transfer-123",
          }),
        }),
      });
    });

    it("should log payment completed event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "payment-complete-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logPaymentEvent(req, {
        eventType: "SUBSCRIPTION_PAYMENT_COMPLETED",
        transactionId: "txn-123",
        investorId: "investor-789",
        amount: 100000,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_COMPLETED",
        }),
      });
    });

    it("should log payment failed event with failure reason", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "payment-failed-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logPaymentEvent(req, {
        eventType: "SUBSCRIPTION_PAYMENT_FAILED",
        transactionId: "txn-123",
        investorId: "investor-789",
        amount: 100000,
        failureReason: "Insufficient funds",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_FAILED",
          metadata: expect.objectContaining({
            failureReason: "Insufficient funds",
          }),
        }),
      });
    });

    it("should log payment recorded event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "payment-recorded-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logPaymentEvent(req, {
        eventType: "SUBSCRIPTION_PAYMENT_RECORDED",
        transactionId: "txn-123",
        investorId: "investor-789",
        amount: "50000",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "SUBSCRIPTION_PAYMENT_RECORDED",
        }),
      });
    });
  });

  describe("logAccreditationEvent", () => {
    it("should log accreditation submitted event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "accred-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logAccreditationEvent(req, {
        eventType: "ACCREDITATION_SUBMITTED",
        userId: "user-1",
        teamId: null,
        investorId: "investor-123",
        accreditationType: "INCOME",
        commitmentAmount: 100000,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "ACCREDITATION_SUBMITTED",
          resourceType: "Accreditation",
          resourceId: "investor-123",
          metadata: expect.objectContaining({
            accreditationType: "INCOME",
            commitmentAmount: 100000,
          }),
        }),
      });
    });

    it("should log accreditation approved event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "accred-approved-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logAccreditationEvent(req, {
        eventType: "ACCREDITATION_APPROVED",
        investorId: "investor-123",
        reason: "Verified via third-party verification service",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "ACCREDITATION_APPROVED",
          metadata: expect.objectContaining({
            reason: "Verified via third-party verification service",
          }),
        }),
      });
    });

    it("should log accreditation rejected event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "accred-rejected-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logAccreditationEvent(req, {
        eventType: "ACCREDITATION_REJECTED",
        investorId: "investor-123",
        reason: "Documentation insufficient",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "ACCREDITATION_REJECTED",
        }),
      });
    });

    it("should log auto-approved accreditation", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "accred-auto-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logAccreditationEvent(req, {
        eventType: "ACCREDITATION_AUTO_APPROVED",
        investorId: "investor-123",
        autoApproved: true,
        commitmentAmount: 500000,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "ACCREDITATION_AUTO_APPROVED",
          metadata: expect.objectContaining({
            autoApproved: true,
            commitmentAmount: 500000,
          }),
        }),
      });
    });
  });

  describe("logCertificateEvent", () => {
    it("should log certificate generated event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "cert-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logCertificateEvent(req, {
        eventType: "CERTIFICATE_GENERATED",
        userId: "user-1",
        teamId: null,
        documentId: "doc-123",
        certificateId: "cert-456",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "CERTIFICATE_GENERATED",
          resourceType: "Certificate",
          resourceId: "doc-123",
          metadata: expect.objectContaining({
            certificateId: "cert-456",
          }),
        }),
      });
    });

    it("should log certificate downloaded event", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "cert-download-log" });

      const { req } = createMocks<NextApiRequest>({});

      await logCertificateEvent(req, {
        eventType: "CERTIFICATE_DOWNLOADED",
        documentId: "doc-123",
        certificateId: "cert-456",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          eventType: "CERTIFICATE_DOWNLOADED",
        }),
      });
    });
  });

  describe("Event Types Coverage", () => {
    const allEventTypes: AuditEventType[] = [
      "DOCUMENT_VIEWED",
      "DOCUMENT_DOWNLOADED",
      "DOCUMENT_SIGNED",
      "DOCUMENT_COMPLETED",
      "DOCUMENT_DECLINED",
      "SUBSCRIPTION_CREATED",
      "SUBSCRIPTION_SIGNED",
      "SUBSCRIPTION_PAYMENT_INITIATED",
      "SUBSCRIPTION_PAYMENT_COMPLETED",
      "SUBSCRIPTION_PAYMENT_FAILED",
      "SUBSCRIPTION_PAYMENT_RECORDED",
      "ACCREDITATION_SUBMITTED",
      "ACCREDITATION_APPROVED",
      "ACCREDITATION_REJECTED",
      "ACCREDITATION_AUTO_APPROVED",
      "NDA_SIGNED",
      "CAPITAL_CALL_CREATED",
      "CAPITAL_CALL_PAID",
      "DISTRIBUTION_CREATED",
      "DISTRIBUTION_COMPLETED",
      "INVESTOR_CREATED",
      "INVESTOR_UPDATED",
      "KYC_INITIATED",
      "KYC_COMPLETED",
      "KYC_FAILED",
      "BANK_ACCOUNT_LINKED",
      "BANK_ACCOUNT_REMOVED",
      "USER_LOGIN",
      "USER_LOGOUT",
      "ADMIN_ACTION",
      "CERTIFICATE_GENERATED",
      "CERTIFICATE_DOWNLOADED",
      "AUDIT_LOG_EXPORT",
      "AUDIT_LOG_VERIFIED",
    ];

    it.each(allEventTypes)("should accept %s event type", async (eventType) => {
      mockAuditLogCreate.mockResolvedValue({ id: `log-${eventType}` });

      const result = await logAuditEvent({
        eventType,
        userId: "user-1",
      });

      expect(result).toBe(`log-${eventType}`);
    });
  });

  describe("Resource Types Coverage", () => {
    const allResourceTypes: ResourceType[] = [
      "Document",
      "SignatureDocument",
      "Subscription",
      "Transaction",
      "Investor",
      "Fund",
      "User",
      "Accreditation",
      "CapitalCall",
      "Distribution",
      "BankLink",
      "Certificate",
      "AuditLog",
    ];

    it.each(allResourceTypes)("should accept %s resource type", async (resourceType) => {
      mockAuditLogCreate.mockResolvedValue({ id: `log-${resourceType}` });

      const result = await logAuditEvent({
        eventType: "ADMIN_ACTION",
        resourceType,
        resourceId: "resource-123",
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          resourceType,
        }),
      });
    });
  });

  describe("Timestamp Metadata", () => {
    it("should include ISO timestamp in view event metadata", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({});
      const beforeCall = new Date().toISOString();

      await logViewEvent(req, { documentId: "doc-1" });

      const afterCall = new Date().toISOString();
      const callData = mockAuditLogCreate.mock.calls[0][0].data;
      const timestamp = callData.metadata.timestamp;

      expect(timestamp >= beforeCall).toBe(true);
      expect(timestamp <= afterCall).toBe(true);
    });

    it("should include ISO timestamp in sign event metadata", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      const { req } = createMocks<NextApiRequest>({});

      await logSignEvent(req, {
        documentId: "doc-1",
        signerEmail: "test@example.com",
      });

      const callData = mockAuditLogCreate.mock.calls[0][0].data;
      expect(callData.metadata.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });

  describe("Null vs Undefined Handling", () => {
    it("should convert undefined userId to null", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      await logAuditEvent({
        eventType: "USER_LOGIN",
        // userId not provided
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: null,
        }),
      });
    });

    it("should preserve null values for optional fields", async () => {
      mockAuditLogCreate.mockResolvedValue({ id: "log-1" });

      await logAuditEvent({
        eventType: "USER_LOGIN",
        userId: null,
        teamId: null,
        ipAddress: null,
        userAgent: null,
      });

      expect(mockAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: null,
          teamId: null,
          ipAddress: null,
          userAgent: null,
        }),
      });
    });
  });
});
