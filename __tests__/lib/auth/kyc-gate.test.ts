/**
 * KYC Gate Tests
 *
 * Tests for lib/auth/kyc-gate.ts - KYC verification checks,
 * transaction gating, and investor status validation.
 *
 * Security-critical tests for KYC/AML compliance enforcement.
 */

// Mock prisma
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    investor: {
      findUnique: jest.fn(),
    },
  },
}));

import prisma from "@/lib/prisma";
import {
  checkKycGate,
  enforceKycForTransaction,
  KycGateResult,
} from "@/lib/auth/kyc-gate";

describe("KYC Gate", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("checkKycGate", () => {
    it("should allow APPROVED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(true);
      expect(result.status).toBe("APPROVED");
      expect(result.message).toBeUndefined();
    });

    it("should allow VERIFIED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "VERIFIED",
        personaVerifiedAt: new Date(),
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(true);
      expect(result.status).toBe("VERIFIED");
    });

    it("should deny PENDING investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "PENDING",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("PENDING");
      expect(result.message).toContain("KYC verification required");
    });

    it("should deny REJECTED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "REJECTED",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("REJECTED");
    });

    it("should deny EXPIRED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "EXPIRED",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("EXPIRED");
    });

    it("should deny NEEDS_REVIEW investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "NEEDS_REVIEW",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("NEEDS_REVIEW");
    });

    it("should return NOT_FOUND for non-existent investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await checkKycGate("non-existent-investor");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("NOT_FOUND");
      expect(result.message).toBe("Investor not found");
    });

    it("should select only necessary fields", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      await checkKycGate("investor-123");

      expect(prisma.investor.findUnique).toHaveBeenCalledWith({
        where: { id: "investor-123" },
        select: {
          personaStatus: true,
          personaVerifiedAt: true,
        },
      });
    });

    it("should handle null personaStatus", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: null,
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
    });

    it("should handle empty string personaStatus", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
    });
  });

  describe("enforceKycForTransaction", () => {
    it("should not throw for APPROVED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      await expect(
        enforceKycForTransaction("investor-123")
      ).resolves.not.toThrow();
    });

    it("should not throw for VERIFIED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "VERIFIED",
        personaVerifiedAt: new Date(),
      });

      await expect(
        enforceKycForTransaction("investor-123")
      ).resolves.not.toThrow();
    });

    it("should throw for PENDING investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "PENDING",
        personaVerifiedAt: null,
      });

      await expect(enforceKycForTransaction("investor-123")).rejects.toThrow(
        "KYC verification required"
      );
    });

    it("should throw for REJECTED investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "REJECTED",
        personaVerifiedAt: null,
      });

      await expect(enforceKycForTransaction("investor-123")).rejects.toThrow(
        "KYC verification required"
      );
    });

    it("should throw for non-existent investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(enforceKycForTransaction("non-existent")).rejects.toThrow(
        "Investor not found"
      );
    });

    it("should include message from checkKycGate result", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "NEEDS_REVIEW",
        personaVerifiedAt: null,
      });

      try {
        await enforceKycForTransaction("investor-123");
        fail("Expected error to be thrown");
      } catch (error) {
        expect((error as Error).message).toContain("KYC");
      }
    });
  });

  describe("KycGateResult Type", () => {
    it("should have correct structure for allowed result", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      const result: KycGateResult = await checkKycGate("investor-123");

      expect(result).toHaveProperty("allowed");
      expect(result).toHaveProperty("status");
      expect(typeof result.allowed).toBe("boolean");
      expect(typeof result.status).toBe("string");
    });

    it("should have optional message for denied result", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "PENDING",
        personaVerifiedAt: null,
      });

      const result: KycGateResult = await checkKycGate("investor-123");

      expect(result.message).toBeTruthy();
    });

    it("should not have message for allowed result", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      const result: KycGateResult = await checkKycGate("investor-123");

      expect(result.message).toBeUndefined();
    });
  });

  describe("Security Requirements", () => {
    it("should only accept APPROVED and VERIFIED as valid statuses", async () => {
      const validStatuses = ["APPROVED", "VERIFIED"];
      const invalidStatuses = [
        "PENDING",
        "REJECTED",
        "EXPIRED",
        "NEEDS_REVIEW",
        "CREATED",
        "SUBMITTED",
        "FAILED",
        null,
        "",
      ];

      for (const status of validStatuses) {
        (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
          personaStatus: status,
          personaVerifiedAt: new Date(),
        });

        const result = await checkKycGate("investor-123");
        expect(result.allowed).toBe(true);
      }

      for (const status of invalidStatuses) {
        (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
          personaStatus: status,
          personaVerifiedAt: null,
        });

        const result = await checkKycGate("investor-123");
        expect(result.allowed).toBe(false);
      }
    });

    it("should not expose sensitive investor data in response", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        id: "investor-123",
        personaStatus: "PENDING",
        personaVerifiedAt: null,
        email: "investor@example.com", // Should not be exposed
        ssn: "123-45-6789", // Should not be exposed
      });

      const result = await checkKycGate("investor-123");

      // Result should only contain allowed, status, and message
      expect(Object.keys(result)).toEqual(
        expect.arrayContaining(["allowed", "status"])
      );
      expect((result as any).email).toBeUndefined();
      expect((result as any).ssn).toBeUndefined();
    });

    it("should block transaction before KYC completion", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "PENDING",
        personaVerifiedAt: null,
      });

      await expect(enforceKycForTransaction("investor-123")).rejects.toThrow();
    });

    it("should handle database errors gracefully", async () => {
      (prisma.investor.findUnique as jest.Mock).mockRejectedValue(
        new Error("Database connection error")
      );

      await expect(checkKycGate("investor-123")).rejects.toThrow(
        "Database connection error"
      );
    });

    it("should not cache KYC status (always check database)", async () => {
      // First call: PENDING
      (prisma.investor.findUnique as jest.Mock).mockResolvedValueOnce({
        personaStatus: "PENDING",
        personaVerifiedAt: null,
      });

      const result1 = await checkKycGate("investor-123");
      expect(result1.allowed).toBe(false);

      // Second call: APPROVED (status updated)
      (prisma.investor.findUnique as jest.Mock).mockResolvedValueOnce({
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      const result2 = await checkKycGate("investor-123");
      expect(result2.allowed).toBe(true);

      // Both calls should hit the database
      expect(prisma.investor.findUnique).toHaveBeenCalledTimes(2);
    });
  });

  describe("Compliance Requirements", () => {
    it("should enforce KYC before financial transactions", async () => {
      // This test documents the requirement that KYC must be completed
      // before any financial transaction (subscription, wire transfer, etc.)

      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "CREATED",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
      expect(result.message).toContain("transaction");
    });

    it("should require personaStatus to be in approved list", async () => {
      // SEC 506(c) requires verification of accredited investor status
      // This is enforced by requiring APPROVED or VERIFIED status

      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "SUBMITTED", // Submitted but not yet verified
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      expect(result.allowed).toBe(false);
    });
  });

  describe("Edge Cases", () => {
    it("should handle investor with empty ID", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await checkKycGate("");

      expect(result.allowed).toBe(false);
      expect(result.status).toBe("NOT_FOUND");
    });

    it("should handle undefined personaVerifiedAt with APPROVED status", async () => {
      // Edge case: status is approved but no verification timestamp
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "APPROVED",
        personaVerifiedAt: null,
      });

      const result = await checkKycGate("investor-123");

      // Should still be allowed based on status alone
      expect(result.allowed).toBe(true);
    });

    it("should handle concurrent checks for same investor", async () => {
      (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
        personaStatus: "APPROVED",
        personaVerifiedAt: new Date(),
      });

      // Simulate concurrent checks
      const results = await Promise.all([
        checkKycGate("investor-123"),
        checkKycGate("investor-123"),
        checkKycGate("investor-123"),
      ]);

      results.forEach((result) => {
        expect(result.allowed).toBe(true);
      });
    });
  });
});
