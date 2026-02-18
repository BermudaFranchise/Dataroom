// @ts-nocheck
/**
 * Tests for /api/funds/[fundId]/aggregates endpoint
 * Covers: financial calculations, team scoping, aggregation accuracy
 */
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

jest.mock("@/lib/auth/auth-options", () => ({
  authOptions: { providers: [], session: { strategy: "jwt" } },
}));

jest.mock("@/lib/auth/with-role", () => ({
  getUserWithRole: jest.fn(),
  requireRole: jest.fn(),
}));

import handler from "@/pages/api/funds/[fundId]/aggregates";
import prisma from "@/lib/prisma";
import { getUserWithRole, requireRole } from "@/lib/auth/with-role";

// Add manualInvestment mock
(prisma as any).manualInvestment = { findMany: jest.fn() };
(prisma as any).transaction = {
  ...(prisma as any).transaction,
  findMany: jest.fn(),
};

function makeMocks(method: string, opts: any = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method,
    query: { fundId: "fund-1", ...opts.query },
  });
}

const mockGPResult = {
  user: {
    id: "user-1",
    email: "gp@test.com",
    role: "GP",
    teamIds: ["team-1"],
  },
};

beforeEach(() => {
  jest.clearAllMocks();
  (getUserWithRole as jest.Mock).mockResolvedValue(mockGPResult);
  (requireRole as jest.Mock).mockReturnValue({ allowed: true });
});

describe("Authentication & Authorization", () => {
  it("returns 405 for non-GET methods", async () => {
    const { req, res } = makeMocks("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when user is not GP", async () => {
    (requireRole as jest.Mock).mockReturnValue({ allowed: false, error: "Insufficient permissions", statusCode: 403 });

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 400 when fundId is missing", async () => {
    const { req, res } = makeMocks("GET", { query: {} });
    req.query = {};
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 404 when fund not in user's teams", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("scopes fund query to user's teamIds", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const findFirstCall = (prisma.fund.findFirst as jest.Mock).mock.calls[0][0];
    expect(findFirstCall.where.id).toBe("fund-1");
    expect(findFirstCall.where.teamId).toEqual({ in: ["team-1"] });
  });
});

describe("Financial Aggregation", () => {
  const baseFund = {
    id: "fund-1",
    name: "Growth Fund I",
    status: "RAISING",
    targetRaise: { toString: () => "5000000" },
    currentRaise: { toString: () => "1200000" },
    closingDate: null,
    investments: [],
    capitalCalls: [],
    distributions: [],
  };

  it("returns zero aggregates for fund with no activity", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue(baseFund);
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());
    expect(data.aggregates.totalCommitments).toBe("0.00");
    expect(data.aggregates.totalFunded).toBe("0.00");
    expect(data.aggregates.totalCapitalCalled).toBe("0.00");
    expect(data.aggregates.totalDistributed).toBe("0.00");
    expect(data.aggregates.netCashFlow).toBe("0.00");
    expect(data.investorCount).toBe(0);
    expect(data.manualInvestmentCount).toBe(0);
  });

  it("correctly aggregates platform + manual commitments and funded amounts", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [
        { investorId: "inv-1", commitmentAmount: 500000, fundedAmount: 250000, status: "COMMITTED", investor: { id: "inv-1", entityName: "Entity A", user: { name: "Alice", email: "alice@test.com" } } },
        { investorId: "inv-2", commitmentAmount: 300000, fundedAmount: 300000, status: "FUNDED", investor: { id: "inv-2", entityName: null, user: { name: "Bob", email: "bob@test.com" } } },
      ],
      capitalCalls: [
        { amount: 400000, responses: [] },
      ],
      distributions: [
        { totalAmount: 50000 },
      ],
    });

    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([
      { id: "mi-1", investorId: "inv-3", commitmentAmount: 200000, fundedAmount: 100000, documentType: "LPA", documentTitle: "Manual LP", signedDate: null, status: "ACTIVE" },
    ]);

    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([
      { type: "CAPITAL_CALL", status: "COMPLETED", amount: 400000 },
      { type: "DISTRIBUTION", status: "COMPLETED", amount: 50000 },
      { type: "CAPITAL_CALL", status: "PENDING", amount: 100000 },
    ]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());

    // Platform: 500k + 300k = 800k; Manual: 200k; Total: 1M
    expect(data.aggregates.totalCommitments).toBe("1000000.00");
    expect(data.aggregates.platformCommitments).toBe("800000.00");
    expect(data.aggregates.manualCommitments).toBe("200000.00");

    // Platform: 250k + 300k = 550k; Manual: 100k; Total: 650k
    expect(data.aggregates.totalFunded).toBe("650000.00");

    // Capital calls: 400k
    expect(data.aggregates.totalCapitalCalled).toBe("400000.00");

    // Distributions: 50k
    expect(data.aggregates.totalDistributed).toBe("50000.00");

    // Net: 400k inbound - 50k outbound = 350k
    expect(data.aggregates.totalInbound).toBe("400000.00");
    expect(data.aggregates.totalOutbound).toBe("50000.00");
    expect(data.aggregates.netCashFlow).toBe("350000.00");

    // Unique investors: inv-1, inv-2 (platform) + inv-3 (manual) = 3
    expect(data.investorCount).toBe(3);
    expect(data.manualInvestmentCount).toBe(1);

    // Pending transactions
    expect(data.pendingTransactionCount).toBe(1);
  });

  it("only counts COMPLETED transactions for inbound/outbound", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [],
      capitalCalls: [],
      distributions: [],
    });
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([
      { type: "CAPITAL_CALL", status: "COMPLETED", amount: 100000 },
      { type: "CAPITAL_CALL", status: "PROCESSING", amount: 50000 },
      { type: "CAPITAL_CALL", status: "FAILED", amount: 25000 },
      { type: "CAPITAL_CALL", status: "PENDING", amount: 75000 },
    ]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    // Only COMPLETED should count
    expect(data.aggregates.totalInbound).toBe("100000.00");
    // PROCESSING and PENDING are pending
    expect(data.pendingTransactionCount).toBe(2);
  });

  it("deduplicates investor count across platform and manual", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [
        { investorId: "inv-shared", commitmentAmount: 100000, fundedAmount: 50000, status: "COMMITTED", investor: { id: "inv-shared", entityName: null, user: { name: "Shared", email: "s@t.com" } } },
      ],
      capitalCalls: [],
      distributions: [],
    });
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([
      { id: "mi-1", investorId: "inv-shared", commitmentAmount: 50000, fundedAmount: 25000, status: "ACTIVE" },
    ]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    // Same investorId appears in both — should count as 1
    expect(data.investorCount).toBe(1);
    expect(data.aggregates.totalCommitments).toBe("150000.00");
  });

  it("uses entityName over user name when present in investor response", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [
        {
          investorId: "inv-1",
          commitmentAmount: 100000,
          fundedAmount: 50000,
          status: "COMMITTED",
          investor: { id: "inv-1", entityName: "My LLC", user: { name: "John Doe", email: "john@test.com" } },
        },
      ],
      capitalCalls: [],
      distributions: [],
    });
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    expect(data.investors[0].name).toBe("My LLC");
    expect(data.investors[0].email).toBe("john@test.com");
  });

  it("falls back to user.name when entityName is null", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [
        {
          investorId: "inv-1",
          commitmentAmount: 100000,
          fundedAmount: 0,
          status: "COMMITTED",
          investor: { id: "inv-1", entityName: null, user: { name: "Jane Smith", email: "jane@test.com" } },
        },
      ],
      capitalCalls: [],
      distributions: [],
    });
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    expect(data.investors[0].name).toBe("Jane Smith");
  });

  it("formats all currency values with 2 decimal places", async () => {
    (prisma.fund.findFirst as jest.Mock).mockResolvedValue({
      ...baseFund,
      investments: [
        { investorId: "inv-1", commitmentAmount: 99999.999, fundedAmount: 33333.333, status: "COMMITTED", investor: { id: "inv-1", entityName: null, user: { name: "A", email: "a@t.com" } } },
      ],
      capitalCalls: [],
      distributions: [],
    });
    ((prisma as any).manualInvestment.findMany as jest.Mock).mockResolvedValue([]);
    ((prisma as any).transaction.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    expect(data.aggregates.totalCommitments).toMatch(/^\d+\.\d{2}$/);
    expect(data.aggregates.totalFunded).toMatch(/^\d+\.\d{2}$/);
  });

  it("handles DB error gracefully", async () => {
    (prisma.fund.findFirst as jest.Mock).mockRejectedValue(new Error("Connection timeout"));

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(JSON.parse(res._getData()).message).toBe("Failed to fetch fund aggregates");
  });
});
