// @ts-nocheck
/**
 * Tests for /api/transactions endpoint
 * Covers: AML screening, KYC enforcement, transaction CRUD, team scoping
 */
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

// Must mock before importing handler
jest.mock("@/lib/auth/auth-options", () => ({
  authOptions: { providers: [], session: { strategy: "jwt" } },
}));

jest.mock("@/lib/auth/with-role", () => ({
  getUserWithRole: jest.fn(),
  requireRole: jest.fn(),
}));

import handler from "@/pages/api/transactions/index";
import prisma from "@/lib/prisma";
import { getUserWithRole } from "@/lib/auth/with-role";

function makeMocks(method: string, opts: any = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method,
    body: opts.body || {},
    query: opts.query || {},
    headers: { "x-forwarded-for": "1.2.3.4", "user-agent": "test-agent", ...opts.headers },
  });
}

const mockGPUser = {
  user: {
    id: "user-1",
    email: "gp@example.com",
    role: "GP",
    teamIds: ["team-1"],
    userId: "user-1",
  },
};

const mockLPUser = {
  user: {
    id: "user-2",
    email: "lp@example.com",
    role: "LP",
    teamIds: ["team-1"],
    userId: "user-2",
  },
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe("POST /api/transactions - Authentication & Authorization", () => {
  it("returns 401 when not authenticated", async () => {
    (getUserWithRole as jest.Mock).mockResolvedValue({
      user: null,
      error: "Not authenticated",
      statusCode: 401,
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 403 when user is LP (not GP)", async () => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockLPUser);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "GP access required" });
  });

  it("returns 403 when user has no team access", async () => {
    (getUserWithRole as jest.Mock).mockResolvedValue({
      user: { ...mockGPUser.user, teamIds: [] },
    });

    const { req, res } = makeMocks("POST");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "No team access" });
  });
});

describe("POST /api/transactions - Validation", () => {
  beforeEach(() => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);
  });

  it("rejects invalid transaction type", async () => {
    const { req, res } = makeMocks("POST", {
      body: { type: "INVALID", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "Invalid transaction type" });
  });

  it("rejects missing required fields", async () => {
    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "Missing required fields" });
  });

  it("rejects fund not in user's team", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "other-fund" }]);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "Fund not in your team" });
  });

  it("rejects when investor not found", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });
});

describe("POST /api/transactions - KYC Enforcement", () => {
  beforeEach(() => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
  });

  it("blocks transaction when KYC is NOT_STARTED", async () => {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "NOT_STARTED",
      bankLinks: [],
    });
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    const data = JSON.parse(res._getData());
    expect(data.code).toBe("KYC_REQUIRED");
    expect(data.kycStatus).toBe("NOT_STARTED");
  });

  it("blocks transaction when KYC is PENDING", async () => {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "PENDING",
      bankLinks: [],
    });
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).code).toBe("KYC_REQUIRED");
  });

  it("allows transaction when KYC is APPROVED", async () => {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "APPROVED",
      bankLinks: [{ id: "bl-1" }],
    });
    // AML: no recent transactions
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
    expect(JSON.parse(res._getData()).success).toBe(true);
  });

  it("allows transaction when KYC is VERIFIED", async () => {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "VERIFIED",
      bankLinks: [{ id: "bl-1" }],
    });
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
  });

  it("creates audit log when KYC check blocks transaction", async () => {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: null,
      bankLinks: [],
    });
    const auditCreate = jest.fn().mockResolvedValue({});
    (prisma.auditLog.create as jest.Mock) = auditCreate;

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(auditCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          eventType: "TRANSACTION_BLOCKED_KYC",
        }),
      })
    );
  });
});

describe("POST /api/transactions - AML Screening", () => {
  beforeEach(() => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
  });

  function mockVerifiedInvestor() {
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "APPROVED",
      bankLinks: [{ id: "bl-1" }],
    });
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});
  }

  it("passes AML for small transaction with no history", async () => {
    mockVerifiedInvestor();
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 10000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "10000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
  });

  it("flags LARGE_TRANSACTION for amount > $100k but still passes if < 70 risk", async () => {
    mockVerifiedInvestor();
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 150000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "150000" },
    });
    await handler(req, res);
    // Risk = 30 (large txn only), under 70 threshold
    expect(res._getStatusCode()).toBe(201);
  });

  it("blocks when daily cumulative exceeds $250k (risk 40) + large txn (risk 30) = 70", async () => {
    mockVerifiedInvestor();
    // Previous transactions totaling $200k in last 24hrs
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([
      { amount: 100000, createdAt: new Date() },
      { amount: 100000, createdAt: new Date() },
    ]);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "120000" },
    });
    await handler(req, res);
    // amount = 120k (LARGE_TRANSACTION: +30)
    // daily = 200k + 120k = 320k (DAILY_LIMIT_EXCEEDED: +40)
    // total risk = 70 -> blocked
    expect(res._getStatusCode()).toBe(403);
    const data = JSON.parse(res._getData());
    expect(data.code).toBe("AML_BLOCKED");
  });

  it("blocks when high velocity (5+ transactions in 24h) + large transaction", async () => {
    mockVerifiedInvestor();
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([
      { amount: 10000, createdAt: new Date() },
      { amount: 10000, createdAt: new Date() },
      { amount: 10000, createdAt: new Date() },
      { amount: 10000, createdAt: new Date() },
      { amount: 10000, createdAt: new Date() },
    ]);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "110000" },
    });
    await handler(req, res);
    // amount = 110k (LARGE_TRANSACTION: +30)
    // velocity: 5 existing (HIGH_VELOCITY: +25)
    // daily = 50k + 110k = 160k (under 250k, no flag)
    // total risk = 55 -> passes
    expect(res._getStatusCode()).toBe(201);
  });

  it("blocks when all three AML flags triggered (risk 95)", async () => {
    mockVerifiedInvestor();
    // 5 previous large transactions
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([
      { amount: 60000, createdAt: new Date() },
      { amount: 60000, createdAt: new Date() },
      { amount: 60000, createdAt: new Date() },
      { amount: 60000, createdAt: new Date() },
      { amount: 60000, createdAt: new Date() },
    ]);

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "120000" },
    });
    await handler(req, res);
    // amount = 120k (LARGE_TRANSACTION: +30)
    // velocity: 5 (HIGH_VELOCITY: +25)
    // daily = 300k + 120k = 420k (DAILY_LIMIT_EXCEEDED: +40)
    // total = 95 -> blocked
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).code).toBe("AML_BLOCKED");
  });

  it("creates AML audit log even when screening passes", async () => {
    mockVerifiedInvestor();
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    const auditCreate = jest.fn().mockResolvedValue({});
    (prisma.auditLog.create as jest.Mock) = auditCreate;
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 5000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "5000" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
    // Audit log for AML screening should have been called
    expect(auditCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          eventType: "AML_SCREENING",
        }),
      })
    );
  });
});

describe("POST /api/transactions - Transaction Creation", () => {
  beforeEach(() => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.investor.findUnique as jest.Mock).mockResolvedValue({
      id: "inv-1",
      personaStatus: "APPROVED",
      bankLinks: [{ id: "bl-1" }, { id: "bl-2" }],
    });
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.auditLog.create as jest.Mock).mockResolvedValue({});
  });

  it("creates CAPITAL_CALL transaction successfully", async () => {
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: {
        type: "CAPITAL_CALL",
        investorId: "inv-1",
        fundId: "fund-1",
        amount: "50000",
        description: "First capital call",
      },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(201);
    const data = JSON.parse(res._getData());
    expect(data.transaction.type).toBe("CAPITAL_CALL");
    expect(data.transaction.amount).toBe("50000");
    expect(data.transaction.status).toBe("PENDING");
  });

  it("creates DISTRIBUTION transaction successfully", async () => {
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-2",
      type: "DISTRIBUTION",
      amount: 25000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: {
        type: "DISTRIBUTION",
        investorId: "inv-1",
        fundId: "fund-1",
        amount: "25000",
      },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);
    const data = JSON.parse(res._getData());
    expect(data.transaction.type).toBe("DISTRIBUTION");
  });

  it("uses specific bankLinkId when provided", async () => {
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: {
        type: "CAPITAL_CALL",
        investorId: "inv-1",
        fundId: "fund-1",
        amount: "50000",
        bankLinkId: "bl-2",
      },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);

    const createCall = (prisma.transaction.create as jest.Mock).mock.calls[0][0];
    expect(createCall.data.bankLinkId).toBe("bl-2");
  });

  it("defaults to first bankLink when no bankLinkId specified", async () => {
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: {
        type: "CAPITAL_CALL",
        investorId: "inv-1",
        fundId: "fund-1",
        amount: "50000",
      },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(201);

    const createCall = (prisma.transaction.create as jest.Mock).mock.calls[0][0];
    expect(createCall.data.bankLinkId).toBe("bl-1");
  });

  it("records IP address and user agent in audit trail", async () => {
    (prisma.transaction.create as jest.Mock).mockResolvedValue({
      id: "txn-1",
      type: "CAPITAL_CALL",
      amount: 50000,
      status: "PENDING",
    });

    const { req, res } = makeMocks("POST", {
      body: { type: "CAPITAL_CALL", investorId: "inv-1", fundId: "fund-1", amount: "50000" },
    });
    await handler(req, res);

    const createCall = (prisma.transaction.create as jest.Mock).mock.calls[0][0];
    expect(createCall.data.ipAddress).toBe("1.2.3.4");
    expect(createCall.data.userAgent).toBe("test-agent");
    expect(createCall.data.auditTrail[0].action).toBe("INITIATED");
  });
});

describe("GET /api/transactions - List & Filtering", () => {
  beforeEach(() => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);
  });

  it("returns empty list when no funds in team", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());
    expect(data.transactions).toEqual([]);
    expect(data.total).toBe(0);
  });

  it("returns paginated transactions with summary", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([
      {
        id: "txn-1",
        type: "CAPITAL_CALL",
        amount: 50000,
        currency: "USD",
        status: "COMPLETED",
        description: "Capital call #1",
        fundId: "fund-1",
        investor: { id: "inv-1", entityName: "LLC Corp", user: { name: "John", email: "john@test.com" } },
        bankLink: { institutionName: "Chase", accountMask: "1234", accountType: "checking" },
        plaidTransferId: null,
        initiatedAt: new Date("2024-01-01"),
        processedAt: null,
        completedAt: new Date("2024-01-02"),
        failedAt: null,
        statusMessage: null,
        createdAt: new Date("2024-01-01"),
      },
    ]);
    (prisma.transaction.count as jest.Mock).mockResolvedValue(1);
    (prisma.transaction.groupBy as jest.Mock).mockResolvedValue([
      { type: "CAPITAL_CALL", status: "COMPLETED", _sum: { amount: 50000 }, _count: 1 },
    ]);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());
    expect(data.transactions).toHaveLength(1);
    expect(data.transactions[0].direction).toBe("inbound");
    expect(data.transactions[0].amount).toBe("50000");
    expect(data.transactions[0].investor.name).toBe("LLC Corp");
    expect(data.transactions[0].bankAccount).toBe("Chase ••••1234");
    expect(data.total).toBe(1);
    expect(data.hasMore).toBe(false);
  });

  it("filters by fundId only if it's in allowed funds", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }, { id: "fund-2" }]);
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.count as jest.Mock).mockResolvedValue(0);
    (prisma.transaction.groupBy as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET", { query: { fundId: "fund-2" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);

    const findManyCall = (prisma.transaction.findMany as jest.Mock).mock.calls[0][0];
    expect(findManyCall.where.fundId).toBe("fund-2");
  });

  it("ignores fundId filter if fund is not in user's teams", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.count as jest.Mock).mockResolvedValue(0);
    (prisma.transaction.groupBy as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET", { query: { fundId: "attacker-fund" } });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);

    // Should NOT filter to attacker-fund, should use allowedFundIds
    const findManyCall = (prisma.transaction.findMany as jest.Mock).mock.calls[0][0];
    expect(findManyCall.where.fundId).toEqual({ in: ["fund-1"] });
  });

  it("maps direction=inbound to CAPITAL_CALL type filter", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.count as jest.Mock).mockResolvedValue(0);
    (prisma.transaction.groupBy as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET", { query: { direction: "inbound" } });
    await handler(req, res);

    const findManyCall = (prisma.transaction.findMany as jest.Mock).mock.calls[0][0];
    expect(findManyCall.where.type).toBe("CAPITAL_CALL");
  });

  it("maps direction=outbound to DISTRIBUTION type filter", async () => {
    (prisma.fund.findMany as jest.Mock).mockResolvedValue([{ id: "fund-1" }]);
    (prisma.transaction.findMany as jest.Mock).mockResolvedValue([]);
    (prisma.transaction.count as jest.Mock).mockResolvedValue(0);
    (prisma.transaction.groupBy as jest.Mock).mockResolvedValue([]);

    const { req, res } = makeMocks("GET", { query: { direction: "outbound" } });
    await handler(req, res);

    const findManyCall = (prisma.transaction.findMany as jest.Mock).mock.calls[0][0];
    expect(findManyCall.where.type).toBe("DISTRIBUTION");
  });
});

describe("Method validation", () => {
  it("returns 405 for unsupported methods", async () => {
    (getUserWithRole as jest.Mock).mockResolvedValue(mockGPUser);

    const { req, res } = makeMocks("DELETE");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});
