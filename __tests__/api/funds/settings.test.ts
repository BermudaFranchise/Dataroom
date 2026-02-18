// @ts-nocheck
/**
 * Tests for /api/funds/[fundId]/settings endpoint
 * Covers: auth, RBAC, GET/PATCH fund settings, audit logging
 */
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth";

import handler from "@/pages/api/funds/[fundId]/settings";
import prisma from "@/lib/prisma";

function makeMocks(method: string, opts: any = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method,
    body: opts.body || {},
    query: { fundId: "fund-1", ...opts.query },
    headers: { "x-forwarded-for": "1.2.3.4", "user-agent": "test-agent", ...opts.headers },
  });
}

// Add auditLog mock
(prisma as any).auditLog = { create: jest.fn().mockResolvedValue({}) };

const mockFund = {
  id: "fund-1",
  name: "Test Fund I",
  teamId: "team-1",
  ndaGateEnabled: false,
  capitalCallThresholdEnabled: false,
  capitalCallThreshold: null,
  callFrequency: "AS_NEEDED",
  stagedCommitmentsEnabled: false,
  currentRaise: 1000000,
  targetRaise: 5000000,
};

const mockUserWithAccess = {
  id: "user-1",
  email: "admin@test.com",
  teams: [{ teamId: "team-1", role: "ADMIN" }],
};

const mockUserOwner = {
  id: "user-2",
  email: "owner@test.com",
  teams: [{ teamId: "team-1", role: "OWNER" }],
};

const mockUserMember = {
  id: "user-3",
  email: "member@test.com",
  teams: [{ teamId: "team-1", role: "MEMBER" }],
};

const mockUserOtherTeam = {
  id: "user-4",
  email: "other@test.com",
  teams: [{ teamId: "team-other", role: "ADMIN" }],
};

beforeEach(() => {
  jest.clearAllMocks();
});

describe("Authentication", () => {
  it("returns 401 when not authenticated", async () => {
    (getServerSession as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 401 when session has no email", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: {} });

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 401 when user not found in DB", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "ghost@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });
});

describe("Authorization", () => {
  it("returns 403 when user is MEMBER (not ADMIN/OWNER)", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "member@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserMember);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 403 when user is ADMIN of a different team", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "other@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserOtherTeam);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("allows ADMIN of the fund's team", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithAccess);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });

  it("allows OWNER of the fund's team", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "owner@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserOwner);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
  });
});

describe("Validation", () => {
  it("returns 400 when fundId is missing", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });

    const { req, res } = makeMocks("GET", { query: { fundId: undefined } });
    // Override query to remove fundId
    req.query = {};
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 404 when fund not found", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithAccess);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks("GET");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 405 for unsupported methods", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithAccess);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("DELETE");
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });
});

describe("GET /api/funds/[fundId]/settings", () => {
  beforeEach(() => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithAccess);
  });

  it("returns fund settings correctly", async () => {
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());
    expect(data.fund.id).toBe("fund-1");
    expect(data.fund.name).toBe("Test Fund I");
    expect(data.fund.ndaGateEnabled).toBe(false);
    expect(data.fund.capitalCallThresholdEnabled).toBe(false);
    expect(data.fund.capitalCallThreshold).toBeNull();
    expect(data.fund.callFrequency).toBe("AS_NEEDED");
    expect(data.fund.stagedCommitmentsEnabled).toBe(false);
    expect(data.fund.currentRaise).toBe(1000000);
    expect(data.fund.targetRaise).toBe(5000000);
  });

  it("converts Decimal capitalCallThreshold to number", async () => {
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue({
      ...mockFund,
      capitalCallThreshold: 500000.50,
      capitalCallThresholdEnabled: true,
    });

    const { req, res } = makeMocks("GET");
    await handler(req, res);

    const data = JSON.parse(res._getData());
    expect(data.fund.capitalCallThreshold).toBe(500000.5);
    expect(typeof data.fund.capitalCallThreshold).toBe("number");
  });
});

describe("PATCH /api/funds/[fundId]/settings", () => {
  beforeEach(() => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "admin@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUserWithAccess);
    (prisma.fund.findUnique as jest.Mock).mockResolvedValue(mockFund);
  });

  it("updates ndaGateEnabled", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      ndaGateEnabled: true,
    });

    const { req, res } = makeMocks("PATCH", {
      body: { ndaGateEnabled: true },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const data = JSON.parse(res._getData());
    expect(data.fund.ndaGateEnabled).toBe(true);

    const updateCall = (prisma.fund.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.ndaGateEnabled).toBe(true);
  });

  it("updates capitalCallThreshold with parseFloat", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      capitalCallThresholdEnabled: true,
      capitalCallThreshold: 250000,
    });

    const { req, res } = makeMocks("PATCH", {
      body: { capitalCallThresholdEnabled: true, capitalCallThreshold: "250000" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const updateCall = (prisma.fund.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.capitalCallThreshold).toBe(250000);
  });

  it("sets capitalCallThreshold to null when falsy value provided", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      capitalCallThreshold: null,
    });

    const { req, res } = makeMocks("PATCH", {
      body: { capitalCallThreshold: "" },
    });
    await handler(req, res);

    const updateCall = (prisma.fund.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.capitalCallThreshold).toBeNull();
  });

  it("validates callFrequency enum", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      callFrequency: "QUARTERLY",
    });

    const { req, res } = makeMocks("PATCH", {
      body: { callFrequency: "QUARTERLY" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const updateCall = (prisma.fund.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.callFrequency).toBe("QUARTERLY");
  });

  it("rejects invalid callFrequency values", async () => {
    const { req, res } = makeMocks("PATCH", {
      body: { callFrequency: "WEEKLY" },
    });
    await handler(req, res);

    // WEEKLY is not in the allowed list, so it's not added to updateData
    // With no valid fields, should return 400
    expect(res._getStatusCode()).toBe(400);
    expect(JSON.parse(res._getData())).toMatchObject({ message: "No valid fields to update" });
  });

  it("returns 400 when no valid fields provided", async () => {
    const { req, res } = makeMocks("PATCH", {
      body: { unknownField: "value" },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(400);
    expect(JSON.parse(res._getData()).message).toBe("No valid fields to update");
  });

  it("creates audit log with previous and new settings", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      ndaGateEnabled: true,
    });

    const { req, res } = makeMocks("PATCH", {
      body: { ndaGateEnabled: true },
    });
    await handler(req, res);

    expect((prisma as any).auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          eventType: "FUND_SETTINGS_UPDATE",
          resourceType: "FUND",
          resourceId: "fund-1",
          metadata: expect.objectContaining({
            previousSettings: expect.objectContaining({
              ndaGateEnabled: false,
            }),
            newSettings: expect.objectContaining({
              ndaGateEnabled: true,
            }),
          }),
        }),
      })
    );
  });

  it("records IP address in audit log", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({ ...mockFund, ndaGateEnabled: true });

    const { req, res } = makeMocks("PATCH", {
      body: { ndaGateEnabled: true },
    });
    await handler(req, res);

    const auditCall = (prisma as any).auditLog.create.mock.calls[0][0];
    expect(auditCall.data.ipAddress).toBe("1.2.3.4");
    expect(auditCall.data.userAgent).toBe("test-agent");
  });

  it("updates multiple fields at once", async () => {
    (prisma.fund.update as jest.Mock).mockResolvedValue({
      ...mockFund,
      ndaGateEnabled: true,
      stagedCommitmentsEnabled: true,
      callFrequency: "ANNUAL",
    });

    const { req, res } = makeMocks("PATCH", {
      body: {
        ndaGateEnabled: true,
        stagedCommitmentsEnabled: true,
        callFrequency: "ANNUAL",
      },
    });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    const updateCall = (prisma.fund.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.ndaGateEnabled).toBe(true);
    expect(updateCall.data.stagedCommitmentsEnabled).toBe(true);
    expect(updateCall.data.callFrequency).toBe("ANNUAL");
  });
});
