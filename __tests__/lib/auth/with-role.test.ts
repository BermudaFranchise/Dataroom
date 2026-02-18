// @ts-nocheck
/**
 * Tests for lib/auth/with-role.ts
 * Covers: getUserWithRole, requireRole, filterByInvestorIfLP
 */
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

jest.mock("@/lib/auth/auth-options", () => ({
  authOptions: { providers: [], session: { strategy: "jwt" } },
}));

// Override the next-auth mock for this specific module
jest.mock("next-auth/next", () => ({
  getServerSession: jest.fn(),
}));

import prisma from "@/lib/prisma";
import { getServerSession } from "next-auth/next";
import { getUserWithRole, requireRole, filterByInvestorIfLP } from "@/lib/auth/with-role";

beforeEach(() => {
  jest.clearAllMocks();
});

describe("getUserWithRole", () => {
  function makeMocks() {
    return createMocks<NextApiRequest, NextApiResponse>();
  }

  it("returns 401 when session is null", async () => {
    (getServerSession as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user).toBeNull();
    expect(result.error).toBe("Not authenticated");
    expect(result.statusCode).toBe(401);
  });

  it("returns 401 when session has no email", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { id: "u1" } });

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user).toBeNull();
    expect(result.statusCode).toBe(401);
  });

  it("returns 404 when user not found in DB", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "ghost@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user).toBeNull();
    expect(result.error).toBe("User not found");
    expect(result.statusCode).toBe(404);
  });

  it("returns user with GP role and team IDs", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "gp@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-1",
      email: "gp@test.com",
      role: "GP",
      investorProfile: null,
      teams: [{ teamId: "team-1" }, { teamId: "team-2" }],
    });

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user).not.toBeNull();
    expect(result.user!.id).toBe("user-1");
    expect(result.user!.email).toBe("gp@test.com");
    expect(result.user!.role).toBe("GP");
    expect(result.user!.teamIds).toEqual(["team-1", "team-2"]);
    expect(result.user!.investorId).toBeUndefined();
    expect(result.error).toBeUndefined();
    expect(result.statusCode).toBeUndefined();
  });

  it("returns user with LP role and investor ID", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "lp@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-2",
      email: "lp@test.com",
      role: "LP",
      investorProfile: { id: "inv-1" },
      teams: [{ teamId: "team-1" }],
    });

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user!.role).toBe("LP");
    expect(result.user!.investorId).toBe("inv-1");
  });

  it("returns empty teamIds when user has no teams", async () => {
    (getServerSession as jest.Mock).mockResolvedValue({ user: { email: "lonely@test.com" } });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-3",
      email: "lonely@test.com",
      role: "GP",
      investorProfile: null,
      teams: [],
    });

    const { req, res } = makeMocks();
    const result = await getUserWithRole(req, res);

    expect(result.user!.teamIds).toEqual([]);
  });
});

describe("requireRole", () => {
  it("allows when user has required role", () => {
    const result = requireRole(["GP"], {
      user: { id: "u1", email: "e", role: "GP", teamIds: [] },
    });

    expect(result.allowed).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("allows when user has one of multiple required roles", () => {
    const result = requireRole(["GP", "LP"], {
      user: { id: "u1", email: "e", role: "LP", teamIds: [] },
    });

    expect(result.allowed).toBe(true);
  });

  it("denies when user role not in allowed list", () => {
    const result = requireRole(["GP"], {
      user: { id: "u1", email: "e", role: "LP", teamIds: [] },
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe("Insufficient permissions");
    expect(result.statusCode).toBe(403);
  });

  it("denies when user is null (not authenticated)", () => {
    const result = requireRole(["GP"], {
      user: null,
      error: "Not authenticated",
      statusCode: 401,
    });

    expect(result.allowed).toBe(false);
    expect(result.error).toBe("Not authenticated");
    expect(result.statusCode).toBe(401);
  });
});

describe("filterByInvestorIfLP", () => {
  it("adds investorId to where clause for LP users", () => {
    const user = { id: "u1", email: "e", role: "LP" as const, investorId: "inv-1", teamIds: [] };
    const where = { fundId: "fund-1" };

    const result = filterByInvestorIfLP(user, where);

    expect(result).toEqual({ fundId: "fund-1", investorId: "inv-1" });
  });

  it("does not add investorId for GP users", () => {
    const user = { id: "u1", email: "e", role: "GP" as const, teamIds: [] };
    const where = { fundId: "fund-1" };

    const result = filterByInvestorIfLP(user, where);

    expect(result).toEqual({ fundId: "fund-1" });
    expect(result.investorId).toBeUndefined();
  });

  it("does not add investorId for LP without investorId", () => {
    const user = { id: "u1", email: "e", role: "LP" as const, teamIds: [] };
    const where = { fundId: "fund-1" };

    const result = filterByInvestorIfLP(user, where);

    expect(result).toEqual({ fundId: "fund-1" });
  });

  it("does not mutate the original where clause", () => {
    const user = { id: "u1", email: "e", role: "LP" as const, investorId: "inv-1", teamIds: [] };
    const where = { fundId: "fund-1" };

    filterByInvestorIfLP(user, where);

    expect(where).toEqual({ fundId: "fund-1" });
  });
});
