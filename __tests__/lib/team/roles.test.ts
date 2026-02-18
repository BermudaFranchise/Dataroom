// @ts-nocheck
/**
 * Tests for lib/team/roles.ts
 * Covers: role hierarchy checks, label generation, edge cases
 */
import { isAdminRole, isSuperAdminRole, isOwnerRole, getRoleLabel } from "@/lib/team/roles";

describe("isAdminRole", () => {
  it("returns true for OWNER", () => {
    expect(isAdminRole("OWNER")).toBe(true);
  });

  it("returns true for SUPER_ADMIN", () => {
    expect(isAdminRole("SUPER_ADMIN")).toBe(true);
  });

  it("returns true for ADMIN", () => {
    expect(isAdminRole("ADMIN")).toBe(true);
  });

  it("returns false for MANAGER", () => {
    expect(isAdminRole("MANAGER")).toBe(false);
  });

  it("returns false for MEMBER", () => {
    expect(isAdminRole("MEMBER")).toBe(false);
  });

  it("returns false for empty string", () => {
    expect(isAdminRole("")).toBe(false);
  });

  it("returns false for lowercase variants (case-sensitive)", () => {
    expect(isAdminRole("admin")).toBe(false);
    expect(isAdminRole("owner")).toBe(false);
    expect(isAdminRole("Admin")).toBe(false);
  });

  it("returns false for unknown role strings", () => {
    expect(isAdminRole("SUPERUSER")).toBe(false);
    expect(isAdminRole("GP")).toBe(false);
    expect(isAdminRole("LP")).toBe(false);
  });
});

describe("isSuperAdminRole", () => {
  it("returns true only for SUPER_ADMIN", () => {
    expect(isSuperAdminRole("SUPER_ADMIN")).toBe(true);
  });

  it("returns false for OWNER", () => {
    expect(isSuperAdminRole("OWNER")).toBe(false);
  });

  it("returns false for ADMIN", () => {
    expect(isSuperAdminRole("ADMIN")).toBe(false);
  });

  it("returns false for MANAGER", () => {
    expect(isSuperAdminRole("MANAGER")).toBe(false);
  });

  it("returns false for MEMBER", () => {
    expect(isSuperAdminRole("MEMBER")).toBe(false);
  });
});

describe("isOwnerRole", () => {
  it("returns true only for OWNER", () => {
    expect(isOwnerRole("OWNER")).toBe(true);
  });

  it("returns false for SUPER_ADMIN", () => {
    expect(isOwnerRole("SUPER_ADMIN")).toBe(false);
  });

  it("returns false for ADMIN", () => {
    expect(isOwnerRole("ADMIN")).toBe(false);
  });

  it("returns false for MANAGER", () => {
    expect(isOwnerRole("MANAGER")).toBe(false);
  });

  it("returns false for MEMBER", () => {
    expect(isOwnerRole("MEMBER")).toBe(false);
  });
});

describe("getRoleLabel", () => {
  it("returns 'Owner' for OWNER", () => {
    expect(getRoleLabel("OWNER")).toBe("Owner");
  });

  it("returns 'Super Admin' for SUPER_ADMIN", () => {
    expect(getRoleLabel("SUPER_ADMIN")).toBe("Super Admin");
  });

  it("returns 'Admin' for ADMIN", () => {
    expect(getRoleLabel("ADMIN")).toBe("Admin");
  });

  it("returns 'Manager' for MANAGER", () => {
    expect(getRoleLabel("MANAGER")).toBe("Manager");
  });

  it("returns 'Member' for MEMBER", () => {
    expect(getRoleLabel("MEMBER")).toBe("Member");
  });

  it("returns lowercase for unknown roles", () => {
    expect(getRoleLabel("GP_VIEWER")).toBe("gp_viewer");
  });

  it("handles empty string", () => {
    expect(getRoleLabel("")).toBe("");
  });
});
