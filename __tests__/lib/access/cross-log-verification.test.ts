// @ts-nocheck
/**
 * Tests for lib/access/cross-log-verification.ts
 * Covers: SEC compliance access checks, multi-source access aggregation, revocation impact
 */
import prisma from "@/lib/prisma";
import {
  checkCrossLogAccess,
  getAccessRevokeImpact,
  verifyBeforeGrantingAccess,
  reactivateViewerAccess,
} from "@/lib/access/cross-log-verification";

// Extend prisma mock with required sub-models
(prisma.viewer as any).update = jest.fn();

beforeEach(() => {
  jest.clearAllMocks();
});

describe("checkCrossLogAccess", () => {
  it("returns no access when viewer does not exist", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue(null);

    const result = await checkCrossLogAccess("team-1", "unknown@example.com");

    expect(result.hasAccess).toBe(false);
    expect(result.viewer).toBeNull();
    expect(result.totalViews).toBe(0);
    expect(result.lastViewedAt).toBeNull();
    expect(result.accessLocations.datarooms).toEqual([]);
    expect(result.accessLocations.links).toEqual([]);
    expect(result.accessLocations.groups).toEqual([]);
  });

  it("normalizes email to lowercase and trims", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue(null);

    await checkCrossLogAccess("team-1", "  Test@Example.COM  ");

    const call = (prisma.viewer.findUnique as jest.Mock).mock.calls[0][0];
    expect(call.where.teamId_email.email).toBe("test@example.com");
    expect(call.where.teamId_email.teamId).toBe("team-1");
  });

  it("aggregates direct dataroom access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "test@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: { id: "dr-1", name: "Main Dataroom" },
      groups: [],
      views: [{ id: "v-1", viewedAt: new Date("2024-06-15") }],
      invitations: [],
      _count: { views: 5 },
    });

    const result = await checkCrossLogAccess("team-1", "test@example.com");

    expect(result.hasAccess).toBe(true);
    expect(result.accessLocations.datarooms).toEqual([{ id: "dr-1", name: "Main Dataroom" }]);
    expect(result.totalViews).toBe(5);
    expect(result.lastViewedAt).toEqual(new Date("2024-06-15"));
  });

  it("aggregates group-based dataroom access (no duplicates)", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "test@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: { id: "dr-1", name: "Direct DR" },
      groups: [
        {
          group: {
            id: "grp-1",
            name: "Partners",
            dataroom: { id: "dr-1", name: "Direct DR" }, // same as direct
            links: [{ id: "link-1", name: "Partner Link" }],
          },
        },
        {
          group: {
            id: "grp-2",
            name: "Board",
            dataroom: { id: "dr-2", name: "Board DR" },
            links: [{ id: "link-2", name: "Board Link" }],
          },
        },
      ],
      views: [],
      invitations: [],
      _count: { views: 0 },
    });

    const result = await checkCrossLogAccess("team-1", "test@example.com");

    // dr-1 should appear once (deduped from direct + group)
    expect(result.accessLocations.datarooms).toHaveLength(2);
    expect(result.accessLocations.datarooms).toContainEqual({ id: "dr-1", name: "Direct DR" });
    expect(result.accessLocations.datarooms).toContainEqual({ id: "dr-2", name: "Board DR" });

    // Groups
    expect(result.accessLocations.groups).toHaveLength(2);
    expect(result.accessLocations.groups[0].name).toBe("Partners");
    expect(result.accessLocations.groups[1].name).toBe("Board");

    // Links from groups
    expect(result.accessLocations.links).toHaveLength(2);
    expect(result.accessLocations.links).toContainEqual({ id: "link-1", name: "Partner Link", accessType: "group" });
  });

  it("aggregates invitation-based link access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "test@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: null,
      groups: [],
      views: [],
      invitations: [
        { link: { id: "link-inv-1", name: "Invited Link" } },
        { link: { id: "link-inv-2", name: "Second Invite" } },
      ],
      _count: { views: 3 },
    });

    const result = await checkCrossLogAccess("team-1", "test@example.com");

    expect(result.accessLocations.links).toHaveLength(2);
    expect(result.accessLocations.links[0].accessType).toBe("invitation");
    expect(result.accessLocations.links[1].accessType).toBe("invitation");
  });

  it("deduplicates links from invitations and groups", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "test@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: null,
      groups: [
        {
          group: {
            id: "grp-1",
            name: "G1",
            dataroom: { id: "dr-1", name: "DR1" },
            links: [{ id: "link-shared", name: "Shared Link" }],
          },
        },
      ],
      views: [],
      invitations: [
        { link: { id: "link-shared", name: "Shared Link" } }, // same link
      ],
      _count: { views: 0 },
    });

    const result = await checkCrossLogAccess("team-1", "test@example.com");

    // link-shared should appear only once (invitation takes priority in map)
    expect(result.accessLocations.links).toHaveLength(1);
    expect(result.accessLocations.links[0].id).toBe("link-shared");
    expect(result.accessLocations.links[0].accessType).toBe("invitation");
  });

  it("returns hasAccess=false when accessRevokedAt is set", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "test@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: new Date("2024-06-01"),
      dataroom: { id: "dr-1", name: "DR" },
      groups: [],
      views: [],
      invitations: [],
      _count: { views: 10 },
    });

    const result = await checkCrossLogAccess("team-1", "test@example.com");

    expect(result.hasAccess).toBe(false);
    expect(result.viewer).not.toBeNull();
    expect(result.viewer!.accessRevokedAt).toEqual(new Date("2024-06-01"));
    expect(result.totalViews).toBe(10); // Views preserved even after revocation
  });
});

describe("getAccessRevokeImpact", () => {
  it("returns defaults when viewer not found", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue(null);

    const result = await getAccessRevokeImpact("team-1", "viewer-unknown");

    expect(result.viewer).toBeNull();
    expect(result.documentsAccessed).toBe(0);
    expect(result.dataRoomsAccessed).toEqual([]);
    expect(result.willLoseAllAccess).toBe(true);
    expect(result.auditTrailPreserved).toBe(true);
  });

  it("counts unique documents and datarooms accessed", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "user@test.com",
      teamId: "team-1",
      views: [
        { documentId: "doc-1", dataroomId: "dr-1" },
        { documentId: "doc-2", dataroomId: "dr-1" },
        { documentId: "doc-3", dataroomId: "dr-2" },
      ],
      _count: { views: 15 },
    });

    (prisma.dataroom.findMany as jest.Mock).mockResolvedValue([
      { name: "Dataroom Alpha" },
      { name: "Dataroom Beta" },
    ]);

    const result = await getAccessRevokeImpact("team-1", "viewer-1");

    expect(result.viewer).toEqual({ email: "user@test.com", totalViews: 15 });
    expect(result.documentsAccessed).toBe(3);
    expect(result.dataRoomsAccessed).toEqual(["Dataroom Alpha", "Dataroom Beta"]);
    expect(result.auditTrailPreserved).toBe(true);
  });

  it("filters out null documentIds and dataroomIds", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "user@test.com",
      views: [
        { documentId: null, dataroomId: "dr-1" },
        { documentId: "doc-1", dataroomId: null },
        { documentId: null, dataroomId: null },
      ],
      _count: { views: 3 },
    });

    (prisma.dataroom.findMany as jest.Mock).mockResolvedValue([{ name: "DR1" }]);

    const result = await getAccessRevokeImpact("team-1", "viewer-1");

    expect(result.documentsAccessed).toBe(1); // Only doc-1
    expect(result.dataRoomsAccessed).toEqual(["DR1"]); // Only dr-1
  });

  it("handles viewer with no views", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "user@test.com",
      views: [],
      _count: { views: 0 },
    });

    const result = await getAccessRevokeImpact("team-1", "viewer-1");

    expect(result.documentsAccessed).toBe(0);
    expect(result.dataRoomsAccessed).toEqual([]);
    // Should NOT call dataroom.findMany with empty array
    expect(prisma.dataroom.findMany).not.toHaveBeenCalled();
  });
});

describe("verifyBeforeGrantingAccess", () => {
  it("returns safe-to-grant for new viewer", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue(null);

    const result = await verifyBeforeGrantingAccess("team-1", "new@example.com");

    expect(result.alreadyHasAccess).toBe(false);
    expect(result.recommendation).toContain("New viewer");
  });

  it("detects existing dataroom access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "existing@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: { id: "dr-target", name: "Target DR" },
      groups: [],
      views: [],
      invitations: [],
      _count: { views: 0 },
    });

    const result = await verifyBeforeGrantingAccess("team-1", "existing@example.com", "dr-target");

    expect(result.alreadyHasAccess).toBe(true);
    expect(result.recommendation).toContain("already has this access");
  });

  it("detects existing group access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "existing@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: null,
      groups: [
        {
          group: {
            id: "grp-target",
            name: "Target Group",
            dataroom: { id: "dr-1", name: "DR" },
            links: [],
          },
        },
      ],
      views: [],
      invitations: [],
      _count: { views: 0 },
    });

    const result = await verifyBeforeGrantingAccess("team-1", "existing@example.com", undefined, "grp-target");

    expect(result.alreadyHasAccess).toBe(true);
    expect(result.recommendation).toContain("already has this access");
  });

  it("warns about previously revoked access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "revoked@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: new Date("2024-06-01"),
      dataroom: null,
      groups: [],
      views: [],
      invitations: [],
      _count: { views: 0 },
    });

    const result = await verifyBeforeGrantingAccess("team-1", "revoked@example.com", "dr-new");

    expect(result.alreadyHasAccess).toBe(false);
    expect(result.recommendation).toContain("previously revoked");
    expect(result.recommendation).toContain("reactivating");
  });

  it("reports existing access to other resources when granting new access", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "active@example.com",
      createdAt: new Date("2024-01-01"),
      accessRevokedAt: null,
      dataroom: { id: "dr-other", name: "Other DR" },
      groups: [],
      views: [],
      invitations: [],
      _count: { views: 0 },
    });

    const result = await verifyBeforeGrantingAccess("team-1", "active@example.com", "dr-new");

    expect(result.alreadyHasAccess).toBe(true); // has access (to other things)
    expect(result.recommendation).toContain("extending access");
  });
});

describe("reactivateViewerAccess", () => {
  it("reactivates revoked viewer successfully", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "revoked@example.com",
      accessRevokedAt: new Date("2024-06-01"),
    });

    (prisma.viewer.update as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "revoked@example.com",
    });

    const result = await reactivateViewerAccess("team-1", "viewer-1", "admin-1", "Investor cleared");

    expect(result.success).toBe(true);
    expect(result.viewer).toEqual({ id: "viewer-1", email: "revoked@example.com" });
    expect(result.error).toBeUndefined();

    // Verify update clears revocation fields
    const updateCall = (prisma.viewer.update as jest.Mock).mock.calls[0][0];
    expect(updateCall.data.accessRevokedAt).toBeNull();
    expect(updateCall.data.accessRevokedBy).toBeNull();
    expect(updateCall.data.accessRevokedReason).toBeNull();
  });

  it("fails when viewer not found", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue(null);

    const result = await reactivateViewerAccess("team-1", "viewer-unknown", "admin-1");

    expect(result.success).toBe(false);
    expect(result.viewer).toBeNull();
    expect(result.error).toBe("Viewer not found");
  });

  it("fails when viewer access is not revoked", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockResolvedValue({
      id: "viewer-1",
      email: "active@example.com",
      accessRevokedAt: null,
    });

    const result = await reactivateViewerAccess("team-1", "viewer-1", "admin-1");

    expect(result.success).toBe(false);
    expect(result.error).toBe("Access is not revoked");
    expect(result.viewer).toEqual({ id: "viewer-1", email: "active@example.com" });
  });

  it("handles database error gracefully", async () => {
    (prisma.viewer.findUnique as jest.Mock).mockRejectedValue(new Error("DB connection lost"));

    const result = await reactivateViewerAccess("team-1", "viewer-1", "admin-1");

    expect(result.success).toBe(false);
    expect(result.error).toBe("Failed to reactivate access");
  });
});
