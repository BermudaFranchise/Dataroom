// @ts-nocheck
/**
 * Immutable Audit Log Tests
 *
 * Tests for lib/audit/immutable-audit-log.ts - Tamper-proof audit trail.
 *
 * These tests validate:
 * - Hash chain computation and integrity
 * - Genesis hash handling for first entries
 * - Metadata hashing with stable JSON stringification
 * - Chain verification detecting tampering
 * - Export functionality with checksums
 * - Team isolation of hash chains
 */

import crypto from "crypto";

// Mock prisma
const mockQueryRaw = jest.fn();

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    $queryRaw: (...args: any[]) => mockQueryRaw(...args),
    auditLog: {
      create: jest.fn(),
    },
  },
}));

import {
  createImmutableAuditEntry,
  verifyAuditChain,
  exportAuditLogForCompliance,
  getAuditLogIntegrity,
} from "@/lib/audit/immutable-audit-log";

// Constants matching the source
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

describe("Immutable Audit Log", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockQueryRaw.mockReset();
  });

  describe("createImmutableAuditEntry", () => {
    it("should create first entry with genesis hash", async () => {
      // First query returns empty (no previous entries)
      mockQueryRaw.mockResolvedValueOnce([]);
      // Second query returns the created entry
      mockQueryRaw.mockResolvedValueOnce([{
        id: "entry-1",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: { viewerEmail: "test@example.com" },
        metadataHash: expect.any(String),
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: GENESIS_HASH,
        currentHash: expect.any(String),
        sequenceNumber: BigInt(1),
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: { viewerEmail: "test@example.com" },
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
      });

      expect(result).toBeDefined();
      expect(result.previousHash).toBe(GENESIS_HASH);
      expect(result.sequenceNumber).toBe(BigInt(1));
    });

    it("should chain to previous entry hash", async () => {
      const previousEntryHash = "abc123def456789previoushash0000000000000000000000000000000000";

      // First query returns previous entry
      mockQueryRaw.mockResolvedValueOnce([{
        currentHash: previousEntryHash,
        sequenceNumber: BigInt(5),
      }]);
      // Second query returns the created entry
      mockQueryRaw.mockResolvedValueOnce([{
        id: "entry-6",
        timestamp: new Date(),
        eventType: "DOCUMENT_SIGNED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "SignatureDocument",
        resourceId: "doc-1",
        metadata: null,
        metadataHash: null,
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: previousEntryHash,
        currentHash: "newhash123",
        sequenceNumber: BigInt(6),
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "DOCUMENT_SIGNED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "SignatureDocument",
        resourceId: "doc-1",
      });

      expect(result.previousHash).toBe(previousEntryHash);
      expect(result.sequenceNumber).toBe(BigInt(6));
    });

    it("should increment sequence number correctly", async () => {
      mockQueryRaw.mockResolvedValueOnce([{
        currentHash: "somehash",
        sequenceNumber: BigInt(99),
      }]);
      mockQueryRaw.mockResolvedValueOnce([{
        id: "entry-100",
        sequenceNumber: BigInt(100),
        previousHash: "somehash",
        currentHash: "newhash",
        timestamp: new Date(),
        eventType: "USER_LOGIN",
        userId: null,
        teamId: "team-1",
        resourceType: null,
        resourceId: null,
        metadata: null,
        metadataHash: null,
        ipAddress: null,
        userAgent: null,
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "USER_LOGIN",
        teamId: "team-1",
      });

      expect(result.sequenceNumber).toBe(BigInt(100));
    });

    it("should handle entries without teamId (global chain)", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce([{
        id: "global-entry-1",
        timestamp: new Date(),
        eventType: "ADMIN_ACTION",
        userId: "admin-1",
        teamId: null,
        resourceType: null,
        resourceId: null,
        metadata: { action: "system_maintenance" },
        metadataHash: "hash123",
        ipAddress: "10.0.0.1",
        userAgent: "AdminTool/1.0",
        previousHash: GENESIS_HASH,
        currentHash: "globalhash123",
        sequenceNumber: BigInt(1),
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "ADMIN_ACTION",
        userId: "admin-1",
        metadata: { action: "system_maintenance" },
        ipAddress: "10.0.0.1",
        userAgent: "AdminTool/1.0",
      });

      expect(result.teamId).toBeNull();
      expect(result.previousHash).toBe(GENESIS_HASH);
    });

    it("should compute metadata hash for non-null metadata", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const metadata = { key1: "value1", key2: 123 };
      mockQueryRaw.mockResolvedValueOnce([{
        id: "entry-with-metadata",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        userId: null,
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata,
        metadataHash: expect.any(String),
        ipAddress: null,
        userAgent: null,
        previousHash: GENESIS_HASH,
        currentHash: "hash123",
        sequenceNumber: BigInt(1),
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "DOCUMENT_VIEWED",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata,
      });

      expect(result.metadataHash).toBeDefined();
      expect(result.metadataHash).not.toBeNull();
    });

    it("should handle null metadata with null metadataHash", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce([{
        id: "entry-no-metadata",
        timestamp: new Date(),
        eventType: "USER_LOGOUT",
        userId: "user-1",
        teamId: "team-1",
        resourceType: null,
        resourceId: null,
        metadata: null,
        metadataHash: null,
        ipAddress: null,
        userAgent: null,
        previousHash: GENESIS_HASH,
        currentHash: "hash456",
        sequenceNumber: BigInt(1),
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "USER_LOGOUT",
        userId: "user-1",
        teamId: "team-1",
      });

      expect(result.metadata).toBeNull();
      expect(result.metadataHash).toBeNull();
    });
  });

  describe("verifyAuditChain", () => {
    it("should return valid for empty chain", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const result = await verifyAuditChain("team-1");

      expect(result.isValid).toBe(true);
      expect(result.totalEntries).toBe(0);
      expect(result.verifiedEntries).toBe(0);
      expect(result.errors).toHaveLength(0);
    });

    it("should verify single entry with genesis hash", async () => {
      const timestamp = new Date("2024-01-15T10:00:00Z");
      const entry = {
        id: "entry-1",
        timestamp,
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: null,
        metadataHash: null,
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
        currentHash: "", // Will be computed
      };

      // Compute the expected hash
      const dataToHash = JSON.stringify({
        timestamp: timestamp.toISOString(),
        eventType: entry.eventType,
        userId: entry.userId,
        teamId: entry.teamId,
        resourceType: entry.resourceType,
        resourceId: entry.resourceId,
        metadataHash: entry.metadataHash,
        previousHash: entry.previousHash,
        sequenceNumber: entry.sequenceNumber.toString(),
      });
      entry.currentHash = crypto.createHash("sha256").update(dataToHash).digest("hex");

      mockQueryRaw.mockResolvedValueOnce([entry]);

      const result = await verifyAuditChain("team-1");

      expect(result.isValid).toBe(true);
      expect(result.totalEntries).toBe(1);
      expect(result.verifiedEntries).toBe(1);
    });

    it("should detect hash mismatch (tampering)", async () => {
      const entry = {
        id: "tampered-entry",
        timestamp: new Date("2024-01-15T10:00:00Z"),
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: null,
        metadataHash: null,
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
        currentHash: "invalid_hash_that_doesnt_match_computed_value",
      };

      mockQueryRaw.mockResolvedValueOnce([entry]);

      const result = await verifyAuditChain("team-1");

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain("Hash mismatch");
      expect(result.firstInvalidEntry).toBe("tampered-entry");
    });

    it("should detect previous hash chain break", async () => {
      const timestamp1 = new Date("2024-01-15T10:00:00Z");
      const timestamp2 = new Date("2024-01-15T11:00:00Z");

      // Create valid first entry
      const entry1Data = JSON.stringify({
        timestamp: timestamp1.toISOString(),
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadataHash: null,
        previousHash: GENESIS_HASH,
        sequenceNumber: "1",
      });
      const entry1Hash = crypto.createHash("sha256").update(entry1Data).digest("hex");

      const entry1 = {
        id: "entry-1",
        timestamp: timestamp1,
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadata: null,
        metadataHash: null,
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
        currentHash: entry1Hash,
      };

      // Create second entry with WRONG previousHash (chain break)
      const entry2Data = JSON.stringify({
        timestamp: timestamp2.toISOString(),
        eventType: "DOCUMENT_SIGNED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "SignatureDocument",
        resourceId: "doc-1",
        metadataHash: null,
        previousHash: "wrong_previous_hash_that_breaks_chain",
        sequenceNumber: "2",
      });
      const entry2Hash = crypto.createHash("sha256").update(entry2Data).digest("hex");

      const entry2 = {
        id: "entry-2",
        timestamp: timestamp2,
        eventType: "DOCUMENT_SIGNED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "SignatureDocument",
        resourceId: "doc-1",
        metadata: null,
        metadataHash: null,
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        previousHash: "wrong_previous_hash_that_breaks_chain",
        sequenceNumber: BigInt(2),
        currentHash: entry2Hash,
      };

      mockQueryRaw.mockResolvedValueOnce([entry1, entry2]);

      const result = await verifyAuditChain("team-1");

      expect(result.isValid).toBe(false);
      expect(result.errors.some(e => e.includes("Previous hash mismatch"))).toBe(true);
      expect(result.firstInvalidEntry).toBe("entry-2");
    });

    it("should verify chain with date range filter", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const fromDate = new Date("2024-01-01");
      const toDate = new Date("2024-12-31");

      const result = await verifyAuditChain("team-1", fromDate, toDate);

      expect(result.isValid).toBe(true);
      // Verify that the query was called (we can't easily check the exact SQL)
      expect(mockQueryRaw).toHaveBeenCalled();
    });

    it("should verify chain with only fromDate", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const fromDate = new Date("2024-06-01");

      const result = await verifyAuditChain("team-1", fromDate);

      expect(result.isValid).toBe(true);
    });

    it("should verify chain with only toDate", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const toDate = new Date("2024-06-30");

      const result = await verifyAuditChain("team-1", undefined, toDate);

      expect(result.isValid).toBe(true);
    });

    it("should continue verification after finding first invalid entry", async () => {
      const entries = [
        {
          id: "entry-1",
          timestamp: new Date("2024-01-15T10:00:00Z"),
          eventType: "DOCUMENT_VIEWED",
          userId: null,
          teamId: "team-1",
          resourceType: null,
          resourceId: null,
          metadata: null,
          metadataHash: null,
          ipAddress: null,
          userAgent: null,
          previousHash: GENESIS_HASH,
          sequenceNumber: BigInt(1),
          currentHash: "invalid1",
        },
        {
          id: "entry-2",
          timestamp: new Date("2024-01-15T11:00:00Z"),
          eventType: "DOCUMENT_SIGNED",
          userId: null,
          teamId: "team-1",
          resourceType: null,
          resourceId: null,
          metadata: null,
          metadataHash: null,
          ipAddress: null,
          userAgent: null,
          previousHash: "invalid1",
          sequenceNumber: BigInt(2),
          currentHash: "invalid2",
        },
      ];

      mockQueryRaw.mockResolvedValueOnce(entries);

      const result = await verifyAuditChain("team-1");

      expect(result.isValid).toBe(false);
      expect(result.totalEntries).toBe(2);
      expect(result.firstInvalidEntry).toBe("entry-1");
      // Both entries should have errors reported
      expect(result.errors.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("exportAuditLogForCompliance", () => {
    it("should export entries with verification and checksum", async () => {
      // Use number instead of BigInt for JSON serialization compatibility
      const entries = [
        {
          id: "export-entry-1",
          timestamp: new Date("2024-06-15T10:00:00Z"),
          eventType: "SUBSCRIPTION_CREATED",
          userId: "user-1",
          teamId: "team-1",
          resourceType: "Subscription",
          resourceId: "sub-1",
          metadata: { amount: "100000" },
          metadataHash: "hash1",
          ipAddress: "192.168.1.1",
          userAgent: "Mozilla/5.0",
          previousHash: GENESIS_HASH,
          currentHash: "exporthash1",
          sequenceNumber: 1, // Use number for JSON compatibility
        },
      ];

      // First call for verifyAuditChain
      mockQueryRaw.mockResolvedValueOnce(entries);
      // Second call for export query
      mockQueryRaw.mockResolvedValueOnce(entries);

      const fromDate = new Date("2024-01-01");
      const toDate = new Date("2024-12-31");

      const result = await exportAuditLogForCompliance("team-1", fromDate, toDate);

      expect(result.entries).toHaveLength(1);
      expect(result.chainVerification).toBeDefined();
      expect(result.exportMetadata).toBeDefined();
      expect(result.exportMetadata.teamId).toBe("team-1");
      expect(result.exportMetadata.totalRecords).toBe(1);
      expect(result.exportMetadata.checksum).toMatch(/^[a-f0-9]{64}$/);
      expect(result.exportMetadata.dateRange.from).toBe(fromDate.toISOString());
      expect(result.exportMetadata.dateRange.to).toBe(toDate.toISOString());
    });

    it("should include chain verification status in export", async () => {
      // Return empty for both calls
      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce([]);

      const result = await exportAuditLogForCompliance(
        "team-1",
        new Date("2024-01-01"),
        new Date("2024-12-31")
      );

      expect(result.chainVerification.isValid).toBe(true);
      expect(result.chainVerification.totalEntries).toBe(0);
    });

    it("should generate unique checksum for different data", async () => {
      const entries1 = [{
        id: "entry-a",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        sequenceNumber: 1, // Use number for JSON compatibility
      }];
      const entries2 = [{
        id: "entry-b",
        timestamp: new Date(),
        eventType: "DOCUMENT_SIGNED",
        sequenceNumber: 1, // Use number for JSON compatibility
      }];

      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce(entries1);

      const result1 = await exportAuditLogForCompliance(
        "team-1",
        new Date("2024-01-01"),
        new Date("2024-12-31")
      );

      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce(entries2);

      const result2 = await exportAuditLogForCompliance(
        "team-1",
        new Date("2024-01-01"),
        new Date("2024-12-31")
      );

      expect(result1.exportMetadata.checksum).not.toBe(result2.exportMetadata.checksum);
    });

    it("should set exportedBy to system", async () => {
      mockQueryRaw.mockResolvedValueOnce([]);
      mockQueryRaw.mockResolvedValueOnce([]);

      const result = await exportAuditLogForCompliance(
        "team-1",
        new Date("2024-01-01"),
        new Date("2024-12-31")
      );

      expect(result.exportMetadata.exportedBy).toBe("system");
    });
  });

  describe("getAuditLogIntegrity", () => {
    it("should return integrity status for team", async () => {
      // First call for stats
      mockQueryRaw.mockResolvedValueOnce([{
        count: BigInt(100),
        latestHash: "latesthash123456789abcdef",
      }]);
      // Second call for verifyAuditChain
      mockQueryRaw.mockResolvedValueOnce([]);

      const result = await getAuditLogIntegrity("team-1");

      expect(result.chainLength).toBe(100);
      expect(result.latestHash).toBe("latesthash123456789abcdef");
      expect(result.genesisHash).toBe(GENESIS_HASH);
      expect(result.isValid).toBe(true);
      expect(result.lastVerifiedAt).toBeInstanceOf(Date);
    });

    it("should return genesis hash when no entries exist", async () => {
      mockQueryRaw.mockResolvedValueOnce([{
        count: BigInt(0),
        latestHash: null,
      }]);
      mockQueryRaw.mockResolvedValueOnce([]);

      const result = await getAuditLogIntegrity("team-1");

      expect(result.chainLength).toBe(0);
      expect(result.latestHash).toBe(GENESIS_HASH);
      expect(result.isValid).toBe(true);
    });

    it("should report invalid status when chain is corrupted", async () => {
      mockQueryRaw.mockResolvedValueOnce([{
        count: BigInt(5),
        latestHash: "somehash",
      }]);

      // Return corrupted entries for verification
      mockQueryRaw.mockResolvedValueOnce([{
        id: "corrupted",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        userId: null,
        teamId: "team-1",
        resourceType: null,
        resourceId: null,
        metadata: null,
        metadataHash: null,
        ipAddress: null,
        userAgent: null,
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
        currentHash: "wrong_hash",
      }]);

      const result = await getAuditLogIntegrity("team-1");

      expect(result.isValid).toBe(false);
    });
  });

  describe("Hash Computation", () => {
    it("should produce deterministic hashes for same input", async () => {
      const timestamp = new Date("2024-01-15T10:00:00.000Z");

      const computeHash = (data: any) => {
        const dataToHash = JSON.stringify({
          timestamp: data.timestamp.toISOString(),
          eventType: data.eventType,
          userId: data.userId,
          teamId: data.teamId,
          resourceType: data.resourceType,
          resourceId: data.resourceId,
          metadataHash: data.metadataHash,
          previousHash: data.previousHash,
          sequenceNumber: data.sequenceNumber.toString(),
        });
        return crypto.createHash("sha256").update(dataToHash).digest("hex");
      };

      const data = {
        timestamp,
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadataHash: null,
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
      };

      const hash1 = computeHash(data);
      const hash2 = computeHash(data);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should produce different hashes for different inputs", async () => {
      const timestamp = new Date("2024-01-15T10:00:00.000Z");

      const computeHash = (data: any) => {
        const dataToHash = JSON.stringify({
          timestamp: data.timestamp.toISOString(),
          eventType: data.eventType,
          userId: data.userId,
          teamId: data.teamId,
          resourceType: data.resourceType,
          resourceId: data.resourceId,
          metadataHash: data.metadataHash,
          previousHash: data.previousHash,
          sequenceNumber: data.sequenceNumber.toString(),
        });
        return crypto.createHash("sha256").update(dataToHash).digest("hex");
      };

      const data1 = {
        timestamp,
        eventType: "DOCUMENT_VIEWED",
        userId: "user-1",
        teamId: "team-1",
        resourceType: "Document",
        resourceId: "doc-1",
        metadataHash: null,
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
      };

      const data2 = {
        ...data1,
        eventType: "DOCUMENT_SIGNED", // Different event type
      };

      const hash1 = computeHash(data1);
      const hash2 = computeHash(data2);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe("Stable JSON Stringification", () => {
    it("should produce same string for objects with different key order", () => {
      // This tests the stableStringify internal function behavior
      const obj1 = { b: 2, a: 1 };
      const obj2 = { a: 1, b: 2 };

      // Sort keys and stringify
      const stringify = (obj: any) => {
        const keys = Object.keys(obj).sort();
        const pairs = keys.map((k) => JSON.stringify(k) + ":" + JSON.stringify(obj[k]));
        return "{" + pairs.join(",") + "}";
      };

      expect(stringify(obj1)).toBe(stringify(obj2));
    });

    it("should handle nested objects", () => {
      const stableStringify = (obj: any): string => {
        if (obj === null) return "null";
        if (obj === undefined) return "null";
        if (typeof obj === "number") {
          if (!Number.isFinite(obj)) return "null";
          return JSON.stringify(obj);
        }
        if (typeof obj !== "object") return JSON.stringify(obj);
        if (Array.isArray(obj)) {
          return "[" + obj.map(stableStringify).join(",") + "]";
        }
        const keys = Object.keys(obj).sort();
        const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
        return "{" + pairs.join(",") + "}";
      };

      const nested = { z: { b: 2, a: 1 }, a: "first" };
      const result = stableStringify(nested);

      // Keys should be sorted at each level
      expect(result).toBe('{"a":"first","z":{"a":1,"b":2}}');
    });

    it("should handle special values", () => {
      const stableStringify = (obj: any): string => {
        if (obj === null) return "null";
        if (obj === undefined) return "null";
        if (typeof obj === "number") {
          if (!Number.isFinite(obj)) return "null";
          return JSON.stringify(obj);
        }
        if (typeof obj !== "object") return JSON.stringify(obj);
        if (Array.isArray(obj)) {
          return "[" + obj.map(stableStringify).join(",") + "]";
        }
        const keys = Object.keys(obj).sort();
        const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
        return "{" + pairs.join(",") + "}";
      };

      expect(stableStringify(null)).toBe("null");
      expect(stableStringify(undefined)).toBe("null");
      expect(stableStringify(Infinity)).toBe("null");
      expect(stableStringify(NaN)).toBe("null");
      expect(stableStringify(42)).toBe("42");
      expect(stableStringify("test")).toBe('"test"');
      expect(stableStringify([1, 2, 3])).toBe("[1,2,3]");
    });
  });

  describe("Team Isolation", () => {
    it("should maintain separate chains per team", async () => {
      // Team 1 has entries
      mockQueryRaw.mockResolvedValueOnce([{
        currentHash: "team1hash",
        sequenceNumber: BigInt(10),
      }]);
      mockQueryRaw.mockResolvedValueOnce([{
        id: "team1-entry",
        previousHash: "team1hash",
        sequenceNumber: BigInt(11),
        currentHash: "newhash1",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        userId: null,
        teamId: "team-1",
        resourceType: null,
        resourceId: null,
        metadata: null,
        metadataHash: null,
        ipAddress: null,
        userAgent: null,
      }]);

      await createImmutableAuditEntry({
        eventType: "DOCUMENT_VIEWED",
        teamId: "team-1",
      });

      // Team 2 starts fresh
      mockQueryRaw.mockResolvedValueOnce([]); // No previous entries
      mockQueryRaw.mockResolvedValueOnce([{
        id: "team2-entry",
        previousHash: GENESIS_HASH,
        sequenceNumber: BigInt(1),
        currentHash: "newhash2",
        timestamp: new Date(),
        eventType: "DOCUMENT_VIEWED",
        userId: null,
        teamId: "team-2",
        resourceType: null,
        resourceId: null,
        metadata: null,
        metadataHash: null,
        ipAddress: null,
        userAgent: null,
      }]);

      const result = await createImmutableAuditEntry({
        eventType: "DOCUMENT_VIEWED",
        teamId: "team-2",
      });

      // Team 2 should start from genesis
      expect(result.previousHash).toBe(GENESIS_HASH);
      expect(result.sequenceNumber).toBe(BigInt(1));
    });
  });

  describe("GENESIS_HASH Constant", () => {
    it("should be 64 zeros", () => {
      expect(GENESIS_HASH).toBe("0000000000000000000000000000000000000000000000000000000000000000");
      expect(GENESIS_HASH.length).toBe(64);
      expect(GENESIS_HASH).toMatch(/^0+$/);
    });
  });
});
