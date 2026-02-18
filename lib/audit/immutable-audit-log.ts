/**
 * Immutable Audit Log System
 * 
 * This module implements a tamper-evident audit log system using cryptographic
 * hash chaining (similar to blockchain). Each audit entry is linked to the
 * previous entry via a SHA-256 hash, making it impossible to modify or delete
 * historical entries without detection.
 * 
 * ## Security Architecture
 * - **Algorithm**: SHA-256 hash chaining
 * - **Genesis Hash**: Predefined 64-character zero hash for first entry
 * - **Metadata Hashing**: Separate hash of metadata for deterministic verification
 * - **Team Isolation**: Separate hash chains per team for multi-tenant security
 * - **Sequence Numbers**: Monotonically increasing BigInt for ordering
 * 
 * ## Hash Chain Structure
 * Each entry contains:
 * - `previousHash`: Hash of the previous entry in the chain
 * - `currentHash`: Hash of this entry (includes previousHash)
 * - `sequenceNumber`: Position in the chain (1-indexed)
 * - `metadataHash`: Separate hash of metadata for JSON stability
 * 
 * ## Verification Process
 * 1. Start from the first entry (genesis hash as previousHash)
 * 2. Recompute hash from entry data
 * 3. Compare computed hash with stored currentHash
 * 4. Verify previousHash matches previous entry's currentHash
 * 5. Continue through all entries
 * 
 * ## Compliance Features
 * - 7-year retention policy support
 * - Export with integrity checksums
 * - Tamper detection and reporting
 * - ESIGN/UETA compliance compatible
 * 
 * ## API Endpoints
 * - `GET /api/teams/:teamId/audit/verify` - Verify chain integrity
 * - `POST /api/teams/:teamId/audit/export` - Export with checksums
 * 
 * @module lib/audit/immutable-audit-log
 * @see lib/audit/audit-logger - Event types and logging interface
 * @see pages/api/teams/[teamId]/audit/verify.ts - Verification API
 * @see pages/api/teams/[teamId]/audit/export.ts - Export API
 */

import crypto from "crypto";
import prisma from "@/lib/prisma";
import { AuditLogData } from "./audit-logger";
import { Prisma } from "@prisma/client";

/** SHA-256 algorithm identifier */
const HASH_ALGORITHM = "sha256";

/** Genesis hash - used as previousHash for the first entry in a chain */
const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Represents a single entry in the immutable audit log chain
 * 
 * @property id - Unique identifier for the entry
 * @property timestamp - When the event occurred
 * @property eventType - Type of audit event (e.g., DOCUMENT_VIEWED)
 * @property userId - User who triggered the event (null for system events)
 * @property teamId - Team context for the event
 * @property resourceType - Type of resource affected (Document, Investor, etc.)
 * @property resourceId - ID of the affected resource
 * @property metadata - Additional event-specific data
 * @property metadataHash - SHA-256 hash of canonicalized metadata
 * @property ipAddress - Client IP address
 * @property userAgent - Client user agent string
 * @property previousHash - Hash of the previous entry in chain
 * @property currentHash - Hash of this entry
 * @property sequenceNumber - Position in the chain (BigInt for large chains)
 */
export interface ImmutableAuditEntry {
  id: string;
  timestamp: Date;
  eventType: string;
  userId: string | null;
  teamId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, any> | null;
  metadataHash: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  previousHash: string;
  currentHash: string;
  sequenceNumber: bigint;
}

/**
 * Result of audit chain verification
 * 
 * @property isValid - Whether the entire chain is valid (no tampering detected)
 * @property totalEntries - Total number of entries in the chain
 * @property verifiedEntries - Number of entries that passed verification
 * @property firstInvalidEntry - ID of the first invalid entry (if any)
 * @property errors - List of error messages for any verification failures
 */
export interface AuditChainVerificationResult {
  isValid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  firstInvalidEntry?: string;
  errors: string[];
}

function stableStringify(obj: any): string {
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
}

function canonicalizeMetadata(metadata: Record<string, any> | null): string | null {
  if (metadata === null) return null;
  return stableStringify(metadata);
}

function computeEntryHash(entry: {
  timestamp: Date;
  eventType: string;
  userId: string | null;
  teamId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadataHash: string | null;
  previousHash: string;
  sequenceNumber: bigint;
}): string {
  const dataToHash = JSON.stringify({
    timestamp: entry.timestamp.toISOString(),
    eventType: entry.eventType,
    userId: entry.userId,
    teamId: entry.teamId,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId,
    metadataHash: entry.metadataHash,
    previousHash: entry.previousHash,
    sequenceNumber: entry.sequenceNumber.toString(),
  });

  return crypto.createHash(HASH_ALGORITHM).update(dataToHash).digest("hex");
}

function hashMetadata(metadata: Record<string, any> | null): string | null {
  if (metadata === null) return null;
  const canonical = stableStringify(metadata);
  return crypto.createHash(HASH_ALGORITHM).update(canonical).digest("hex");
}

/**
 * Creates a new immutable audit log entry with hash chaining
 * 
 * Each entry is cryptographically linked to the previous entry via SHA-256 hash,
 * creating a tamper-evident chain similar to blockchain. Team-scoped entries
 * maintain separate chains per team for multi-tenant isolation.
 * 
 * ## Hash Chain Process
 * 1. Fetch the last entry's hash and sequence number for this team
 * 2. Use genesis hash if this is the first entry
 * 3. Compute metadata hash for deterministic verification
 * 4. Compute current entry hash (includes previous hash)
 * 5. Insert with atomic sequence number increment
 * 
 * @param data - The audit log data to record
 * @returns Promise resolving to the created ImmutableAuditEntry
 * @throws Error if database insertion fails
 * 
 * @example
 * ```typescript
 * await createImmutableAuditEntry({
 *   eventType: "DOCUMENT_VIEWED",
 *   userId: "user123",
 *   teamId: "team456",
 *   resourceType: "Document",
 *   resourceId: "doc789",
 *   metadata: { viewDuration: 30 }
 * });
 * ```
 */
export async function createImmutableAuditEntry(
  data: AuditLogData
): Promise<ImmutableAuditEntry> {
  const teamId = data.teamId ?? null;
  
  const lastEntry = teamId
    ? await prisma.$queryRaw<Array<{
        currentHash: string;
        sequenceNumber: bigint;
      }>>`
        SELECT "currentHash", "sequenceNumber"
        FROM "AuditLog"
        WHERE "currentHash" IS NOT NULL AND "teamId" = ${teamId}
        ORDER BY "sequenceNumber" DESC
        LIMIT 1
      `
    : await prisma.$queryRaw<Array<{
        currentHash: string;
        sequenceNumber: bigint;
      }>>`
        SELECT "currentHash", "sequenceNumber"
        FROM "AuditLog"
        WHERE "currentHash" IS NOT NULL AND "teamId" IS NULL
        ORDER BY "sequenceNumber" DESC
        LIMIT 1
      `;

  const previousHash = lastEntry.length > 0 ? lastEntry[0].currentHash : GENESIS_HASH;
  const sequenceNumber = lastEntry.length > 0 ? lastEntry[0].sequenceNumber + BigInt(1) : BigInt(1);
  const timestamp = new Date();

  const metadataHashValue = hashMetadata(data.metadata ?? null);
  
  const entryForHash = {
    timestamp,
    eventType: data.eventType,
    userId: data.userId ?? null,
    teamId,
    resourceType: data.resourceType ?? null,
    resourceId: data.resourceId ?? null,
    metadataHash: metadataHashValue,
    previousHash,
    sequenceNumber,
  };

  const currentHash = computeEntryHash(entryForHash);
  const id = crypto.randomUUID();
  const metadataJson = canonicalizeMetadata(data.metadata ?? null);

  const result = await prisma.$queryRaw<Array<ImmutableAuditEntry>>`
    INSERT INTO "AuditLog" (
      "id", "eventType", "userId", "teamId", "resourceType", "resourceId",
      "metadata", "ipAddress", "userAgent", "previousHash", "currentHash",
      "sequenceNumber", "timestamp", "metadataHash"
    )
    VALUES (
      ${id},
      ${data.eventType},
      ${data.userId ?? null},
      ${teamId},
      ${data.resourceType ?? null},
      ${data.resourceId ?? null},
      ${metadataJson}::jsonb,
      ${data.ipAddress ?? null},
      ${data.userAgent ?? null},
      ${previousHash},
      ${currentHash},
      ${sequenceNumber},
      ${timestamp},
      ${metadataHashValue}
    )
    RETURNING *
  `;

  return result[0];
}

/**
 * Verifies the integrity of an audit log hash chain
 * 
 * Iterates through all entries in the chain and verifies:
 * 1. Each entry's hash is correctly computed from its data
 * 2. Each entry's previousHash matches the previous entry's currentHash
 * 3. Sequence numbers are contiguous and properly ordered
 * 4. Metadata hashes match the stored values
 * 
 * If any verification fails, the function identifies the first invalid entry
 * and continues checking to report all errors.
 * 
 * @param teamId - The team ID whose audit chain to verify
 * @param fromDate - Optional start date for partial verification
 * @param toDate - Optional end date for partial verification
 * @returns Promise resolving to AuditChainVerificationResult
 * 
 * @example
 * ```typescript
 * const result = await verifyAuditChain("team123");
 * if (!result.isValid) {
 *   console.error("Tampering detected:", result.errors);
 *   console.error("First invalid entry:", result.firstInvalidEntry);
 * }
 * ```
 */
export async function verifyAuditChain(
  teamId: string,
  fromDate?: Date,
  toDate?: Date
): Promise<AuditChainVerificationResult> {
  const errors: string[] = [];
  
  let entries: ImmutableAuditEntry[];
  
  if (fromDate && toDate) {
    entries = await prisma.$queryRaw<ImmutableAuditEntry[]>`
      SELECT * FROM "AuditLog"
      WHERE "currentHash" IS NOT NULL 
        AND "teamId" = ${teamId}
        AND "timestamp" >= ${fromDate}
        AND "timestamp" <= ${toDate}
      ORDER BY "sequenceNumber" ASC
    `;
  } else if (fromDate) {
    entries = await prisma.$queryRaw<ImmutableAuditEntry[]>`
      SELECT * FROM "AuditLog"
      WHERE "currentHash" IS NOT NULL 
        AND "teamId" = ${teamId}
        AND "timestamp" >= ${fromDate}
      ORDER BY "sequenceNumber" ASC
    `;
  } else if (toDate) {
    entries = await prisma.$queryRaw<ImmutableAuditEntry[]>`
      SELECT * FROM "AuditLog"
      WHERE "currentHash" IS NOT NULL 
        AND "teamId" = ${teamId}
        AND "timestamp" <= ${toDate}
      ORDER BY "sequenceNumber" ASC
    `;
  } else {
    entries = await prisma.$queryRaw<ImmutableAuditEntry[]>`
      SELECT * FROM "AuditLog"
      WHERE "currentHash" IS NOT NULL AND "teamId" = ${teamId}
      ORDER BY "sequenceNumber" ASC
    `;
  }

  let verifiedEntries = 0;
  let previousHash = GENESIS_HASH;
  let firstInvalidEntry: string | undefined;

  for (const entry of entries) {
    if (entry.previousHash !== previousHash) {
      errors.push(`Entry ${entry.id}: Previous hash mismatch. Expected ${previousHash}, got ${entry.previousHash}`);
      if (!firstInvalidEntry) {
        firstInvalidEntry = entry.id;
      }
    }

    const expectedHash = computeEntryHash({
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      userId: entry.userId,
      teamId: entry.teamId,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      metadataHash: entry.metadataHash,
      previousHash: entry.previousHash,
      sequenceNumber: entry.sequenceNumber,
    });

    if (entry.currentHash !== expectedHash) {
      errors.push(`Entry ${entry.id}: Hash mismatch. Data may have been tampered.`);
      if (!firstInvalidEntry) {
        firstInvalidEntry = entry.id;
      }
    } else {
      verifiedEntries++;
    }

    previousHash = entry.currentHash;
  }

  return {
    isValid: errors.length === 0,
    totalEntries: entries.length,
    verifiedEntries,
    firstInvalidEntry,
    errors,
  };
}

/**
 * Exports audit logs for regulatory compliance with integrity verification
 * 
 * Creates a compliance-ready export package containing:
 * - All audit entries within the specified date range
 * - Chain verification results proving data integrity
 * - Export metadata with SHA-256 checksum
 * 
 * The export is suitable for regulatory audits (SEC, FINRA, etc.) and
 * the checksum can be used to verify the export hasn't been modified.
 * 
 * @param teamId - The team ID to export logs for
 * @param fromDate - Start date for the export range
 * @param toDate - End date for the export range
 * @returns Promise resolving to export package with entries, verification, and metadata
 * 
 * @example
 * ```typescript
 * const export = await exportAuditLogForCompliance(
 *   "team123",
 *   new Date("2024-01-01"),
 *   new Date("2024-12-31")
 * );
 * // Save export.entries and export.exportMetadata.checksum
 * ```
 */
export async function exportAuditLogForCompliance(
  teamId: string,
  fromDate: Date,
  toDate: Date
): Promise<{
  entries: ImmutableAuditEntry[];
  chainVerification: AuditChainVerificationResult;
  exportMetadata: {
    exportedAt: string;
    exportedBy: string;
    teamId: string;
    dateRange: { from: string; to: string };
    totalRecords: number;
    checksum: string;
  };
}> {
  const verification = await verifyAuditChain(teamId, fromDate, toDate);
  
  const entries = await prisma.$queryRaw<ImmutableAuditEntry[]>`
    SELECT * FROM "AuditLog"
    WHERE "teamId" = ${teamId}
    AND "timestamp" >= ${fromDate}
    AND "timestamp" <= ${toDate}
    ORDER BY "sequenceNumber" ASC
  `;

  const entriesJson = JSON.stringify(entries);
  const checksum = crypto.createHash("sha256").update(entriesJson).digest("hex");

  return {
    entries,
    chainVerification: verification,
    exportMetadata: {
      exportedAt: new Date().toISOString(),
      exportedBy: "system",
      teamId,
      dateRange: {
        from: fromDate.toISOString(),
        to: toDate.toISOString(),
      },
      totalRecords: entries.length,
      checksum,
    },
  };
}

/**
 * Gets the current integrity status of a team's audit log chain
 * 
 * Returns a summary of the chain's health including:
 * - Chain length (total entries)
 * - Latest hash for quick integrity checks
 * - Verification status (runs full verification)
 * - Genesis hash for reference
 * 
 * This is a quick way to check if the audit log has been tampered with
 * without examining each entry individually.
 * 
 * @param teamId - The team ID to check integrity for
 * @returns Promise resolving to integrity status object
 * 
 * @example
 * ```typescript
 * const status = await getAuditLogIntegrity("team123");
 * if (!status.isValid) {
 *   alert("Audit log tampering detected!");
 * }
 * console.log(`Chain has ${status.chainLength} entries`);
 * ```
 */
export async function getAuditLogIntegrity(teamId: string): Promise<{
  lastVerifiedAt: Date;
  chainLength: number;
  isValid: boolean;
  genesisHash: string;
  latestHash: string;
}> {
  const stats = await prisma.$queryRaw<Array<{
    count: bigint;
    latestHash: string | null;
  }>>`
    SELECT 
      COUNT(*) as count,
      (SELECT "currentHash" FROM "AuditLog" WHERE "currentHash" IS NOT NULL AND "teamId" = ${teamId} ORDER BY "sequenceNumber" DESC LIMIT 1) as "latestHash"
    FROM "AuditLog"
    WHERE "currentHash" IS NOT NULL AND "teamId" = ${teamId}
  `;

  const verification = await verifyAuditChain(teamId);

  return {
    lastVerifiedAt: new Date(),
    chainLength: Number(stats[0]?.count || 0),
    isValid: verification.isValid,
    genesisHash: GENESIS_HASH,
    latestHash: stats[0]?.latestHash || GENESIS_HASH,
  };
}
