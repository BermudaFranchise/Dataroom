// @ts-nocheck
/**
 * Tests for OrganizationCredentialService
 * Covers: AES-256-GCM encryption/decryption, credential CRUD, integrity verification
 */
import crypto from "crypto";

// Generate a valid 64-char hex key for tests
const TEST_KEY = crypto.randomBytes(32).toString("hex");
process.env.STORAGE_ENCRYPTION_KEY = TEST_KEY;

import prisma from "@/lib/prisma";

// Add mock for organizationIntegrationCredential model
const mockCredentialModel = {
  upsert: jest.fn(),
  findUnique: jest.fn(),
  findMany: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
};
(prisma as any).organizationIntegrationCredential = mockCredentialModel;

import { OrganizationCredentialService } from "@/lib/organization/credential-service";

let service: OrganizationCredentialService;

beforeEach(() => {
  jest.clearAllMocks();
  process.env.STORAGE_ENCRYPTION_KEY = TEST_KEY;
  service = new OrganizationCredentialService();
});

describe("OrganizationCredentialService - Constructor", () => {
  it("initializes successfully with valid 64-char hex key", () => {
    expect(() => new OrganizationCredentialService()).not.toThrow();
  });

  it("throws on missing STORAGE_ENCRYPTION_KEY", () => {
    const orig = process.env.STORAGE_ENCRYPTION_KEY;
    delete process.env.STORAGE_ENCRYPTION_KEY;
    expect(() => new OrganizationCredentialService()).toThrow(
      "STORAGE_ENCRYPTION_KEY must be a 64-character hex string"
    );
    process.env.STORAGE_ENCRYPTION_KEY = orig;
  });

  it("throws on short key", () => {
    process.env.STORAGE_ENCRYPTION_KEY = "abcdef1234";
    expect(() => new OrganizationCredentialService()).toThrow();
    process.env.STORAGE_ENCRYPTION_KEY = TEST_KEY;
  });

  it("throws on non-hex key", () => {
    process.env.STORAGE_ENCRYPTION_KEY = "g".repeat(64);
    expect(() => new OrganizationCredentialService()).toThrow();
    process.env.STORAGE_ENCRYPTION_KEY = TEST_KEY;
  });
});

describe("OrganizationCredentialService - Encrypt/Decrypt", () => {
  it("encrypts and decrypts credentials correctly (round-trip)", async () => {
    const creds = { apiKey: "sk_live_abc123", apiSecret: "secret_xyz" };

    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });

    await service.storeCredentials("org-1", "stripe", creds);

    // Capture what was stored
    const stored = mockCredentialModel.upsert.mock.calls[0][0];
    const encryptedData = stored.create.encryptedCredentials;
    const hash = stored.create.credentialHash;

    // Verify encrypted data is base64 and NOT plaintext
    expect(encryptedData).not.toContain("sk_live_abc123");
    expect(encryptedData).not.toContain("secret_xyz");

    // Simulate retrieval
    mockCredentialModel.findUnique.mockResolvedValue({
      id: "cred-1",
      isActive: true,
      encryptedCredentials: encryptedData,
      credentialHash: hash,
    });
    mockCredentialModel.update.mockResolvedValue({});

    const retrieved = await service.getCredentials("org-1", "stripe");
    expect(retrieved).toEqual(creds);
  });

  it("produces different ciphertext for same input (random IV)", async () => {
    const creds = { apiKey: "sk_live_same" };

    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });

    await service.storeCredentials("org-1", "stripe", creds);
    const first = mockCredentialModel.upsert.mock.calls[0][0].create.encryptedCredentials;

    await service.storeCredentials("org-1", "stripe", creds);
    const second = mockCredentialModel.upsert.mock.calls[1][0].create.encryptedCredentials;

    expect(first).not.toEqual(second);
  });

  it("detects tampered ciphertext via GCM auth tag", async () => {
    const creds = { apiKey: "sk_live_abc" };

    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });
    await service.storeCredentials("org-1", "stripe", creds);

    const encryptedData = mockCredentialModel.upsert.mock.calls[0][0].create.encryptedCredentials;

    // Tamper with the encrypted data
    const tampered = Buffer.from(encryptedData, "base64");
    tampered[tampered.length - 1] ^= 0xff; // flip last byte
    const tamperedBase64 = tampered.toString("base64");

    mockCredentialModel.findUnique.mockResolvedValue({
      id: "cred-1",
      isActive: true,
      encryptedCredentials: tamperedBase64,
    });

    await expect(service.getCredentials("org-1", "stripe")).rejects.toThrow();
  });

  it("handles complex credential objects with all fields", async () => {
    const creds = {
      apiKey: "key-123",
      apiSecret: "secret-456",
      clientId: "client-789",
      clientSecret: "cs-abc",
      accessToken: "at-def",
      refreshToken: "rt-ghi",
      webhookSecret: "ws-jkl",
    };

    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });
    await service.storeCredentials("org-1", "persona", creds);

    const stored = mockCredentialModel.upsert.mock.calls[0][0];
    mockCredentialModel.findUnique.mockResolvedValue({
      id: "cred-1",
      isActive: true,
      encryptedCredentials: stored.create.encryptedCredentials,
      credentialHash: stored.create.credentialHash,
    });
    mockCredentialModel.update.mockResolvedValue({});

    const retrieved = await service.getCredentials("org-1", "persona");
    expect(retrieved).toEqual(creds);
  });
});

describe("OrganizationCredentialService - Store/Get", () => {
  it("upserts with correct composite key", async () => {
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });

    await service.storeCredentials("org-1", "plaid", { clientId: "id" }, { environment: "staging", label: "Test" });

    const call = mockCredentialModel.upsert.mock.calls[0][0];
    expect(call.where.organizationId_provider_environment).toEqual({
      organizationId: "org-1",
      provider: "plaid",
      environment: "staging",
    });
    expect(call.create.label).toBe("Test");
    expect(call.update.lastRotatedAt).toBeDefined();
  });

  it("defaults environment to 'production'", async () => {
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });

    await service.storeCredentials("org-1", "stripe", { apiKey: "key" });

    const call = mockCredentialModel.upsert.mock.calls[0][0];
    expect(call.where.organizationId_provider_environment.environment).toBe("production");
    expect(call.create.environment).toBe("production");
  });

  it("returns null for inactive credentials", async () => {
    mockCredentialModel.findUnique.mockResolvedValue({
      id: "cred-1",
      isActive: false,
      encryptedCredentials: "dummy",
    });

    const result = await service.getCredentials("org-1", "stripe");
    expect(result).toBeNull();
    // Should not try to update lastUsedAt
    expect(mockCredentialModel.update).not.toHaveBeenCalled();
  });

  it("returns null for non-existent credentials", async () => {
    mockCredentialModel.findUnique.mockResolvedValue(null);

    const result = await service.getCredentials("org-1", "nonexistent");
    expect(result).toBeNull();
  });

  it("updates lastUsedAt on successful retrieval", async () => {
    const creds = { apiKey: "key" };
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });
    await service.storeCredentials("org-1", "stripe", creds);

    const stored = mockCredentialModel.upsert.mock.calls[0][0];
    mockCredentialModel.findUnique.mockResolvedValue({
      id: "cred-1",
      isActive: true,
      encryptedCredentials: stored.create.encryptedCredentials,
    });
    mockCredentialModel.update.mockResolvedValue({});

    await service.getCredentials("org-1", "stripe");

    expect(mockCredentialModel.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "cred-1" },
        data: { lastUsedAt: expect.any(Date) },
      })
    );
  });
});

describe("OrganizationCredentialService - List", () => {
  it("lists credentials for an organization (without decrypted values)", async () => {
    mockCredentialModel.findMany.mockResolvedValue([
      { id: "c1", provider: "stripe", environment: "production", label: null, isActive: true, lastUsedAt: null, lastRotatedAt: null, createdAt: new Date() },
      { id: "c2", provider: "plaid", environment: "production", label: "Main", isActive: true, lastUsedAt: null, lastRotatedAt: null, createdAt: new Date() },
    ]);

    const list = await service.listCredentials("org-1");
    expect(list).toHaveLength(2);
    expect(list[0].provider).toBe("stripe");
    expect(list[1].provider).toBe("plaid");

    // Verify no encrypted data is returned
    const call = mockCredentialModel.findMany.mock.calls[0][0];
    expect(call.select.encryptedCredentials).toBeUndefined();
  });
});

describe("OrganizationCredentialService - Rotate", () => {
  it("rotation overwrites credentials via storeCredentials", async () => {
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });

    await service.rotateCredentials("org-1", "stripe", { apiKey: "new-key" });

    expect(mockCredentialModel.upsert).toHaveBeenCalledTimes(1);
    const call = mockCredentialModel.upsert.mock.calls[0][0];
    expect(call.where.organizationId_provider_environment.provider).toBe("stripe");
  });
});

describe("OrganizationCredentialService - Deactivate", () => {
  it("sets isActive to false without deleting", async () => {
    mockCredentialModel.update.mockResolvedValue({});

    await service.deactivateCredentials("org-1", "stripe");

    expect(mockCredentialModel.update).toHaveBeenCalledWith({
      where: {
        organizationId_provider_environment: {
          organizationId: "org-1",
          provider: "stripe",
          environment: "production",
        },
      },
      data: { isActive: false },
    });
    // Should NOT call delete
    expect(mockCredentialModel.delete).not.toHaveBeenCalled();
  });
});

describe("OrganizationCredentialService - Delete", () => {
  it("permanently deletes credential record", async () => {
    mockCredentialModel.delete.mockResolvedValue({});

    await service.deleteCredentials("org-1", "stripe");

    expect(mockCredentialModel.delete).toHaveBeenCalledWith({
      where: {
        organizationId_provider_environment: {
          organizationId: "org-1",
          provider: "stripe",
          environment: "production",
        },
      },
    });
  });
});

describe("OrganizationCredentialService - verifyIntegrity", () => {
  it("returns true for matching hash", async () => {
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });
    await service.storeCredentials("org-1", "s", { apiKey: "k" });

    const stored = mockCredentialModel.upsert.mock.calls[0][0];
    const result = service.verifyIntegrity(stored.create.encryptedCredentials, stored.create.credentialHash);
    expect(result).toBe(true);
  });

  it("returns false for mismatched hash", () => {
    const result = service.verifyIntegrity(
      Buffer.from("hello").toString("base64"),
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    expect(result).toBe(false);
  });

  it("returns false for tampered encrypted data", async () => {
    mockCredentialModel.upsert.mockResolvedValue({ id: "cred-1" });
    await service.storeCredentials("org-1", "s", { apiKey: "k" });

    const stored = mockCredentialModel.upsert.mock.calls[0][0];
    // Decode, flip a byte, re-encode to guarantee tampering
    const buf = Buffer.from(stored.create.encryptedCredentials, "base64");
    buf[0] ^= 0xff;
    const tampered = buf.toString("base64");
    const result = service.verifyIntegrity(tampered, stored.create.credentialHash);
    expect(result).toBe(false);
  });
});
