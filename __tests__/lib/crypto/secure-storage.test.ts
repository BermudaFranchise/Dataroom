// @ts-nocheck
/**
 * Secure Storage Tests
 *
 * Tests for lib/crypto/secure-storage.ts - Server-side encryption and storage.
 *
 * These tests validate:
 * - AES-256-GCM server-side encryption/decryption
 * - Signature storage and retrieval
 * - Password hashing with PBKDF2
 * - Secure token generation
 * - Document checksum computation and verification
 * - Document integrity records
 * - PDF encryption and storage
 */

// Mock functions
const mockRandomBytes = jest.fn();
const mockCreateCipheriv = jest.fn();
const mockCreateDecipheriv = jest.fn();
const mockCreateHash = jest.fn();
const mockPbkdf2Sync = jest.fn();
const mockTimingSafeEqual = jest.fn();

const mockSignatureAuditLogCreate = jest.fn();
const mockSignatureAuditLogFindUnique = jest.fn();

// Mock crypto
jest.mock("crypto", () => ({
  randomBytes: (...args: any[]) => mockRandomBytes(...args),
  createCipheriv: (...args: any[]) => mockCreateCipheriv(...args),
  createDecipheriv: (...args: any[]) => mockCreateDecipheriv(...args),
  createHash: (...args: any[]) => mockCreateHash(...args),
  pbkdf2Sync: (...args: any[]) => mockPbkdf2Sync(...args),
  timingSafeEqual: (...args: any[]) => mockTimingSafeEqual(...args),
}));

// Mock prisma
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    signatureAuditLog: {
      create: (...args: any[]) => mockSignatureAuditLogCreate(...args),
      findUnique: (...args: any[]) => mockSignatureAuditLogFindUnique(...args),
    },
  },
}));

// Set up environment variables
const originalEnv = process.env;
beforeAll(() => {
  process.env = {
    ...originalEnv,
    NEXT_PRIVATE_DOCUMENT_PASSWORD_KEY: "test-encryption-key-32-chars-long",
    NEXTAUTH_SECRET: "fallback-secret",
  };
});

afterAll(() => {
  process.env = originalEnv;
});

import {
  encryptServerSide,
  decryptServerSide,
  encryptToString,
  decryptFromString,
  storeEncryptedSignature,
  retrieveEncryptedSignature,
  hashPassword,
  verifyPassword,
  generateSecureToken,
  computeDocumentChecksum,
  verifyDocumentChecksum,
  createDocumentIntegrityRecord,
  verifyDocumentIntegrity,
  encryptAndStorePDF,
} from "@/lib/crypto/secure-storage";
import type { EncryptedPayload, DocumentIntegrityData } from "@/lib/crypto/secure-storage";

describe("Secure Storage", () => {
  const mockCipher = {
    update: jest.fn(),
    final: jest.fn(),
    getAuthTag: jest.fn(),
  };

  const mockDecipher = {
    update: jest.fn(),
    final: jest.fn(),
    setAuthTag: jest.fn(),
  };

  const mockHashInstance = {
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup default mocks
    mockRandomBytes.mockReturnValue(Buffer.alloc(16, 0));
    mockCreateCipheriv.mockReturnValue(mockCipher);
    mockCreateDecipheriv.mockReturnValue(mockDecipher);
    mockCreateHash.mockReturnValue(mockHashInstance);
    // Handle both Buffer return and hex string return based on argument
    mockHashInstance.digest.mockImplementation((encoding?: string) => {
      if (encoding === "hex") {
        return Buffer.alloc(32, 1).toString("hex");
      }
      return Buffer.alloc(32, 1);
    });

    mockCipher.update.mockReturnValue(Buffer.from("encrypted"));
    mockCipher.final.mockReturnValue(Buffer.from(""));
    mockCipher.getAuthTag.mockReturnValue(Buffer.alloc(16, 2));

    mockDecipher.update.mockReturnValue(Buffer.from("decrypted"));
    mockDecipher.final.mockReturnValue(Buffer.from(""));

    mockPbkdf2Sync.mockReturnValue(Buffer.alloc(64, 3));
    mockTimingSafeEqual.mockReturnValue(true);

    mockSignatureAuditLogCreate.mockResolvedValue({ id: "audit-log-123" });
    mockSignatureAuditLogFindUnique.mockResolvedValue(null);
  });

  describe("encryptServerSide", () => {
    it("should encrypt Buffer data", () => {
      const data = Buffer.from("sensitive data");

      const result = encryptServerSide(data);

      expect(result).toHaveProperty("ciphertext");
      expect(result).toHaveProperty("iv");
      expect(result).toHaveProperty("authTag");
      expect(result).toHaveProperty("version");
      expect(result.version).toBe(1);
    });

    it("should encrypt string data", () => {
      const data = "sensitive string";

      const result = encryptServerSide(data);

      expect(result).toHaveProperty("ciphertext");
      expect(mockCreateCipheriv).toHaveBeenCalled();
    });

    it("should use AES-256-GCM algorithm", () => {
      const data = Buffer.from("test");

      encryptServerSide(data);

      expect(mockCreateCipheriv).toHaveBeenCalledWith(
        "aes-256-gcm",
        expect.any(Buffer),
        expect.any(Buffer)
      );
    });

    it("should generate random IV for each encryption", () => {
      let callCount = 0;
      mockRandomBytes.mockImplementation((length) => {
        const buf = Buffer.alloc(length);
        buf.fill(callCount++);
        return buf;
      });

      const result1 = encryptServerSide("data1");
      const result2 = encryptServerSide("data2");

      expect(result1.iv).not.toBe(result2.iv);
    });

    it("should return base64-encoded values", () => {
      const result = encryptServerSide("data");

      // Base64 validation regex
      const base64Regex = /^[A-Za-z0-9+/=]+$/;
      expect(result.ciphertext).toMatch(base64Regex);
      expect(result.iv).toMatch(base64Regex);
      expect(result.authTag).toMatch(base64Regex);
    });

    it("should include authentication tag", () => {
      mockCipher.getAuthTag.mockReturnValue(Buffer.from("auth-tag-bytes"));

      const result = encryptServerSide("data");

      expect(mockCipher.getAuthTag).toHaveBeenCalled();
      expect(result.authTag).toBeDefined();
    });
  });

  describe("decryptServerSide", () => {
    it("should decrypt encrypted payload", () => {
      const payload: EncryptedPayload = {
        ciphertext: Buffer.from("encrypted").toString("base64"),
        iv: Buffer.alloc(16, 0).toString("base64"),
        authTag: Buffer.alloc(16, 2).toString("base64"),
        version: 1,
      };

      const result = decryptServerSide(payload);

      expect(result).toBeInstanceOf(Buffer);
    });

    it("should use same algorithm for decryption", () => {
      const payload: EncryptedPayload = {
        ciphertext: Buffer.from("encrypted").toString("base64"),
        iv: Buffer.alloc(16, 0).toString("base64"),
        authTag: Buffer.alloc(16, 2).toString("base64"),
        version: 1,
      };

      decryptServerSide(payload);

      expect(mockCreateDecipheriv).toHaveBeenCalledWith(
        "aes-256-gcm",
        expect.any(Buffer),
        expect.any(Buffer)
      );
    });

    it("should set authentication tag before decryption", () => {
      const payload: EncryptedPayload = {
        ciphertext: Buffer.from("encrypted").toString("base64"),
        iv: Buffer.alloc(16, 0).toString("base64"),
        authTag: Buffer.from("tag").toString("base64"),
        version: 1,
      };

      decryptServerSide(payload);

      expect(mockDecipher.setAuthTag).toHaveBeenCalled();
    });

    it("should throw on invalid auth tag", () => {
      mockDecipher.final.mockImplementation(() => {
        throw new Error("Unsupported state or unable to authenticate data");
      });

      const payload: EncryptedPayload = {
        ciphertext: Buffer.from("encrypted").toString("base64"),
        iv: Buffer.alloc(16, 0).toString("base64"),
        authTag: Buffer.from("wrong-tag").toString("base64"),
        version: 1,
      };

      expect(() => decryptServerSide(payload)).toThrow();
    });
  });

  describe("encryptToString", () => {
    it("should return JSON string", () => {
      const result = encryptToString("secret");

      expect(typeof result).toBe("string");
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it("should contain all encrypted payload fields", () => {
      const result = encryptToString("secret");
      const parsed = JSON.parse(result);

      expect(parsed).toHaveProperty("ciphertext");
      expect(parsed).toHaveProperty("iv");
      expect(parsed).toHaveProperty("authTag");
      expect(parsed).toHaveProperty("version");
    });
  });

  describe("decryptFromString", () => {
    it("should decrypt JSON-encoded encrypted payload", () => {
      mockDecipher.update.mockReturnValue(Buffer.from("decrypted text"));

      const encrypted = JSON.stringify({
        ciphertext: Buffer.from("encrypted").toString("base64"),
        iv: Buffer.alloc(16, 0).toString("base64"),
        authTag: Buffer.alloc(16, 2).toString("base64"),
        version: 1,
      });

      const result = decryptFromString(encrypted);

      expect(typeof result).toBe("string");
    });

    it("should throw on invalid JSON", () => {
      expect(() => decryptFromString("not-json")).toThrow();
    });
  });

  describe("storeEncryptedSignature", () => {
    it("should encrypt signature data before storing", async () => {
      await storeEncryptedSignature("doc-123", "recipient-456", "signature-data");

      expect(mockCreateCipheriv).toHaveBeenCalled();
    });

    it("should create audit log record", async () => {
      await storeEncryptedSignature("doc-123", "recipient-456", "signature-data");

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          documentId: "doc-123",
          recipientId: "recipient-456",
          event: "SIGNATURE_DATA_ENCRYPTED",
        }),
      });
    });

    it("should include encrypted payload in metadata", async () => {
      await storeEncryptedSignature("doc-123", "recipient-456", "signature-data");

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          metadata: expect.objectContaining({
            encryptedPayload: expect.any(Object),
            encryptionVersion: 1,
            algorithm: "aes-256-gcm",
          }),
        }),
      });
    });

    it("should return audit log ID", async () => {
      mockSignatureAuditLogCreate.mockResolvedValue({ id: "audit-789" });

      const result = await storeEncryptedSignature(
        "doc-123",
        "recipient-456",
        "signature-data"
      );

      expect(result).toBe("audit-789");
    });

    it("should include custom metadata if provided", async () => {
      await storeEncryptedSignature(
        "doc-123",
        "recipient-456",
        "signature-data",
        { customField: "value" }
      );

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          metadata: expect.objectContaining({
            customField: "value",
          }),
        }),
      });
    });
  });

  describe("retrieveEncryptedSignature", () => {
    it("should return null when record not found", async () => {
      mockSignatureAuditLogFindUnique.mockResolvedValue(null);

      const result = await retrieveEncryptedSignature("nonexistent-id");

      expect(result).toBeNull();
    });

    it("should return null when metadata is missing", async () => {
      mockSignatureAuditLogFindUnique.mockResolvedValue({
        id: "audit-123",
        metadata: null,
      });

      const result = await retrieveEncryptedSignature("audit-123");

      expect(result).toBeNull();
    });

    it("should return null when encrypted payload is missing", async () => {
      mockSignatureAuditLogFindUnique.mockResolvedValue({
        id: "audit-123",
        metadata: { someOtherField: "value" },
      });

      const result = await retrieveEncryptedSignature("audit-123");

      expect(result).toBeNull();
    });

    it("should decrypt and return signature data", async () => {
      mockDecipher.update.mockReturnValue(Buffer.from("original-signature"));
      mockSignatureAuditLogFindUnique.mockResolvedValue({
        id: "audit-123",
        metadata: {
          encryptedPayload: {
            ciphertext: Buffer.from("encrypted").toString("base64"),
            iv: Buffer.alloc(16, 0).toString("base64"),
            authTag: Buffer.alloc(16, 2).toString("base64"),
            version: 1,
          },
        },
      });

      const result = await retrieveEncryptedSignature("audit-123");

      expect(result).toBeDefined();
      expect(mockCreateDecipheriv).toHaveBeenCalled();
    });
  });

  describe("hashPassword", () => {
    it("should hash password with PBKDF2", () => {
      const result = hashPassword("myPassword");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        "myPassword",
        expect.any(String),
        100000,
        64,
        "sha512"
      );
      expect(result).toHaveProperty("hash");
      expect(result).toHaveProperty("salt");
    });

    it("should generate random salt if not provided", () => {
      hashPassword("password");

      expect(mockRandomBytes).toHaveBeenCalledWith(32);
    });

    it("should use provided salt if given", () => {
      const providedSalt = "provided-salt-value";

      hashPassword("password", providedSalt);

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        "password",
        providedSalt,
        100000,
        64,
        "sha512"
      );
    });

    it("should return hex-encoded hash", () => {
      mockPbkdf2Sync.mockReturnValue(Buffer.from([0xff, 0x00, 0xab]));

      const result = hashPassword("password");

      expect(result.hash).toMatch(/^[a-f0-9]+$/);
    });

    it("should use 100,000 iterations", () => {
      hashPassword("password");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        100000,
        expect.any(Number),
        expect.any(String)
      );
    });
  });

  describe("verifyPassword", () => {
    it("should return true for matching password", () => {
      const storedHash = Buffer.alloc(64, 3).toString("hex");
      mockTimingSafeEqual.mockReturnValue(true);

      const result = verifyPassword("password", storedHash, "salt");

      expect(result).toBe(true);
    });

    it("should return false for non-matching password", () => {
      mockTimingSafeEqual.mockReturnValue(false);

      const result = verifyPassword("wrong", "hash", "salt");

      expect(result).toBe(false);
    });

    it("should use timing-safe comparison", () => {
      verifyPassword("password", "hash", "salt");

      expect(mockTimingSafeEqual).toHaveBeenCalled();
    });

    it("should re-hash password with same salt for comparison", () => {
      verifyPassword("password", "storedHash", "originalSalt");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        "password",
        "originalSalt",
        expect.any(Number),
        expect.any(Number),
        expect.any(String)
      );
    });
  });

  describe("generateSecureToken", () => {
    it("should generate token of default length (32 bytes = 64 hex)", () => {
      mockRandomBytes.mockReturnValue(Buffer.alloc(32, 1));

      const result = generateSecureToken();

      expect(mockRandomBytes).toHaveBeenCalledWith(32);
      expect(result).toHaveLength(64);
    });

    it("should generate token of custom length", () => {
      mockRandomBytes.mockReturnValue(Buffer.alloc(16, 1));

      const result = generateSecureToken(16);

      expect(mockRandomBytes).toHaveBeenCalledWith(16);
      expect(result).toHaveLength(32); // hex encoding doubles length
    });

    it("should return hex-encoded string", () => {
      mockRandomBytes.mockReturnValue(Buffer.from([0xff, 0x00, 0xab, 0xcd]));

      const result = generateSecureToken(4);

      expect(result).toMatch(/^[a-f0-9]+$/);
    });

    it("should generate unique tokens", () => {
      let callCount = 0;
      mockRandomBytes.mockImplementation((length) => {
        const buf = Buffer.alloc(length);
        buf.fill(callCount++);
        return buf;
      });

      const token1 = generateSecureToken();
      const token2 = generateSecureToken();

      expect(token1).not.toBe(token2);
    });
  });

  describe("computeDocumentChecksum", () => {
    it("should compute SHA-256 checksum", () => {
      const data = Buffer.from("document content");

      computeDocumentChecksum(data);

      expect(mockCreateHash).toHaveBeenCalledWith("sha256");
    });

    it("should return hex-encoded checksum", () => {
      mockHashInstance.digest.mockImplementation((encoding?: string) => {
        if (encoding === "hex") return "abcdef";
        return Buffer.from([0xab, 0xcd, 0xef]);
      });

      const result = computeDocumentChecksum(Buffer.from("data"));

      expect(result).toMatch(/^[a-f0-9]+$/);
    });

    it("should accept Uint8Array input", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);

      computeDocumentChecksum(data);

      expect(mockHashInstance.update).toHaveBeenCalled();
    });

    it("should produce consistent checksum for same data", () => {
      mockHashInstance.digest.mockReturnValue(Buffer.alloc(32, 42));

      const data = Buffer.from("consistent data");
      const checksum1 = computeDocumentChecksum(data);
      const checksum2 = computeDocumentChecksum(data);

      expect(checksum1).toBe(checksum2);
    });
  });

  describe("verifyDocumentChecksum", () => {
    it("should return true for matching checksum", () => {
      const checksum = Buffer.alloc(32, 1).toString("hex");
      mockHashInstance.digest.mockReturnValue(Buffer.alloc(32, 1));
      mockTimingSafeEqual.mockReturnValue(true);

      const result = verifyDocumentChecksum(Buffer.from("data"), checksum);

      expect(result).toBe(true);
    });

    it("should return false for non-matching checksum", () => {
      mockTimingSafeEqual.mockReturnValue(false);

      const result = verifyDocumentChecksum(Buffer.from("data"), "wrong-checksum");

      expect(result).toBe(false);
    });

    it("should use timing-safe comparison", () => {
      verifyDocumentChecksum(Buffer.from("data"), "checksum");

      expect(mockTimingSafeEqual).toHaveBeenCalled();
    });

    it("should accept Uint8Array input", () => {
      const data = new Uint8Array([1, 2, 3]);
      mockTimingSafeEqual.mockReturnValue(true);

      verifyDocumentChecksum(data, "checksum");

      expect(mockHashInstance.update).toHaveBeenCalled();
    });
  });

  describe("createDocumentIntegrityRecord", () => {
    it("should create integrity record with checksum", () => {
      mockHashInstance.digest.mockImplementation((encoding?: string) => {
        if (encoding === "hex") return Buffer.alloc(32, 5).toString("hex");
        return Buffer.alloc(32, 5);
      });

      const pdfBytes = Buffer.from("pdf content");
      const result = createDocumentIntegrityRecord(pdfBytes);

      expect(result.checksum).toBeDefined();
      expect(result.checksum).toMatch(/^[a-f0-9]+$/);
    });

    it("should include timestamp", () => {
      const beforeCall = new Date();
      const result = createDocumentIntegrityRecord(Buffer.from("pdf"));
      const afterCall = new Date();

      const recordTime = new Date(result.encryptedAt);
      expect(recordTime.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
      expect(recordTime.getTime()).toBeLessThanOrEqual(afterCall.getTime());
    });

    it("should include algorithm identifier", () => {
      const result = createDocumentIntegrityRecord(Buffer.from("pdf"));

      expect(result.algorithm).toBe("aes-256-gcm");
    });

    it("should include version number", () => {
      const result = createDocumentIntegrityRecord(Buffer.from("pdf"));

      expect(result.version).toBe(1);
    });

    it("should accept Uint8Array input", () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      const result = createDocumentIntegrityRecord(pdfBytes);

      expect(result.checksum).toBeDefined();
    });
  });

  describe("verifyDocumentIntegrity", () => {
    it("should verify document against integrity data", () => {
      mockTimingSafeEqual.mockReturnValue(true);
      mockHashInstance.digest.mockReturnValue(Buffer.alloc(32, 1));

      const pdfBytes = Buffer.from("pdf content");
      const integrityData: DocumentIntegrityData = {
        checksum: Buffer.alloc(32, 1).toString("hex"),
        encryptedAt: new Date().toISOString(),
        algorithm: "aes-256-gcm",
        version: 1,
      };

      const result = verifyDocumentIntegrity(pdfBytes, integrityData);

      expect(result).toBe(true);
    });

    it("should return false for tampered document", () => {
      mockTimingSafeEqual.mockReturnValue(false);

      const pdfBytes = Buffer.from("tampered pdf");
      const integrityData: DocumentIntegrityData = {
        checksum: "original-checksum",
        encryptedAt: new Date().toISOString(),
        algorithm: "aes-256-gcm",
        version: 1,
      };

      const result = verifyDocumentIntegrity(pdfBytes, integrityData);

      expect(result).toBe(false);
    });
  });

  describe("encryptAndStorePDF", () => {
    it("should create integrity record for PDF", async () => {
      const pdfBytes = Buffer.from("pdf content");

      const result = await encryptAndStorePDF(pdfBytes, "doc-123");

      expect(result.integrityData).toBeDefined();
      expect(result.integrityData.checksum).toBeDefined();
    });

    it("should encrypt PDF content", async () => {
      const pdfBytes = Buffer.from("pdf content");

      const result = await encryptAndStorePDF(pdfBytes, "doc-123");

      expect(result.encryptedData).toBeDefined();
      expect(result.encryptedData.ciphertext).toBeDefined();
      expect(mockCreateCipheriv).toHaveBeenCalled();
    });

    it("should create audit log entry", async () => {
      const pdfBytes = Buffer.from("pdf content");

      await encryptAndStorePDF(pdfBytes, "doc-123", "recipient-456");

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          documentId: "doc-123",
          recipientId: "recipient-456",
          event: "DOCUMENT_ENCRYPTED",
        }),
      });
    });

    it("should include checksum in audit log metadata", async () => {
      const pdfBytes = Buffer.from("pdf content");

      await encryptAndStorePDF(pdfBytes, "doc-123");

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          metadata: expect.objectContaining({
            checksum: expect.any(String),
            encryptedAt: expect.any(String),
            algorithm: expect.any(String),
            sizeBytes: pdfBytes.length,
          }),
        }),
      });
    });

    it("should handle undefined recipientId", async () => {
      const pdfBytes = Buffer.from("pdf content");

      await encryptAndStorePDF(pdfBytes, "doc-123");

      expect(mockSignatureAuditLogCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          recipientId: undefined,
        }),
      });
    });

    it("should return both encrypted data and integrity data", async () => {
      const pdfBytes = Buffer.from("pdf content");

      const result = await encryptAndStorePDF(pdfBytes, "doc-123");

      expect(result).toHaveProperty("encryptedData");
      expect(result).toHaveProperty("integrityData");
      expect(result.encryptedData).toHaveProperty("ciphertext");
      expect(result.encryptedData).toHaveProperty("iv");
      expect(result.encryptedData).toHaveProperty("authTag");
      expect(result.integrityData).toHaveProperty("checksum");
    });
  });

  describe("Encryption Key Configuration", () => {
    it("should derive key from NEXT_PRIVATE_DOCUMENT_PASSWORD_KEY", () => {
      encryptServerSide("data");

      // Key derivation uses createHash("sha256")
      expect(mockCreateHash).toHaveBeenCalledWith("sha256");
    });

    it("should use purpose salt in key derivation", () => {
      encryptServerSide("data");

      expect(mockHashInstance.update).toHaveBeenCalledWith(
        expect.stringContaining("bf-fund-document-encryption-v1")
      );
    });
  });

  describe("Security Properties", () => {
    it("should use 32-byte (256-bit) key length", () => {
      // Key is derived from SHA-256 which produces 32 bytes
      encryptServerSide("data");

      expect(mockHashInstance.digest).toHaveBeenCalled();
    });

    it("should use 16-byte IV for AES-GCM", () => {
      encryptServerSide("data");

      expect(mockRandomBytes).toHaveBeenCalledWith(16);
    });

    it("should include authentication tag for integrity", () => {
      const result = encryptServerSide("data");

      expect(result.authTag).toBeDefined();
      expect(mockCipher.getAuthTag).toHaveBeenCalled();
    });

    it("should use 100,000 PBKDF2 iterations for password hashing", () => {
      hashPassword("password");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        100000,
        expect.any(Number),
        expect.any(String)
      );
    });

    it("should use SHA-512 for PBKDF2 password hashing", () => {
      hashPassword("password");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.any(Number),
        expect.any(Number),
        "sha512"
      );
    });

    it("should use 64-byte output for password hash", () => {
      hashPassword("password");

      expect(mockPbkdf2Sync).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.any(Number),
        64,
        expect.any(String)
      );
    });

    it("should use 32-byte random salt for password hashing", () => {
      hashPassword("password");

      expect(mockRandomBytes).toHaveBeenCalledWith(32);
    });
  });
});
