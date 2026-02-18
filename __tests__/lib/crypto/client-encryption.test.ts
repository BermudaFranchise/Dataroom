// @ts-nocheck
/**
 * Client-Side Encryption Tests
 *
 * Tests for lib/crypto/client-encryption.ts - Web Crypto API encryption.
 *
 * These tests validate:
 * - Password-based encryption/decryption (PBKDF2 + AES-256-GCM)
 * - Direct key encryption/decryption
 * - Key generation and export
 * - Signature data encryption
 * - Secure password generation
 * - Data hashing and verification
 */

// Mock Web Crypto API
const mockEncrypt = jest.fn();
const mockDecrypt = jest.fn();
const mockGenerateKey = jest.fn();
const mockExportKey = jest.fn();
const mockImportKey = jest.fn();
const mockDeriveKey = jest.fn();
const mockDigest = jest.fn();
const mockGetRandomValues = jest.fn();

// Store original crypto
const originalCrypto = global.crypto;

// Setup crypto mock before imports
global.crypto = {
  subtle: {
    encrypt: mockEncrypt,
    decrypt: mockDecrypt,
    generateKey: mockGenerateKey,
    exportKey: mockExportKey,
    importKey: mockImportKey,
    deriveKey: mockDeriveKey,
    digest: mockDigest,
  },
  getRandomValues: mockGetRandomValues,
} as any;

// Mock btoa and atob for Node.js environment
global.btoa = (str: string) => Buffer.from(str, "binary").toString("base64");
global.atob = (str: string) => Buffer.from(str, "base64").toString("binary");

import {
  encryptData,
  decryptData,
  decryptToString,
  generateEncryptionKey,
  encryptWithKey,
  decryptWithKey,
  encryptSignatureData,
  decryptSignatureData,
  generateSecurePassword,
  hashData,
  verifyHash,
} from "@/lib/crypto/client-encryption";
import type { EncryptedData } from "@/lib/crypto/client-encryption";

describe("Client-Side Encryption", () => {
  const mockCryptoKey = { type: "secret", algorithm: { name: "AES-GCM" } };

  beforeEach(() => {
    jest.clearAllMocks();

    // Default mock implementations
    mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = i % 256;
      }
      return arr;
    });

    mockImportKey.mockResolvedValue({ type: "raw", usages: ["deriveKey"] });
    mockDeriveKey.mockResolvedValue(mockCryptoKey);
    mockGenerateKey.mockResolvedValue(mockCryptoKey);
    mockExportKey.mockResolvedValue(new ArrayBuffer(32));
    mockEncrypt.mockResolvedValue(new ArrayBuffer(32));
    mockDecrypt.mockResolvedValue(new TextEncoder().encode("decrypted data").buffer);
    mockDigest.mockResolvedValue(new ArrayBuffer(32));
  });

  afterAll(() => {
    global.crypto = originalCrypto;
  });

  describe("encryptData", () => {
    it("should encrypt string data with password", async () => {
      const result = await encryptData("sensitive data", "myPassword123");

      expect(result).toHaveProperty("ciphertext");
      expect(result).toHaveProperty("iv");
      expect(result).toHaveProperty("salt");
      expect(result).toHaveProperty("algorithm");
      expect(result.algorithm).toBe("AES-GCM-256");
    });

    it("should generate random salt for each encryption", async () => {
      let callCount = 0;
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = (callCount * 10 + i) % 256;
        }
        callCount++;
        return arr;
      });

      const result1 = await encryptData("data1", "password");
      const result2 = await encryptData("data2", "password");

      expect(result1.salt).not.toBe(result2.salt);
    });

    it("should generate random IV for each encryption", async () => {
      let callCount = 0;
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = (callCount * 20 + i) % 256;
        }
        callCount++;
        return arr;
      });

      const result1 = await encryptData("data", "password");
      const result2 = await encryptData("data", "password");

      expect(result1.iv).not.toBe(result2.iv);
    });

    it("should use PBKDF2 for key derivation", async () => {
      await encryptData("data", "password");

      expect(mockImportKey).toHaveBeenCalledWith(
        "raw",
        expect.any(Uint8Array),
        "PBKDF2",
        false,
        ["deriveKey"]
      );

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "PBKDF2",
          iterations: 100000,
          hash: "SHA-256",
        }),
        expect.any(Object),
        expect.objectContaining({ name: "AES-GCM", length: 256 }),
        false,
        ["encrypt", "decrypt"]
      );
    });

    it("should encrypt with AES-GCM algorithm", async () => {
      await encryptData("data", "password");

      expect(mockEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: "AES-GCM" }),
        expect.any(Object),
        expect.any(Uint8Array)
      );
    });

    it("should handle ArrayBuffer input", async () => {
      const buffer = new TextEncoder().encode("buffer data").buffer;

      const result = await encryptData(buffer, "password");

      expect(result).toHaveProperty("ciphertext");
      expect(mockEncrypt).toHaveBeenCalled();
    });

    it("should return base64-encoded ciphertext", async () => {
      const result = await encryptData("test", "password");

      // Base64 strings only contain [A-Za-z0-9+/=]
      expect(result.ciphertext).toMatch(/^[A-Za-z0-9+/=]+$/);
      expect(result.iv).toMatch(/^[A-Za-z0-9+/=]+$/);
      expect(result.salt).toMatch(/^[A-Za-z0-9+/=]+$/);
    });
  });

  describe("decryptData", () => {
    it("should decrypt encrypted data with correct password", async () => {
      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      const result = await decryptData(encryptedData, "password");

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(mockDecrypt).toHaveBeenCalled();
    });

    it("should use same key derivation parameters", async () => {
      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      await decryptData(encryptedData, "password");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "PBKDF2",
          iterations: 100000,
          hash: "SHA-256",
        }),
        expect.any(Object),
        expect.objectContaining({ name: "AES-GCM", length: 256 }),
        false,
        ["encrypt", "decrypt"]
      );
    });

    it("should use IV from encrypted data", async () => {
      const ivBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...ivBytes)),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      await decryptData(encryptedData, "password");

      expect(mockDecrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "AES-GCM",
          iv: expect.any(Uint8Array),
        }),
        expect.any(Object),
        expect.any(ArrayBuffer)
      );
    });

    it("should throw on wrong password", async () => {
      mockDecrypt.mockRejectedValue(new Error("Decryption failed"));

      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      await expect(decryptData(encryptedData, "wrongPassword")).rejects.toThrow(
        "Decryption failed"
      );
    });

    it("should throw on corrupted ciphertext", async () => {
      mockDecrypt.mockRejectedValue(new Error("Authentication failed"));

      const encryptedData: EncryptedData = {
        ciphertext: btoa("corrupted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      await expect(decryptData(encryptedData, "password")).rejects.toThrow(
        "Authentication failed"
      );
    });
  });

  describe("decryptToString", () => {
    it("should decrypt and return string", async () => {
      const testString = "Hello, World!";
      mockDecrypt.mockResolvedValue(new TextEncoder().encode(testString).buffer);

      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      const result = await decryptToString(encryptedData, "password");

      expect(result).toBe(testString);
    });

    it("should handle UTF-8 characters", async () => {
      const unicodeString = "Hello 世界! 🎉";
      mockDecrypt.mockResolvedValue(new TextEncoder().encode(unicodeString).buffer);

      const encryptedData: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      const result = await decryptToString(encryptedData, "password");

      expect(result).toBe(unicodeString);
    });
  });

  describe("generateEncryptionKey", () => {
    it("should generate AES-256 key", async () => {
      await generateEncryptionKey();

      expect(mockGenerateKey).toHaveBeenCalledWith(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    });

    it("should export key as base64", async () => {
      const keyBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) keyBytes[i] = i;
      mockExportKey.mockResolvedValue(keyBytes.buffer);

      const result = await generateEncryptionKey();

      expect(result.exportedKey).toMatch(/^[A-Za-z0-9+/=]+$/);
      expect(mockExportKey).toHaveBeenCalledWith("raw", mockCryptoKey);
    });

    it("should return both CryptoKey and exported string", async () => {
      const result = await generateEncryptionKey();

      expect(result).toHaveProperty("key");
      expect(result).toHaveProperty("exportedKey");
      expect(typeof result.exportedKey).toBe("string");
    });

    it("should generate unique keys each time", async () => {
      let callCount = 0;
      mockExportKey.mockImplementation(async () => {
        const bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) bytes[i] = (callCount * 10 + i) % 256;
        callCount++;
        return bytes.buffer;
      });

      const key1 = await generateEncryptionKey();
      const key2 = await generateEncryptionKey();

      expect(key1.exportedKey).not.toBe(key2.exportedKey);
    });
  });

  describe("encryptWithKey", () => {
    it("should encrypt with provided CryptoKey", async () => {
      const data = new ArrayBuffer(100);

      await encryptWithKey(data, mockCryptoKey as CryptoKey);

      expect(mockEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: "AES-GCM" }),
        mockCryptoKey,
        data
      );
    });

    it("should generate random IV", async () => {
      const data = new ArrayBuffer(100);

      await encryptWithKey(data, mockCryptoKey as CryptoKey);

      expect(mockGetRandomValues).toHaveBeenCalled();
    });

    it("should return ciphertext and IV", async () => {
      const data = new ArrayBuffer(100);

      const result = await encryptWithKey(data, mockCryptoKey as CryptoKey);

      expect(result).toHaveProperty("ciphertext");
      expect(result).toHaveProperty("iv");
      expect(result.ciphertext).toMatch(/^[A-Za-z0-9+/=]+$/);
      expect(result.iv).toMatch(/^[A-Za-z0-9+/=]+$/);
    });

    it("should not include salt (direct key encryption)", async () => {
      const data = new ArrayBuffer(100);

      const result = await encryptWithKey(data, mockCryptoKey as CryptoKey);

      expect(result).not.toHaveProperty("salt");
    });
  });

  describe("decryptWithKey", () => {
    it("should decrypt with provided key and IV", async () => {
      const ciphertext = btoa("encrypted");
      const iv = btoa(String.fromCharCode(...new Uint8Array(12)));

      await decryptWithKey(ciphertext, iv, mockCryptoKey as CryptoKey);

      expect(mockDecrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: "AES-GCM" }),
        mockCryptoKey,
        expect.any(ArrayBuffer)
      );
    });

    it("should return decrypted ArrayBuffer", async () => {
      const decryptedBytes = new Uint8Array([1, 2, 3, 4, 5]);
      mockDecrypt.mockResolvedValue(decryptedBytes.buffer);

      const ciphertext = btoa("encrypted");
      const iv = btoa(String.fromCharCode(...new Uint8Array(12)));

      const result = await decryptWithKey(ciphertext, iv, mockCryptoKey as CryptoKey);

      expect(result).toBeInstanceOf(ArrayBuffer);
    });

    it("should throw on invalid ciphertext", async () => {
      mockDecrypt.mockRejectedValue(new Error("Invalid ciphertext"));

      const ciphertext = btoa("invalid");
      const iv = btoa(String.fromCharCode(...new Uint8Array(12)));

      await expect(
        decryptWithKey(ciphertext, iv, mockCryptoKey as CryptoKey)
      ).rejects.toThrow("Invalid ciphertext");
    });
  });

  describe("encryptSignatureData", () => {
    it("should encrypt signature image string", async () => {
      const signatureBase64 = "data:image/png;base64,iVBORw0KGgo...";

      const result = await encryptSignatureData(signatureBase64, "password");

      expect(result).toHaveProperty("ciphertext");
      expect(result).toHaveProperty("iv");
      expect(result).toHaveProperty("salt");
      expect(result.algorithm).toBe("AES-GCM-256");
    });

    it("should use password-based encryption", async () => {
      const signatureBase64 = "data:image/png;base64,abc123";

      await encryptSignatureData(signatureBase64, "signaturePassword");

      expect(mockDeriveKey).toHaveBeenCalled();
    });
  });

  describe("decryptSignatureData", () => {
    it("should decrypt signature back to string", async () => {
      const originalSignature = "data:image/png;base64,iVBORw0KGgo";
      mockDecrypt.mockResolvedValue(new TextEncoder().encode(originalSignature).buffer);

      const encryptedSignature: EncryptedData = {
        ciphertext: btoa("encrypted"),
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        salt: btoa(String.fromCharCode(...new Uint8Array(16))),
        algorithm: "AES-GCM-256",
      };

      const result = await decryptSignatureData(encryptedSignature, "password");

      expect(result).toBe(originalSignature);
    });
  });

  describe("generateSecurePassword", () => {
    it("should generate password of default length (32)", () => {
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = i % 256;
        }
        return arr;
      });

      const password = generateSecurePassword();

      expect(password).toHaveLength(32);
    });

    it("should generate password of custom length", () => {
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = i % 256;
        }
        return arr;
      });

      const password = generateSecurePassword(64);

      expect(password).toHaveLength(64);
    });

    it("should include mixed characters", () => {
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = i * 7;
        }
        return arr;
      });

      const password = generateSecurePassword(100);

      // Charset includes: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*
      expect(password).toMatch(/^[A-Za-z0-9!@#$%^&*]+$/);
    });

    it("should generate different passwords each time", () => {
      let callCount = 0;
      mockGetRandomValues.mockImplementation((arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = (callCount * 13 + i) % 256;
        }
        callCount++;
        return arr;
      });

      const password1 = generateSecurePassword();
      const password2 = generateSecurePassword();

      expect(password1).not.toBe(password2);
    });

    it("should use crypto.getRandomValues", () => {
      generateSecurePassword(16);

      expect(mockGetRandomValues).toHaveBeenCalled();
    });
  });

  describe("hashData", () => {
    it("should compute SHA-256 hash", async () => {
      await hashData("test data");

      expect(mockDigest).toHaveBeenCalledWith("SHA-256", expect.any(Uint8Array));
    });

    it("should return base64-encoded hash", async () => {
      const hashBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) hashBytes[i] = i;
      mockDigest.mockResolvedValue(hashBytes.buffer);

      const result = await hashData("test");

      expect(result).toMatch(/^[A-Za-z0-9+/=]+$/);
    });

    it("should produce consistent hash for same input", async () => {
      const fixedHash = new Uint8Array(32).fill(42);
      mockDigest.mockResolvedValue(fixedHash.buffer);

      const hash1 = await hashData("same data");
      const hash2 = await hashData("same data");

      expect(hash1).toBe(hash2);
    });

    it("should produce different hash for different input", async () => {
      let callCount = 0;
      mockDigest.mockImplementation(async () => {
        const hash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) hash[i] = (callCount * 10 + i) % 256;
        callCount++;
        return hash.buffer;
      });

      const hash1 = await hashData("data1");
      const hash2 = await hashData("data2");

      expect(hash1).not.toBe(hash2);
    });

    it("should handle empty string", async () => {
      const result = await hashData("");

      expect(mockDigest).toHaveBeenCalled();
      expect(result).toBeDefined();
    });

    it("should handle Unicode characters", async () => {
      await hashData("Hello 世界 🎉");

      expect(mockDigest).toHaveBeenCalledWith("SHA-256", expect.any(Uint8Array));
    });
  });

  describe("verifyHash", () => {
    it("should return true for matching hash", async () => {
      const hashBytes = new Uint8Array(32).fill(123);
      mockDigest.mockResolvedValue(hashBytes.buffer);

      const originalHash = btoa(String.fromCharCode(...hashBytes));
      const result = await verifyHash("test data", originalHash);

      expect(result).toBe(true);
    });

    it("should return false for non-matching hash", async () => {
      const hashBytes = new Uint8Array(32).fill(100);
      mockDigest.mockResolvedValue(hashBytes.buffer);

      const wrongHash = btoa(String.fromCharCode(...new Uint8Array(32).fill(200)));
      const result = await verifyHash("test data", wrongHash);

      expect(result).toBe(false);
    });

    it("should detect tampered data", async () => {
      // Simulate different hash for different data
      mockDigest
        .mockResolvedValueOnce(new Uint8Array(32).fill(1).buffer)
        .mockResolvedValueOnce(new Uint8Array(32).fill(2).buffer);

      const originalHash = await hashData("original");
      const result = await verifyHash("tampered", originalHash);

      expect(result).toBe(false);
    });
  });

  describe("Security Properties", () => {
    it("should use 100,000 PBKDF2 iterations", async () => {
      await encryptData("data", "password");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({
          iterations: 100000,
        }),
        expect.any(Object),
        expect.any(Object),
        expect.any(Boolean),
        expect.any(Array)
      );
    });

    it("should use 256-bit key length", async () => {
      await encryptData("data", "password");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.any(Object),
        expect.any(Object),
        expect.objectContaining({ length: 256 }),
        expect.any(Boolean),
        expect.any(Array)
      );
    });

    it("should use SHA-256 for PBKDF2 hash", async () => {
      await encryptData("data", "password");

      expect(mockDeriveKey).toHaveBeenCalledWith(
        expect.objectContaining({ hash: "SHA-256" }),
        expect.any(Object),
        expect.any(Object),
        expect.any(Boolean),
        expect.any(Array)
      );
    });

    it("should generate 12-byte IV (96 bits)", async () => {
      await encryptData("data", "password");

      // First call is for salt (16 bytes), second is for IV (12 bytes)
      const calls = mockGetRandomValues.mock.calls;
      const ivCall = calls.find((call) => call[0].length === 12);
      expect(ivCall).toBeDefined();
    });

    it("should generate 16-byte salt (128 bits)", async () => {
      await encryptData("data", "password");

      const calls = mockGetRandomValues.mock.calls;
      const saltCall = calls.find((call) => call[0].length === 16);
      expect(saltCall).toBeDefined();
    });
  });
});
