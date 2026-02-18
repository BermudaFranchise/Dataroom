/**
 * Client-Side Encryption Cryptographic Primitives
 * 
 * This module provides low-level cryptographic functions for client-side
 * encryption using the Web Crypto API. It implements AES-256-GCM encryption
 * with secure key generation and derivation.
 * 
 * ## Security Specifications
 * - **Algorithm**: AES-GCM (Galois/Counter Mode)
 * - **Key Length**: 256 bits
 * - **IV Length**: 12 bytes (96 bits) - recommended for GCM
 * - **Salt Length**: 16 bytes (128 bits)
 * - **PBKDF2 Iterations**: 100,000 (for password-based key derivation)
 * 
 * ## Encryption Modes
 * 
 * ### Password-Based Encryption
 * Uses PBKDF2 to derive a key from a password:
 * - `encryptData(data, password)`: Encrypt with password
 * - `decryptData(encryptedData, password)`: Decrypt with password
 * 
 * ### Direct Key Encryption (for file uploads)
 * Uses randomly generated keys for maximum security:
 * - `generateEncryptionKey()`: Generate a random AES-256 key
 * - `encryptWithKey(data, key)`: Encrypt with generated key
 * - `decryptWithKey(ciphertext, iv, key)`: Decrypt with key
 * 
 * ## Why AES-GCM?
 * - Authenticated encryption (integrity + confidentiality)
 * - Widely supported in browsers via Web Crypto API
 * - Industry standard for file encryption
 * - Detects tampering during decryption
 * 
 * ## Browser Compatibility
 * Requires modern browser with Web Crypto API:
 * - Chrome 37+, Firefox 34+, Safari 11+, Edge 12+
 * - HTTPS required in production
 * 
 * @module lib/crypto/client-encryption
 * @see lib/files/encrypt-file - File encryption wrapper
 * @see components/upload-zone.tsx - Integration with uploads
 */

/**
 * Result of password-based encryption
 * 
 * @property ciphertext - Base64-encoded encrypted data
 * @property iv - Base64-encoded initialization vector
 * @property salt - Base64-encoded salt for key derivation
 * @property algorithm - Algorithm identifier (e.g., "AES-GCM-256")
 */
export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  algorithm: string;
}

/**
 * Parameters for PBKDF2 key derivation
 * 
 * @property salt - Random salt for key derivation
 * @property iterations - Number of PBKDF2 iterations
 * @property hash - Hash algorithm for PBKDF2
 */
export interface KeyDerivationParams {
  salt: Uint8Array;
  iterations: number;
  hash: string;
}

/** Encryption algorithm: AES-GCM */
const ALGORITHM = "AES-GCM";

/** Key length in bits: 256 */
const KEY_LENGTH = 256;

/** IV (Initialization Vector) length in bytes: 12 (recommended for GCM) */
const IV_LENGTH = 12;

/** Salt length in bytes for password-based key derivation: 16 */
const SALT_LENGTH = 16;

/** PBKDF2 iteration count for password-based key derivation: 100,000 */
const PBKDF2_ITERATIONS = 100000;

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function generateRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt.buffer as ArrayBuffer,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts data using password-based encryption (PBKDF2 + AES-GCM)
 * 
 * Derives an encryption key from the password using PBKDF2 with 100,000
 * iterations, then encrypts the data using AES-256-GCM.
 * 
 * @param data - The data to encrypt (string or ArrayBuffer)
 * @param password - The password to derive the encryption key from
 * @returns Promise resolving to EncryptedData containing ciphertext and metadata
 * @throws Error if encryption fails
 * 
 * @example
 * ```typescript
 * const encrypted = await encryptData("sensitive data", "myPassword123");
 * // encrypted.ciphertext contains base64-encoded encrypted data
 * ```
 */
export async function encryptData(
  data: string | ArrayBuffer,
  password: string
): Promise<EncryptedData> {
  const salt = generateRandomBytes(SALT_LENGTH);
  const iv = generateRandomBytes(IV_LENGTH);
  const key = await deriveKey(password, salt);

  const encoder = new TextEncoder();
  const dataBytes = typeof data === "string" ? encoder.encode(data) : new Uint8Array(data);

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    key,
    dataBytes
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
    salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
    algorithm: `${ALGORITHM}-${KEY_LENGTH}`,
  };
}

/**
 * Decrypts password-encrypted data back to its original form
 * 
 * Uses PBKDF2 to re-derive the encryption key from the password and salt,
 * then decrypts the ciphertext using AES-GCM.
 * 
 * @param encryptedData - The encrypted data object from encryptData()
 * @param password - The password used for encryption
 * @returns Promise resolving to the decrypted data as ArrayBuffer
 * @throws Error if decryption fails (wrong password, corrupted data, etc.)
 * 
 * @example
 * ```typescript
 * const decryptedBuffer = await decryptData(encrypted, "myPassword123");
 * const text = new TextDecoder().decode(decryptedBuffer);
 * ```
 */
export async function decryptData(
  encryptedData: EncryptedData,
  password: string
): Promise<ArrayBuffer> {
  const salt = new Uint8Array(base64ToArrayBuffer(encryptedData.salt));
  const iv = new Uint8Array(base64ToArrayBuffer(encryptedData.iv));
  const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);

  const key = await deriveKey(password, salt);

  return crypto.subtle.decrypt(
    { name: ALGORITHM, iv },
    key,
    ciphertext
  );
}

/**
 * Decrypts password-encrypted data and returns as a string
 * 
 * Convenience wrapper around decryptData() that automatically
 * decodes the result as UTF-8 text.
 * 
 * @param encryptedData - The encrypted data object from encryptData()
 * @param password - The password used for encryption
 * @returns Promise resolving to the decrypted string
 * @throws Error if decryption fails or data is not valid UTF-8
 * 
 * @example
 * ```typescript
 * const text = await decryptToString(encrypted, "myPassword123");
 * console.log(text); // "sensitive data"
 * ```
 */
export async function decryptToString(
  encryptedData: EncryptedData,
  password: string
): Promise<string> {
  const decrypted = await decryptData(encryptedData, password);
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Generates a new random AES-256 encryption key
 * 
 * Creates a cryptographically secure random 256-bit key suitable for
 * AES-GCM encryption. The key is returned both as a CryptoKey object
 * (for immediate use) and as a base64-encoded string (for storage).
 * 
 * This is the preferred method for file encryption as it provides
 * maximum security without password-based key derivation overhead.
 * 
 * @returns Promise resolving to object with key (CryptoKey) and exportedKey (base64 string)
 * 
 * @example
 * ```typescript
 * const { key, exportedKey } = await generateEncryptionKey();
 * // Use 'key' for encryption
 * // Store 'exportedKey' securely for later decryption
 * ```
 */
export async function generateEncryptionKey(): Promise<{ key: CryptoKey; exportedKey: string }> {
  const key = await crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );

  const exported = await crypto.subtle.exportKey("raw", key);
  return {
    key,
    exportedKey: arrayBufferToBase64(exported),
  };
}

/**
 * Encrypts data using a pre-generated AES-256 key
 * 
 * Encrypts the provided data using AES-256-GCM with a random IV.
 * This is faster than password-based encryption and is used for
 * file encryption where keys are managed separately.
 * 
 * @param data - The data to encrypt as ArrayBuffer
 * @param key - The CryptoKey to use for encryption (from generateEncryptionKey)
 * @returns Promise resolving to object with ciphertext and iv (both base64-encoded)
 * @throws Error if encryption fails
 * 
 * @example
 * ```typescript
 * const { key, exportedKey } = await generateEncryptionKey();
 * const fileBuffer = await file.arrayBuffer();
 * const { ciphertext, iv } = await encryptWithKey(fileBuffer, key);
 * // Store ciphertext, iv, and exportedKey for later decryption
 * ```
 */
export async function encryptWithKey(
  data: ArrayBuffer,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const iv = generateRandomBytes(IV_LENGTH);

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    key,
    data
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
  };
}

/**
 * Decrypts data that was encrypted with encryptWithKey
 * 
 * Uses the provided key and IV to decrypt AES-256-GCM encrypted data.
 * The key must be the same one used for encryption.
 * 
 * @param ciphertext - Base64-encoded encrypted data
 * @param iv - Base64-encoded initialization vector from encryption
 * @param key - The CryptoKey used for encryption
 * @returns Promise resolving to the decrypted data as ArrayBuffer
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 * 
 * @example
 * ```typescript
 * const decrypted = await decryptWithKey(ciphertext, iv, key);
 * const file = new File([decrypted], originalFileName);
 * ```
 */
export async function decryptWithKey(
  ciphertext: string,
  iv: string,
  key: CryptoKey
): Promise<ArrayBuffer> {
  const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
  const ciphertextBytes = base64ToArrayBuffer(ciphertext);

  return crypto.subtle.decrypt(
    { name: ALGORITHM, iv: ivBytes },
    key,
    ciphertextBytes
  );
}

/**
 * Encrypts e-signature image data using password-based encryption
 * 
 * Convenience wrapper for encrypting signature images (base64 strings)
 * with password-based encryption for secure storage.
 * 
 * @param signatureImage - Base64-encoded signature image data
 * @param password - Password for encryption
 * @returns Promise resolving to EncryptedData
 */
export async function encryptSignatureData(
  signatureImage: string,
  password: string
): Promise<EncryptedData> {
  return encryptData(signatureImage, password);
}

/**
 * Decrypts e-signature image data encrypted with encryptSignatureData
 * 
 * Convenience wrapper for decrypting signature images back to
 * their original base64 string format.
 * 
 * @param encryptedSignature - The encrypted signature data
 * @param password - Password used for encryption
 * @returns Promise resolving to the original base64 signature string
 */
export async function decryptSignatureData(
  encryptedSignature: EncryptedData,
  password: string
): Promise<string> {
  return decryptToString(encryptedSignature, password);
}

/**
 * Generates a cryptographically secure random password
 * 
 * Creates a password using crypto.getRandomValues() for maximum
 * security. Includes uppercase, lowercase, numbers, and symbols.
 * 
 * @param length - Length of the password (default: 32)
 * @returns A random password string
 * 
 * @example
 * ```typescript
 * const password = generateSecurePassword(24);
 * // e.g., "Xk9#mP2$nL7@wQ4&..."
 * ```
 */
export function generateSecurePassword(length: number = 32): string {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const randomValues = generateRandomBytes(length);
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  return password;
}

/**
 * Computes SHA-256 hash of a string
 * 
 * Creates a cryptographic hash of the input data for integrity
 * verification purposes.
 * 
 * @param data - The string to hash
 * @returns Promise resolving to base64-encoded SHA-256 hash
 * 
 * @example
 * ```typescript
 * const hash = await hashData("my data");
 * // Can be used for integrity verification
 * ```
 */
export async function hashData(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(data));
  return arrayBufferToBase64(hashBuffer);
}

/**
 * Verifies that data matches an expected hash
 * 
 * Computes the SHA-256 hash of the data and compares it to
 * the expected hash for integrity verification.
 * 
 * @param data - The string to verify
 * @param expectedHash - The expected base64-encoded hash
 * @returns Promise resolving to true if hashes match, false otherwise
 * 
 * @example
 * ```typescript
 * const isValid = await verifyHash("my data", storedHash);
 * if (!isValid) throw new Error("Data has been modified");
 * ```
 */
export async function verifyHash(data: string, expectedHash: string): Promise<boolean> {
  const actualHash = await hashData(data);
  return actualHash === expectedHash;
}
