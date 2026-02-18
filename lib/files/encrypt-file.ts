/**
 * Client-Side File Encryption Module
 * 
 * This module provides end-to-end encryption for files before they are uploaded
 * to the server. The encryption happens entirely in the browser using the WebCrypto API.
 * 
 * ## Security Architecture
 * - **Algorithm**: AES-256-GCM (Galois/Counter Mode)
 * - **Key Generation**: Cryptographically secure random 256-bit keys
 * - **IV (Initialization Vector)**: Unique random 12-byte IV per file
 * - **Key Storage**: Keys are NEVER transmitted to the server
 * 
 * ## Usage Flow
 * 1. User selects file for upload
 * 2. `encryptFileForUpload()` generates a unique encryption key
 * 3. File is encrypted with AES-256-GCM
 * 4. Encrypted file is uploaded to storage
 * 5. Only the key HASH (not the key) is stored in database for verification
 * 6. Original key must be stored securely by client application
 * 7. On download, `decryptDownloadedFile()` decrypts with the original key
 * 
 * ## Important Security Notes
 * - The encryption key is returned in the result and MUST be stored securely
 * - The server only receives a hash of the key for integrity verification
 * - If the key is lost, the file CANNOT be decrypted
 * - Each file gets a unique key and IV combination
 * 
 * @module lib/files/encrypt-file
 * @see lib/crypto/client-encryption - Low-level crypto operations
 * @see components/upload-zone.tsx - Integration with upload flow
 */

import { 
  encryptWithKey, 
  generateEncryptionKey,
  decryptWithKey,
} from "@/lib/crypto/client-encryption";

/**
 * Result of encrypting a file for upload
 * 
 * @property encryptedFile - The encrypted File object ready for upload
 * @property encryptionKey - Base64-encoded encryption key (MUST be stored securely by client)
 * @property originalName - Original filename before encryption
 * @property originalSize - Original file size in bytes before encryption
 * @property iv - Base64-encoded initialization vector used for encryption
 */
export interface EncryptedFileResult {
  encryptedFile: File;
  encryptionKey: string;
  originalName: string;
  originalSize: number;
  iv: string;
}

/**
 * Result of decrypting a downloaded file
 * 
 * @property decryptedBlob - The decrypted Blob containing original file data
 * @property originalName - Original filename to use when saving
 */
export interface DecryptedFileResult {
  decryptedBlob: Blob;
  originalName: string;
}

/**
 * Converts an ArrayBuffer to a Base64-encoded string
 * @internal
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64-encoded string to an ArrayBuffer
 * @internal
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encrypts a file for secure upload using AES-256-GCM
 * 
 * This function:
 * 1. Reads the file into memory as an ArrayBuffer
 * 2. Generates a new cryptographically secure 256-bit AES key
 * 3. Generates a random 12-byte IV (initialization vector)
 * 4. Encrypts the file data using AES-256-GCM
 * 5. Returns the encrypted file along with encryption metadata
 * 
 * ## Security Considerations
 * - The returned `encryptionKey` MUST be stored securely by the application
 * - The server should only receive the hash of the key, not the key itself
 * - Each file gets a unique key and IV combination
 * - The encrypted file has `.encrypted` appended to its filename
 * 
 * @param file - The File object to encrypt
 * @returns Promise resolving to EncryptedFileResult containing encrypted file and metadata
 * @throws Error if encryption fails or WebCrypto is not supported
 * 
 * @example
 * ```typescript
 * const file = new File(['hello'], 'test.txt', { type: 'text/plain' });
 * const result = await encryptFileForUpload(file);
 * 
 * // Upload result.encryptedFile to storage
 * // Store result.encryptionKey securely (DO NOT send to server)
 * // Send only hash of key to server for verification
 * ```
 */
export async function encryptFileForUpload(file: File): Promise<EncryptedFileResult> {
  const arrayBuffer = await file.arrayBuffer();
  
  const { key, exportedKey } = await generateEncryptionKey();
  
  const { ciphertext, iv } = await encryptWithKey(arrayBuffer, key);
  
  const encryptedData = base64ToArrayBuffer(ciphertext);
  const encryptedBlob = new Blob([encryptedData], { type: "application/octet-stream" });
  
  const encryptedFileName = `${file.name}.encrypted`;
  const encryptedFile = new File([encryptedBlob], encryptedFileName, {
    type: "application/octet-stream",
    lastModified: Date.now(),
  });

  return {
    encryptedFile,
    encryptionKey: exportedKey,
    originalName: file.name,
    originalSize: file.size,
    iv,
  };
}

/**
 * Decrypts a downloaded encrypted file using AES-256-GCM
 * 
 * This function:
 * 1. Reads the encrypted blob into memory
 * 2. Imports the provided encryption key
 * 3. Decrypts the data using AES-256-GCM with the provided IV
 * 4. Returns the decrypted blob with original metadata
 * 
 * ## Prerequisites
 * - The `encryptionKey` must be the EXACT key used during encryption
 * - The `iv` must be the EXACT IV stored during encryption
 * - Both values should have been stored securely by the client application
 * 
 * @param encryptedBlob - The encrypted blob downloaded from storage
 * @param encryptionKey - Base64-encoded encryption key (from original encryption)
 * @param iv - Base64-encoded initialization vector (from original encryption)
 * @param originalName - Original filename to restore
 * @param originalMimeType - Original MIME type to restore
 * @returns Promise resolving to DecryptedFileResult containing decrypted blob
 * @throws Error if decryption fails (wrong key, corrupted data, etc.)
 * 
 * @example
 * ```typescript
 * const encryptedBlob = await fetch(downloadUrl).then(r => r.blob());
 * const result = await decryptDownloadedFile(
 *   encryptedBlob,
 *   storedEncryptionKey,
 *   storedIv,
 *   'document.pdf',
 *   'application/pdf'
 * );
 * // result.decryptedBlob contains the original file data
 * ```
 */
export async function decryptDownloadedFile(
  encryptedBlob: Blob,
  encryptionKey: string,
  iv: string,
  originalName: string,
  originalMimeType: string
): Promise<DecryptedFileResult> {
  const encryptedArrayBuffer = await encryptedBlob.arrayBuffer();
  const ciphertext = arrayBufferToBase64(encryptedArrayBuffer);
  
  const keyBuffer = base64ToArrayBuffer(encryptionKey);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  
  const decryptedBuffer = await decryptWithKey(ciphertext, iv, cryptoKey);
  const decryptedBlob = new Blob([decryptedBuffer], { type: originalMimeType });

  return {
    decryptedBlob,
    originalName,
  };
}

/**
 * Checks if client-side encryption is supported in the current browser
 * 
 * This function verifies:
 * 1. Running in a browser environment (window exists)
 * 2. WebCrypto API is available (crypto exists)
 * 3. SubtleCrypto interface is available (crypto.subtle exists)
 * 
 * ## Browser Support
 * - Modern browsers (Chrome 37+, Firefox 34+, Safari 11+, Edge 12+)
 * - Requires HTTPS in production (WebCrypto requirement)
 * - Not available in older browsers or Node.js without polyfills
 * 
 * @returns true if encryption is supported, false otherwise
 * 
 * @example
 * ```typescript
 * if (isClientSideEncryptionSupported()) {
 *   const encrypted = await encryptFileForUpload(file);
 * } else {
 *   console.warn('Encryption not supported, uploading unencrypted');
 * }
 * ```
 */
export function isClientSideEncryptionSupported(): boolean {
  return typeof window !== "undefined" && 
         typeof crypto !== "undefined" && 
         typeof crypto.subtle !== "undefined";
}
