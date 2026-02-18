"use client";

/**
 * React Hook for Client-Side File Encryption
 * 
 * This hook provides a convenient interface for encrypting files in React components
 * before uploading them to the server. It wraps the underlying encryption functions
 * with React state management for loading and error handling.
 * 
 * ## Features
 * - Automatic detection of WebCrypto API support
 * - Loading state management during encryption
 * - Error handling with user-friendly messages
 * - Support for single file and batch encryption
 * 
 * ## Security Flow
 * 1. Check if encryption is supported (`isSupported`)
 * 2. Call `encryptFile()` or `encryptFiles()` before upload
 * 3. Store the returned encryption key securely
 * 4. Upload encrypted file and key hash to server
 * 5. Use stored key for decryption on download
 * 
 * ## Important Notes
 * - Encryption keys are NEVER sent to the server
 * - Only the hash of the key is stored for verification
 * - Lost keys cannot be recovered - encrypted files become inaccessible
 * 
 * @module lib/hooks/use-client-encryption
 * @see lib/files/encrypt-file - Core encryption functions
 * @see components/upload-zone.tsx - Integration example
 * 
 * @example
 * ```tsx
 * function UploadForm() {
 *   const { isSupported, isEncrypting, encryptFile, error } = useClientEncryption();
 * 
 *   const handleUpload = async (file: File) => {
 *     if (isSupported) {
 *       const result = await encryptFile(file);
 *       if (result) {
 *         // Upload result.encryptedFile
 *         // Store result.encryptionKey securely
 *       }
 *     }
 *   };
 * 
 *   return (
 *     <div>
 *       {isEncrypting && <span>Encrypting...</span>}
 *       {error && <span>Error: {error}</span>}
 *     </div>
 *   );
 * }
 * ```
 */

import { useState, useCallback } from "react";
import { 
  encryptFileForUpload, 
  isClientSideEncryptionSupported,
  type EncryptedFileResult 
} from "@/lib/files/encrypt-file";

/**
 * Options for the useClientEncryption hook
 * 
 * @property enabled - Whether encryption should be performed (default: true)
 */
interface UseClientEncryptionOptions {
  enabled?: boolean;
}

/**
 * Return type for the useClientEncryption hook
 * 
 * @property isSupported - Whether WebCrypto API is available in the browser
 * @property isEncrypting - Whether an encryption operation is in progress
 * @property encryptFile - Function to encrypt a single file
 * @property encryptFiles - Function to encrypt multiple files
 * @property error - Error message if encryption failed, null otherwise
 */
interface UseClientEncryptionReturn {
  isSupported: boolean;
  isEncrypting: boolean;
  encryptFile: (file: File) => Promise<EncryptedFileResult | null>;
  encryptFiles: (files: File[]) => Promise<Map<File, EncryptedFileResult>>;
  error: string | null;
}

/**
 * React hook for client-side file encryption
 * 
 * Provides a convenient interface for encrypting files in React components
 * with automatic state management and error handling.
 * 
 * @param options - Configuration options for the hook
 * @returns Object containing encryption functions and state
 */
export function useClientEncryption(
  options: UseClientEncryptionOptions = {}
): UseClientEncryptionReturn {
  const { enabled = true } = options;
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isSupported = typeof window !== "undefined" && isClientSideEncryptionSupported();

  const encryptFile = useCallback(async (file: File): Promise<EncryptedFileResult | null> => {
    if (!enabled || !isSupported) {
      return null;
    }

    setIsEncrypting(true);
    setError(null);

    try {
      const result = await encryptFileForUpload(file);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Encryption failed";
      setError(message);
      console.error("Client-side encryption error:", err);
      return null;
    } finally {
      setIsEncrypting(false);
    }
  }, [enabled, isSupported]);

  const encryptFiles = useCallback(async (files: File[]): Promise<Map<File, EncryptedFileResult>> => {
    const results = new Map<File, EncryptedFileResult>();
    
    if (!enabled || !isSupported) {
      return results;
    }

    setIsEncrypting(true);
    setError(null);

    try {
      for (const file of files) {
        const result = await encryptFileForUpload(file);
        results.set(file, result);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Encryption failed";
      setError(message);
      console.error("Client-side encryption error:", err);
    } finally {
      setIsEncrypting(false);
    }

    return results;
  }, [enabled, isSupported]);

  return {
    isSupported,
    isEncrypting,
    encryptFile,
    encryptFiles,
    error,
  };
}
