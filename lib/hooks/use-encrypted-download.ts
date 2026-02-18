/**
 * Encrypted Document Download Hook
 * 
 * Provides functionality to download and decrypt client-side encrypted documents.
 * Works with documents encrypted using the upload-zone.tsx encryption flow.
 * 
 * ## Security Architecture
 * - Downloads encrypted file data from storage
 * - Decrypts using WebCrypto AES-256-GCM
 * - Key must be retrieved from secure client-side storage
 * - Decryption happens entirely in the browser
 * 
 * ## Usage
 * ```tsx
 * const { downloadAndDecrypt, isDownloading, error } = useEncryptedDownload();
 * 
 * // Download and decrypt a document
 * const success = await downloadAndDecrypt({
 *   downloadUrl: "https://storage.example.com/encrypted-file.bin",
 *   encryptionKey: storedEncryptionKey,
 *   iv: document.encryptionIv,
 *   originalFileName: "contract.pdf",
 *   originalMimeType: "application/pdf"
 * });
 * ```
 * 
 * ## Key Management
 * The encryption key must be stored securely on the client side.
 * Options include:
 * - IndexedDB with encryption
 * - Browser's Credential Management API
 * - Hardware security key integration
 * 
 * @see lib/files/encrypt-file.ts - Encryption implementation
 * @see lib/crypto/client-encryption.ts - Core crypto functions
 */

"use client";

import { useState, useCallback } from "react";
import { decryptWithKey } from "@/lib/crypto/client-encryption";

interface DownloadOptions {
  downloadUrl: string;
  encryptionKey: string;
  iv: string;
  originalFileName: string;
  originalMimeType?: string;
}

interface UseEncryptedDownloadResult {
  downloadAndDecrypt: (options: DownloadOptions) => Promise<boolean>;
  isDownloading: boolean;
  progress: number;
  error: string | null;
  clearError: () => void;
}

async function importEncryptionKey(keyBase64: string): Promise<CryptoKey> {
  const keyBytes = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function useEncryptedDownload(): UseEncryptedDownloadResult {
  const [isDownloading, setIsDownloading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => setError(null), []);

  const downloadAndDecrypt = useCallback(
    async (options: DownloadOptions): Promise<boolean> => {
      const { downloadUrl, encryptionKey, iv, originalFileName, originalMimeType } = options;

      setIsDownloading(true);
      setProgress(0);
      setError(null);

      try {
        setProgress(10);
        const response = await fetch(downloadUrl);
        
        if (!response.ok) {
          throw new Error(`Failed to download file: ${response.statusText}`);
        }

        setProgress(30);
        const contentLength = response.headers.get("Content-Length");
        const totalBytes = contentLength ? parseInt(contentLength, 10) : 0;
        
        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error("Failed to read response body");
        }

        const chunks: Uint8Array[] = [];
        let receivedBytes = 0;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          chunks.push(value);
          receivedBytes += value.length;
          
          if (totalBytes > 0) {
            const downloadProgress = 30 + Math.floor((receivedBytes / totalBytes) * 40);
            setProgress(downloadProgress);
          }
        }

        setProgress(70);
        const encryptedData = new Uint8Array(receivedBytes);
        let offset = 0;
        for (const chunk of chunks) {
          encryptedData.set(chunk, offset);
          offset += chunk.length;
        }

        const ciphertextBase64 = btoa(String.fromCharCode(...encryptedData));

        setProgress(80);
        const cryptoKey = await importEncryptionKey(encryptionKey);

        setProgress(90);
        const decryptedBuffer = await decryptWithKey(ciphertextBase64, iv, cryptoKey);

        setProgress(95);
        const mimeType = originalMimeType || getMimeType(originalFileName);
        const blob = new Blob([decryptedBuffer], { type: mimeType });

        triggerDownload(blob, originalFileName);
        
        setProgress(100);
        setIsDownloading(false);
        return true;

      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : "Failed to download and decrypt file";
        setError(errorMessage);
        setIsDownloading(false);
        setProgress(0);
        return false;
      }
    },
    []
  );

  return {
    downloadAndDecrypt,
    isDownloading,
    progress,
    error,
    clearError,
  };
}

function getMimeType(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  const mimeTypes: Record<string, string> = {
    pdf: "application/pdf",
    doc: "application/msword",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    svg: "image/svg+xml",
    mp4: "video/mp4",
    mp3: "audio/mpeg",
    zip: "application/zip",
    txt: "text/plain",
    csv: "text/csv",
    json: "application/json",
  };
  return mimeTypes[ext || ""] || "application/octet-stream";
}

export async function decryptAndDownloadFile(
  encryptedBlob: Blob,
  encryptionKey: string,
  iv: string,
  originalFileName: string,
  originalMimeType?: string
): Promise<void> {
  const encryptedBuffer = await encryptedBlob.arrayBuffer();
  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextBase64 = btoa(String.fromCharCode(...encryptedBytes));
  
  const keyBytes = Uint8Array.from(atob(encryptionKey), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await decryptWithKey(ciphertextBase64, iv, cryptoKey);
  
  const mimeType = originalMimeType || getMimeType(originalFileName);
  const blob = new Blob([decryptedBuffer], { type: mimeType });
  
  triggerDownload(blob, originalFileName);
}
