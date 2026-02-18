/**
 * Document Creation and Upload Module
 * 
 * This module handles the creation of document records in the database
 * after files have been uploaded to storage. It supports both standard
 * and client-side encrypted document uploads.
 * 
 * ## Upload Flow
 * 1. File is uploaded to storage (Vercel Blob, Replit Object Storage, or S3)
 * 2. Client calls `createDocument()` with file metadata
 * 3. Server validates and creates Document record with version history
 * 4. If encrypted, encryption metadata is stored for future decryption
 * 
 * ## Encryption Support
 * When client-side encryption is enabled:
 * - `isClientEncrypted`: true
 * - `encryptionKeyHash`: SHA-256 hash of the encryption key (NOT the key itself)
 * - `encryptionIv`: Initialization vector used for AES-GCM encryption
 * - `originalFileName`: Original filename before encryption
 * - `originalFileSize`: Original file size before encryption
 * 
 * ## Important Security Notes
 * - The encryption key is NEVER stored on the server
 * - Only the key hash is stored for verification purposes
 * - If the key is lost, the file cannot be decrypted
 * 
 * @module lib/documents/create-document
 * @see lib/files/encrypt-file - Client-side encryption
 * @see lib/api/documents/process-document - Server-side processing
 * @see components/upload-zone.tsx - Upload UI integration
 */

import { DocumentStorageType } from "@prisma/client";
import z from "zod";

/**
 * Data required to create a new document record
 * 
 * @property name - Display name for the document
 * @property key - Storage key/URL for the file
 * @property storageType - Where the file is stored (S3_PATH, VERCEL_BLOB)
 * @property contentType - MIME type of the file
 * @property supportedFileType - Simplified type (pdf, sheet, docs, etc.)
 * @property fileSize - File size in bytes
 * @property numPages - Number of pages (for PDFs)
 * @property enableExcelAdvancedMode - Enable advanced Excel features
 * @property isClientEncrypted - Whether file was encrypted client-side
 * @property encryptionKeyHash - Hash of encryption key (NOT the key itself)
 * @property encryptionIv - Initialization vector for decryption
 * @property originalFileName - Original filename before encryption
 * @property originalFileSize - Original file size before encryption
 */
export type DocumentData = {
  name: string;
  key: string;
  storageType: DocumentStorageType;
  contentType: string | null; // actual file mime type
  supportedFileType: string; // supported types: "pdf", "sheet", "docs", "slides", "map", "zip"
  fileSize: number | undefined; // file size in bytes
  numPages?: number;
  enableExcelAdvancedMode?: boolean;
  // Client-side encryption metadata
  isClientEncrypted?: boolean;
  encryptionKeyHash?: string;
  encryptionIv?: string;
  originalFileName?: string;
  originalFileSize?: number;
};

/**
 * Creates a new document record in the database
 * 
 * Stores document metadata including storage location, encryption status,
 * and optional folder placement. Supports client-side encrypted documents
 * by preserving encryption metadata for later decryption.
 * 
 * @param options - Document creation options
 * @param options.documentData - Document metadata including name, storage key, and encryption info
 * @param options.teamId - The team ID this document belongs to
 * @param options.numPages - Optional page count for PDFs
 * @param options.folderPathName - Optional folder path for organization
 * @param options.createLink - Whether to create a shareable link
 * @param options.token - Optional auth token for API calls
 * @returns Promise resolving to the created document record
 * 
 * @example
 * ```typescript
 * const doc = await createDocument({
 *   documentData: {
 *     name: "contract.pdf",
 *     key: "uploads/abc123.pdf",
 *     storageType: "REPLIT",
 *     isClientEncrypted: true,
 *     encryptionKeyHash: "sha256hash...",
 *     encryptionIv: "base64iv..."
 *   },
 *   teamId: "team123"
 * });
 * ```
 */
export const createDocument = async ({
  documentData,
  teamId,
  numPages,
  folderPathName,
  createLink = false,
  token,
}: {
  documentData: DocumentData;
  teamId: string;
  numPages?: number;
  folderPathName?: string;
  createLink?: boolean;
  token?: string;
}) => {
  // create a document in the database with the blob url
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || (typeof window !== 'undefined' ? window.location.origin : '');
  const response = await fetch(
    `${baseUrl}/api/teams/${teamId}/documents`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        name: documentData.name,
        url: documentData.key,
        storageType: documentData.storageType,
        numPages: numPages,
        folderPathName: folderPathName,
        type: documentData.supportedFileType,
        contentType: documentData.contentType,
        createLink: createLink,
        fileSize: documentData.fileSize,
        // Client-side encryption metadata
        isClientEncrypted: documentData.isClientEncrypted,
        encryptionKeyHash: documentData.encryptionKeyHash,
        encryptionIv: documentData.encryptionIv,
        originalFileName: documentData.originalFileName,
        originalFileSize: documentData.originalFileSize,
      }),
    },
  );

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error);
  }

  return response;
};

export const createAgreementDocument = async ({
  documentData,
  teamId,
  numPages,
  folderPathName,
}: {
  documentData: DocumentData;
  teamId: string;
  numPages?: number;
  folderPathName?: string;
}) => {
  // create a document in the database with the blob url
  const response = await fetch(`/api/teams/${teamId}/documents/agreement`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: documentData.name,
      url: documentData.key,
      storageType: documentData.storageType,
      numPages: numPages,
      folderPathName: folderPathName,
      type: documentData.supportedFileType,
      contentType: documentData.contentType,
      fileSize: documentData.fileSize,
    }),
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response;
};

// create a new version in the database
export const createNewDocumentVersion = async ({
  documentData,
  documentId,
  teamId,
  numPages,
}: {
  documentData: DocumentData;
  documentId: string;
  teamId: string;
  numPages?: number;
}) => {
  try {
    const documentIdParsed = z.string().cuid().parse(documentId);

    const response = await fetch(
      `/api/teams/${teamId}/documents/${documentIdParsed}/versions`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: documentData.key,
          storageType: documentData.storageType,
          numPages: numPages,
          type: documentData.supportedFileType,
          contentType: documentData.contentType,
          fileSize: documentData.fileSize,
        }),
      },
    );

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response;
  } catch (error) {
    console.error("Error creating new document version:", error);
    throw new Error("Invalid document ID or team ID");
  }
};
