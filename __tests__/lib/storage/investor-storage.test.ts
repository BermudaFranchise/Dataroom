// @ts-nocheck
/**
 * Tests for lib/storage/investor-storage.ts
 * Covers: path construction, filename sanitization, upload/download, integrity verification
 */
import crypto from "crypto";

// Mock storage provider
const mockProvider = {
  put: jest.fn().mockResolvedValue({ hash: "abc123hash" }),
  get: jest.fn().mockResolvedValue(Buffer.from("file-contents")),
  getSignedUrl: jest.fn().mockResolvedValue("https://signed-url.com/doc"),
  list: jest.fn().mockResolvedValue({ keys: ["investors/inv-1/documents/nda/file.pdf"] }),
  delete: jest.fn().mockResolvedValue(true),
  copy: jest.fn().mockResolvedValue(true),
  exists: jest.fn().mockResolvedValue(true),
};

jest.mock("@/lib/storage/providers", () => ({
  getStorageProvider: jest.fn(() => mockProvider),
}));

import {
  getInvestorStoragePath,
  getInvestorDocumentPath,
  getInvestorSignaturePath,
  uploadInvestorDocument,
  uploadInvestorSignature,
  getInvestorDocument,
  getInvestorDocumentUrl,
  getInvestorDocumentSignedUrl,
  listInvestorDocuments,
  deleteInvestorDocument,
  verifyDocumentIntegrity,
  copyInvestorDocument,
  investorDocumentExists,
  resetStorageProvider,
} from "@/lib/storage/investor-storage";

beforeEach(() => {
  jest.clearAllMocks();
  resetStorageProvider();
});

describe("Path construction", () => {
  describe("getInvestorStoragePath", () => {
    it("constructs correct base path", () => {
      const path = getInvestorStoragePath("inv-123", "my-doc.pdf");
      expect(path).toBe("investors/inv-123/my-doc.pdf");
    });

    it("sanitizes dangerous filename characters", () => {
      const path = getInvestorStoragePath("inv-1", "../../etc/passwd");
      // The regex [^a-zA-Z0-9._-] keeps dots and hyphens, replaces slashes
      expect(path).toBe("investors/inv-1/.._.._etc_passwd");
      // Note: dots are preserved by the sanitizer - path traversal via ".." still possible
      // This is a known limitation worth fixing in production code
    });

    it("sanitizes spaces and special chars in filename", () => {
      const path = getInvestorStoragePath("inv-1", "my doc (final).pdf");
      expect(path).toBe("investors/inv-1/my_doc__final_.pdf");
    });

    it("preserves valid filename characters", () => {
      const path = getInvestorStoragePath("inv-1", "document-v2_final.pdf");
      expect(path).toBe("investors/inv-1/document-v2_final.pdf");
    });
  });

  describe("getInvestorDocumentPath", () => {
    it("includes docType and timestamp", () => {
      const before = Date.now();
      const path = getInvestorDocumentPath("inv-1", "nda", "doc-123");
      const after = Date.now();

      expect(path).toMatch(/^investors\/inv-1\/documents\/nda\/doc-123_\d+$/);
      // Verify timestamp is within range
      const timestamp = parseInt(path.split("_").pop()!);
      expect(timestamp).toBeGreaterThanOrEqual(before);
      expect(timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe("getInvestorSignaturePath", () => {
    it("includes docType and timestamp", () => {
      const path = getInvestorSignaturePath("inv-1", "subscription");
      expect(path).toMatch(/^investors\/inv-1\/signatures\/subscription_\d+$/);
    });
  });
});

describe("Upload operations", () => {
  describe("uploadInvestorDocument", () => {
    it("uploads Buffer content with encryption enabled", async () => {
      const content = Buffer.from("PDF content here");
      const result = await uploadInvestorDocument("inv-1", "nda", content, "agreement.pdf");

      // uploadInvestorDocument passes "documents/{docType}/{filename}" as the filename
      // to getInvestorStoragePath, which sanitizes / to _, producing a flat path
      expect(result.path).toBe("investors/inv-1/documents_nda_agreement.pdf");
      expect(result.hash).toBe("abc123hash");

      const putCall = mockProvider.put.mock.calls[0];
      expect(putCall[1]).toEqual(content);
      expect(putCall[2].encrypt).toBe(true);
      expect(putCall[2].contentType).toBe("application/pdf");
    });

    it("converts base64 string to Buffer before upload", async () => {
      const base64Content = Buffer.from("test content").toString("base64");
      await uploadInvestorDocument("inv-1", "subscription", base64Content, "sub.pdf");

      const putCall = mockProvider.put.mock.calls[0];
      expect(Buffer.isBuffer(putCall[1])).toBe(true);
      expect(putCall[1].toString()).toBe("test content");
    });

    it("detects content type from file extension", async () => {
      await uploadInvestorDocument("inv-1", "photo", Buffer.from(""), "profile.png");
      expect(mockProvider.put.mock.calls[0][2].contentType).toBe("image/png");

      await uploadInvestorDocument("inv-1", "photo", Buffer.from(""), "photo.jpg");
      expect(mockProvider.put.mock.calls[1][2].contentType).toBe("image/jpeg");

      await uploadInvestorDocument("inv-1", "photo", Buffer.from(""), "photo.jpeg");
      expect(mockProvider.put.mock.calls[2][2].contentType).toBe("image/jpeg");

      await uploadInvestorDocument("inv-1", "photo", Buffer.from(""), "photo.gif");
      expect(mockProvider.put.mock.calls[3][2].contentType).toBe("image/gif");

      await uploadInvestorDocument("inv-1", "doc", Buffer.from(""), "file.doc");
      expect(mockProvider.put.mock.calls[4][2].contentType).toBe("application/msword");

      await uploadInvestorDocument("inv-1", "doc", Buffer.from(""), "file.docx");
      expect(mockProvider.put.mock.calls[5][2].contentType).toBe(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      );

      await uploadInvestorDocument("inv-1", "misc", Buffer.from(""), "file.xyz");
      expect(mockProvider.put.mock.calls[6][2].contentType).toBe("application/octet-stream");
    });
  });

  describe("uploadInvestorSignature", () => {
    it("extracts base64 from data URL and uploads as PNG", async () => {
      const dataUrl = "data:image/png;base64,iVBORw0KGgo=";
      const result = await uploadInvestorSignature("inv-1", "lpa", dataUrl);

      expect(result.path).toMatch(/^investors\/inv-1\/signatures\/lpa_\d+$/);
      expect(result.hash).toBe("abc123hash");

      const putCall = mockProvider.put.mock.calls[0];
      expect(Buffer.isBuffer(putCall[1])).toBe(true);
      expect(putCall[2].encrypt).toBe(true);
      expect(putCall[2].contentType).toBe("image/png");
    });

    it("handles raw base64 (no data URL prefix)", async () => {
      const raw = "iVBORw0KGgo=";
      await uploadInvestorSignature("inv-1", "nda", raw);

      const putCall = mockProvider.put.mock.calls[0];
      expect(Buffer.isBuffer(putCall[1])).toBe(true);
    });
  });
});

describe("Download operations", () => {
  describe("getInvestorDocument", () => {
    it("downloads and decrypts document", async () => {
      const result = await getInvestorDocument("investors/inv-1/doc.pdf");

      expect(result).toEqual(Buffer.from("file-contents"));
      expect(mockProvider.get).toHaveBeenCalledWith("investors/inv-1/doc.pdf", { decrypt: true });
    });

    it("returns null on error", async () => {
      mockProvider.get.mockRejectedValueOnce(new Error("Network error"));

      const result = await getInvestorDocument("investors/inv-1/doc.pdf");
      expect(result).toBeNull();
    });
  });

  describe("getInvestorDocumentUrl", () => {
    it("returns data URL with correct MIME type for PDF", async () => {
      mockProvider.get.mockResolvedValueOnce(Buffer.from("pdf-data"));

      const result = await getInvestorDocumentUrl("investors/inv-1/doc.pdf");

      expect(result).toMatch(/^data:application\/pdf;base64,/);
    });

    it("returns data URL with image MIME type for images", async () => {
      mockProvider.get.mockResolvedValueOnce(Buffer.from("png-data"));

      const result = await getInvestorDocumentUrl("investors/inv-1/photo.png");

      expect(result).toMatch(/^data:image\/png;base64,/);
    });

    it("returns null when document not found", async () => {
      mockProvider.get.mockResolvedValueOnce(null);

      const result = await getInvestorDocumentUrl("investors/inv-1/missing.pdf");
      expect(result).toBeNull();
    });

    it("returns null on error", async () => {
      mockProvider.get.mockRejectedValueOnce(new Error("Access denied"));

      const result = await getInvestorDocumentUrl("investors/inv-1/doc.pdf");
      expect(result).toBeNull();
    });
  });

  describe("getInvestorDocumentSignedUrl", () => {
    it("returns signed URL with default 1h expiry", async () => {
      const result = await getInvestorDocumentSignedUrl("investors/inv-1/doc.pdf");

      expect(result).toBe("https://signed-url.com/doc");
      expect(mockProvider.getSignedUrl).toHaveBeenCalledWith("investors/inv-1/doc.pdf", {
        expiresIn: 3600,
        method: "GET",
      });
    });

    it("allows custom expiry", async () => {
      await getInvestorDocumentSignedUrl("investors/inv-1/doc.pdf", 600);

      expect(mockProvider.getSignedUrl).toHaveBeenCalledWith("investors/inv-1/doc.pdf", {
        expiresIn: 600,
        method: "GET",
      });
    });

    it("returns null on error", async () => {
      mockProvider.getSignedUrl.mockRejectedValueOnce(new Error("Auth failed"));

      const result = await getInvestorDocumentSignedUrl("investors/inv-1/doc.pdf");
      expect(result).toBeNull();
    });
  });
});

describe("List, Delete, Copy, Exists", () => {
  it("lists documents with investor prefix", async () => {
    const result = await listInvestorDocuments("inv-1");

    expect(result).toEqual(["investors/inv-1/documents/nda/file.pdf"]);
    expect(mockProvider.list).toHaveBeenCalledWith({ prefix: "investors/inv-1/documents/" });
  });

  it("returns empty array on list error", async () => {
    mockProvider.list.mockRejectedValueOnce(new Error("Bucket error"));

    const result = await listInvestorDocuments("inv-1");
    expect(result).toEqual([]);
  });

  it("deletes document", async () => {
    const result = await deleteInvestorDocument("investors/inv-1/doc.pdf");

    expect(result).toBe(true);
    expect(mockProvider.delete).toHaveBeenCalledWith("investors/inv-1/doc.pdf");
  });

  it("returns false on delete error", async () => {
    mockProvider.delete.mockRejectedValueOnce(new Error("Permission denied"));

    const result = await deleteInvestorDocument("investors/inv-1/doc.pdf");
    expect(result).toBe(false);
  });

  it("copies document between paths", async () => {
    const result = await copyInvestorDocument("source/path", "dest/path");

    expect(result).toBe(true);
    expect(mockProvider.copy).toHaveBeenCalledWith("source/path", "dest/path");
  });

  it("returns false on copy error", async () => {
    mockProvider.copy.mockRejectedValueOnce(new Error("Not found"));

    const result = await copyInvestorDocument("source", "dest");
    expect(result).toBe(false);
  });

  it("checks document existence", async () => {
    const result = await investorDocumentExists("investors/inv-1/doc.pdf");

    expect(result).toBe(true);
    expect(mockProvider.exists).toHaveBeenCalledWith("investors/inv-1/doc.pdf");
  });

  it("returns false on exists error", async () => {
    mockProvider.exists.mockRejectedValueOnce(new Error("Error"));

    const result = await investorDocumentExists("investors/inv-1/doc.pdf");
    expect(result).toBe(false);
  });
});

describe("verifyDocumentIntegrity", () => {
  it("returns true for matching SHA-256 hash", () => {
    const content = Buffer.from("important document content");
    const hash = crypto.createHash("sha256").update(content).digest("hex");

    expect(verifyDocumentIntegrity(content, hash)).toBe(true);
  });

  it("returns false for mismatched hash", () => {
    const content = Buffer.from("real content");
    const fakeHash = crypto.createHash("sha256").update("fake content").digest("hex");

    expect(verifyDocumentIntegrity(content, fakeHash)).toBe(false);
  });

  it("returns false for tampered content", () => {
    const original = Buffer.from("original");
    const hash = crypto.createHash("sha256").update(original).digest("hex");

    const tampered = Buffer.from("tampered");
    expect(verifyDocumentIntegrity(tampered, hash)).toBe(false);
  });

  it("handles empty content", () => {
    const content = Buffer.from("");
    const hash = crypto.createHash("sha256").update(content).digest("hex");

    expect(verifyDocumentIntegrity(content, hash)).toBe(true);
  });
});
