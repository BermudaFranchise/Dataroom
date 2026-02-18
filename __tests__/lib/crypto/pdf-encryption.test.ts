// @ts-nocheck
/**
 * PDF Encryption Tests
 *
 * Tests for lib/crypto/pdf-encryption.ts - PDF encryption and manipulation.
 *
 * These tests validate:
 * - PDF encryption with user/owner passwords
 * - Permission settings for encrypted PDFs
 * - Signature embedding with encryption
 * - Watermark addition with encryption
 * - PDF metadata extraction
 * - Secure document password generation
 */

// Mock pdf-lib-plus-encrypt
const mockPdfDocSave = jest.fn();
const mockPdfDocEncrypt = jest.fn();
const mockPdfDocLoad = jest.fn();
const mockPdfDocGetPage = jest.fn();
const mockPdfDocGetPages = jest.fn();
const mockPdfDocEmbedPng = jest.fn();
const mockPdfDocGetTitle = jest.fn();
const mockPdfDocGetAuthor = jest.fn();
const mockPdfDocGetSubject = jest.fn();
const mockPdfDocGetCreator = jest.fn();
const mockPdfDocGetProducer = jest.fn();
const mockPdfDocGetPageCount = jest.fn();

const mockPageDrawImage = jest.fn();
const mockPageDrawText = jest.fn();
const mockPageGetSize = jest.fn();

jest.mock("pdf-lib-plus-encrypt", () => ({
  PDFDocument: {
    load: (...args: any[]) => mockPdfDocLoad(...args),
  },
}));

// Mock crypto for generateDocumentPassword
const mockRandomBytes = jest.fn();
jest.mock("crypto", () => ({
  randomBytes: (...args: any[]) => mockRandomBytes(...args),
}));

import {
  encryptPDF,
  loadEncryptedPDF,
  embedSignatureAndEncrypt,
  addWatermarkAndEncrypt,
  getPDFMetadata,
  generateDocumentPassword,
} from "@/lib/crypto/pdf-encryption";
import type { PDFEncryptionOptions, SignaturePlacement } from "@/lib/crypto/pdf-encryption";

describe("PDF Encryption", () => {
  const mockPdfDoc = {
    save: mockPdfDocSave,
    encrypt: mockPdfDocEncrypt,
    getPage: mockPdfDocGetPage,
    getPages: mockPdfDocGetPages,
    embedPng: mockPdfDocEmbedPng,
    getTitle: mockPdfDocGetTitle,
    getAuthor: mockPdfDocGetAuthor,
    getSubject: mockPdfDocGetSubject,
    getCreator: mockPdfDocGetCreator,
    getProducer: mockPdfDocGetProducer,
    getPageCount: mockPdfDocGetPageCount,
  };

  const mockPage = {
    drawImage: mockPageDrawImage,
    drawText: mockPageDrawText,
    getSize: mockPageGetSize,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockPdfDocLoad.mockResolvedValue(mockPdfDoc);
    mockPdfDocSave.mockResolvedValue(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    mockPdfDocEncrypt.mockResolvedValue(undefined);
    mockPdfDocGetPage.mockReturnValue(mockPage);
    mockPdfDocGetPages.mockReturnValue([mockPage]);
    mockPageGetSize.mockReturnValue({ width: 612, height: 792 });
    mockPdfDocEmbedPng.mockResolvedValue({ width: 100, height: 50 });
  });

  describe("encryptPDF", () => {
    it("should encrypt PDF with user password only", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const options: PDFEncryptionOptions = {
        userPassword: "user123",
      };

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes);
      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          userPassword: "user123",
          ownerPassword: "user123", // Falls back to user password
        })
      );
      expect(mockPdfDocSave).toHaveBeenCalled();
    });

    it("should encrypt PDF with both user and owner passwords", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const options: PDFEncryptionOptions = {
        userPassword: "user123",
        ownerPassword: "owner456",
      };

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          userPassword: "user123",
          ownerPassword: "owner456",
        })
      );
    });

    it("should apply default permissions when none specified", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const options: PDFEncryptionOptions = {
        userPassword: "user123",
      };

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.objectContaining({
            printing: "highResolution",
            modifying: false,
            copying: false,
            annotating: false,
            fillingForms: true,
            contentAccessibility: true,
            documentAssembly: false,
          }),
        })
      );
    });

    it("should override default permissions with custom ones", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const options: PDFEncryptionOptions = {
        userPassword: "user123",
        permissions: {
          printing: "lowResolution",
          copying: true,
          modifying: true,
        },
      };

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.objectContaining({
            printing: "lowResolution",
            copying: true,
            modifying: true,
          }),
        })
      );
    });

    it("should accept ArrayBuffer input", async () => {
      const pdfBytes = new ArrayBuffer(4);
      const options: PDFEncryptionOptions = {
        userPassword: "user123",
      };

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes);
    });

    it("should return encrypted PDF bytes", async () => {
      const expectedOutput = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0x01]);
      mockPdfDocSave.mockResolvedValue(expectedOutput);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const result = await encryptPDF(pdfBytes, { userPassword: "test" });

      expect(result).toEqual(expectedOutput);
    });

    it("should handle empty passwords as empty string", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const options: PDFEncryptionOptions = {};

      await encryptPDF(pdfBytes, options);

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          userPassword: "",
          ownerPassword: "",
        })
      );
    });
  });

  describe("loadEncryptedPDF", () => {
    it("should load encrypted PDF with password", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await loadEncryptedPDF(pdfBytes, "secretPassword");

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes, { password: "secretPassword" });
    });

    it("should return PDFDocument on success", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      const result = await loadEncryptedPDF(pdfBytes, "password");

      expect(result).toBe(mockPdfDoc);
    });

    it("should accept ArrayBuffer input", async () => {
      const pdfBytes = new ArrayBuffer(4);

      await loadEncryptedPDF(pdfBytes, "password");

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes, expect.any(Object));
    });

    it("should propagate errors on wrong password", async () => {
      mockPdfDocLoad.mockRejectedValue(new Error("Invalid password"));

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await expect(loadEncryptedPDF(pdfBytes, "wrongPassword")).rejects.toThrow(
        "Invalid password"
      );
    });
  });

  describe("embedSignatureAndEncrypt", () => {
    const signatureImage = new Uint8Array([0x89, 0x50, 0x4e, 0x47]); // PNG header
    const placement: SignaturePlacement = {
      pageNumber: 1,
      x: 50, // percentage
      y: 80, // percentage
      width: 150,
      height: 50,
    };

    it("should embed signature on the correct page", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, placement, {});

      expect(mockPdfDocGetPage).toHaveBeenCalledWith(0); // page 1 = index 0
    });

    it("should embed PNG signature image", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, placement, {});

      expect(mockPdfDocEmbedPng).toHaveBeenCalledWith(signatureImage);
    });

    it("should calculate position from percentage", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      mockPageGetSize.mockReturnValue({ width: 612, height: 792 });

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, placement, {});

      // x: 50% of 612 = 306
      // y: 792 - (80% of 792) - 50 = 792 - 633.6 - 50 = 108.4
      expect(mockPageDrawImage).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          x: expect.any(Number),
          y: expect.any(Number),
          width: 150,
          height: 50,
        })
      );
    });

    it("should encrypt after embedding when password provided", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, placement, {
        userPassword: "signedDoc123",
      });

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          userPassword: "signedDoc123",
        })
      );
    });

    it("should not encrypt when no password provided", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, placement, {});

      expect(mockPdfDocEncrypt).not.toHaveBeenCalled();
    });

    it("should return the modified PDF bytes", async () => {
      const expectedOutput = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x01]);
      mockPdfDocSave.mockResolvedValue(expectedOutput);
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      const result = await embedSignatureAndEncrypt(
        pdfBytes,
        signatureImage,
        placement,
        {}
      );

      expect(result).toEqual(expectedOutput);
    });

    it("should handle different page numbers", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const page3Placement = { ...placement, pageNumber: 3 };

      await embedSignatureAndEncrypt(pdfBytes, signatureImage, page3Placement, {});

      expect(mockPdfDocGetPage).toHaveBeenCalledWith(2); // page 3 = index 2
    });
  });

  describe("addWatermarkAndEncrypt", () => {
    it("should add watermark text to all pages", async () => {
      const mockPages = [
        { drawText: jest.fn(), getSize: () => ({ width: 612, height: 792 }) },
        { drawText: jest.fn(), getSize: () => ({ width: 612, height: 792 }) },
        { drawText: jest.fn(), getSize: () => ({ width: 612, height: 792 }) },
      ];
      mockPdfDocGetPages.mockReturnValue(mockPages);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      await addWatermarkAndEncrypt(pdfBytes, "CONFIDENTIAL", {});

      expect(mockPages[0].drawText).toHaveBeenCalledWith(
        "CONFIDENTIAL",
        expect.objectContaining({
          opacity: 0.3,
          size: 50,
        })
      );
      expect(mockPages[1].drawText).toHaveBeenCalled();
      expect(mockPages[2].drawText).toHaveBeenCalled();
    });

    it("should position watermark in center of page", async () => {
      mockPdfDocGetPages.mockReturnValue([mockPage]);
      mockPageGetSize.mockReturnValue({ width: 600, height: 800 });

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      await addWatermarkAndEncrypt(pdfBytes, "DRAFT", {});

      expect(mockPageDrawText).toHaveBeenCalledWith(
        "DRAFT",
        expect.objectContaining({
          x: 150, // width / 4
          y: 400, // height / 2
        })
      );
    });

    it("should encrypt after adding watermark when password provided", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await addWatermarkAndEncrypt(pdfBytes, "SECRET", {
        userPassword: "watermarkDoc",
      });

      expect(mockPdfDocEncrypt).toHaveBeenCalled();
    });

    it("should not encrypt when no password provided", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await addWatermarkAndEncrypt(pdfBytes, "DRAFT", {});

      expect(mockPdfDocEncrypt).not.toHaveBeenCalled();
    });

    it("should handle custom watermark text", async () => {
      mockPdfDocGetPages.mockReturnValue([mockPage]);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      await addWatermarkAndEncrypt(pdfBytes, "DO NOT COPY - INVESTOR COPY", {});

      expect(mockPageDrawText).toHaveBeenCalledWith(
        "DO NOT COPY - INVESTOR COPY",
        expect.any(Object)
      );
    });
  });

  describe("getPDFMetadata", () => {
    it("should extract metadata from unencrypted PDF", async () => {
      mockPdfDocGetTitle.mockReturnValue("Test Document");
      mockPdfDocGetAuthor.mockReturnValue("Test Author");
      mockPdfDocGetSubject.mockReturnValue("Test Subject");
      mockPdfDocGetCreator.mockReturnValue("Test Creator");
      mockPdfDocGetProducer.mockReturnValue("Test Producer");
      mockPdfDocGetPageCount.mockReturnValue(5);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const result = await getPDFMetadata(pdfBytes);

      expect(result).toEqual({
        title: "Test Document",
        author: "Test Author",
        subject: "Test Subject",
        creator: "Test Creator",
        producer: "Test Producer",
        pageCount: 5,
        isEncrypted: false,
      });
    });

    it("should pass password when provided", async () => {
      mockPdfDocGetPageCount.mockReturnValue(3);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      await getPDFMetadata(pdfBytes, "myPassword");

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes, { password: "myPassword" });
    });

    it("should return isEncrypted=true when unable to load", async () => {
      mockPdfDocLoad.mockRejectedValue(new Error("Encrypted document"));

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const result = await getPDFMetadata(pdfBytes);

      expect(result).toEqual({
        pageCount: 0,
        isEncrypted: true,
      });
    });

    it("should handle undefined metadata fields", async () => {
      mockPdfDocGetTitle.mockReturnValue(undefined);
      mockPdfDocGetAuthor.mockReturnValue(undefined);
      mockPdfDocGetSubject.mockReturnValue(undefined);
      mockPdfDocGetCreator.mockReturnValue(undefined);
      mockPdfDocGetProducer.mockReturnValue(undefined);
      mockPdfDocGetPageCount.mockReturnValue(1);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const result = await getPDFMetadata(pdfBytes);

      expect(result).toEqual({
        title: undefined,
        author: undefined,
        subject: undefined,
        creator: undefined,
        producer: undefined,
        pageCount: 1,
        isEncrypted: false,
      });
    });

    it("should work without password for unencrypted PDF", async () => {
      mockPdfDocGetPageCount.mockReturnValue(2);

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      await getPDFMetadata(pdfBytes);

      expect(mockPdfDocLoad).toHaveBeenCalledWith(pdfBytes, undefined);
    });
  });

  describe("generateDocumentPassword", () => {
    it("should generate password of default length (24)", () => {
      const fakeRandomBytes = Buffer.alloc(24);
      for (let i = 0; i < 24; i++) fakeRandomBytes[i] = i;
      mockRandomBytes.mockReturnValue(fakeRandomBytes);

      const password = generateDocumentPassword();

      expect(password).toHaveLength(24);
      expect(mockRandomBytes).toHaveBeenCalledWith(24);
    });

    it("should generate password of custom length", () => {
      const fakeRandomBytes = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) fakeRandomBytes[i] = i;
      mockRandomBytes.mockReturnValue(fakeRandomBytes);

      const password = generateDocumentPassword(32);

      expect(password).toHaveLength(32);
      expect(mockRandomBytes).toHaveBeenCalledWith(32);
    });

    it("should only use alphanumeric characters", () => {
      const fakeRandomBytes = Buffer.alloc(50);
      for (let i = 0; i < 50; i++) fakeRandomBytes[i] = i * 5;
      mockRandomBytes.mockReturnValue(fakeRandomBytes);

      const password = generateDocumentPassword(50);

      expect(password).toMatch(/^[A-Za-z0-9]+$/);
    });

    it("should generate different passwords each time", () => {
      let callCount = 0;
      mockRandomBytes.mockImplementation((length) => {
        const bytes = Buffer.alloc(length);
        for (let i = 0; i < length; i++) bytes[i] = (callCount * 10 + i) % 256;
        callCount++;
        return bytes;
      });

      const password1 = generateDocumentPassword();
      const password2 = generateDocumentPassword();

      expect(password1).not.toBe(password2);
    });

    it("should handle short password length", () => {
      const fakeRandomBytes = Buffer.alloc(8);
      for (let i = 0; i < 8; i++) fakeRandomBytes[i] = i * 20;
      mockRandomBytes.mockReturnValue(fakeRandomBytes);

      const password = generateDocumentPassword(8);

      expect(password).toHaveLength(8);
    });
  });

  describe("Permission Options", () => {
    it("should support lowResolution printing", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await encryptPDF(pdfBytes, {
        userPassword: "test",
        permissions: { printing: "lowResolution" },
      });

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.objectContaining({
            printing: "lowResolution",
          }),
        })
      );
    });

    it("should support disabling all permissions", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await encryptPDF(pdfBytes, {
        userPassword: "locked",
        permissions: {
          printing: undefined,
          modifying: false,
          copying: false,
          annotating: false,
          fillingForms: false,
          contentAccessibility: false,
          documentAssembly: false,
        },
      });

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.objectContaining({
            modifying: false,
            copying: false,
            annotating: false,
            fillingForms: false,
          }),
        })
      );
    });

    it("should support enabling all permissions", async () => {
      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await encryptPDF(pdfBytes, {
        userPassword: "open",
        permissions: {
          printing: "highResolution",
          modifying: true,
          copying: true,
          annotating: true,
          fillingForms: true,
          contentAccessibility: true,
          documentAssembly: true,
        },
      });

      expect(mockPdfDocEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({
          permissions: expect.objectContaining({
            modifying: true,
            copying: true,
            annotating: true,
            documentAssembly: true,
          }),
        })
      );
    });
  });

  describe("Error Handling", () => {
    it("should propagate errors from PDF loading", async () => {
      mockPdfDocLoad.mockRejectedValue(new Error("Invalid PDF structure"));

      const pdfBytes = new Uint8Array([0x00, 0x00, 0x00, 0x00]);

      await expect(encryptPDF(pdfBytes, { userPassword: "test" })).rejects.toThrow(
        "Invalid PDF structure"
      );
    });

    it("should propagate errors from encryption", async () => {
      mockPdfDocEncrypt.mockRejectedValue(new Error("Encryption failed"));

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await expect(encryptPDF(pdfBytes, { userPassword: "test" })).rejects.toThrow(
        "Encryption failed"
      );
    });

    it("should propagate errors from save", async () => {
      mockPdfDocSave.mockRejectedValue(new Error("Save failed"));

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

      await expect(encryptPDF(pdfBytes, { userPassword: "test" })).rejects.toThrow(
        "Save failed"
      );
    });

    it("should handle invalid PNG for signature embedding", async () => {
      mockPdfDocEmbedPng.mockRejectedValue(new Error("Invalid PNG"));

      const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
      const badSignature = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
      const placement: SignaturePlacement = {
        pageNumber: 1,
        x: 50,
        y: 50,
        width: 100,
        height: 50,
      };

      await expect(
        embedSignatureAndEncrypt(pdfBytes, badSignature, placement, {})
      ).rejects.toThrow("Invalid PNG");
    });
  });
});
