// @ts-nocheck
/**
 * Persona KYC Integration Tests
 *
 * Tests for lib/persona.ts - KYC/AML verification service.
 *
 * These tests validate:
 * - Inquiry creation with required fields
 * - Inquiry retrieval and resume
 * - Status mapping from Persona to internal statuses
 * - Webhook signature verification
 * - Webhook event parsing
 * - Configuration checks
 */

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock crypto for webhook verification
jest.mock("crypto", () => {
  const actualCrypto = jest.requireActual("crypto");
  return {
    ...actualCrypto,
    createHmac: jest.fn().mockReturnValue({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue("expectedhash123"),
    }),
    timingSafeEqual: jest.fn().mockReturnValue(true),
  };
});

describe("Persona KYC Integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockReset();
    process.env = {
      ...originalEnv,
      PERSONA_API_KEY: "test-api-key",
      PERSONA_TEMPLATE_ID: "tmpl_test123",
      PERSONA_ENVIRONMENT: "sandbox",
      PERSONA_ENVIRONMENT_ID: "env_test456",
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("createInquiry", () => {
    it("should create inquiry with required fields", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            id: "inq_123",
            type: "inquiry",
            attributes: {
              status: "created",
              "reference-id": "ref-123",
              "created-at": "2024-01-15T10:00:00Z",
            },
          },
        }),
      });

      const { createInquiry } = require("@/lib/persona");

      const result = await createInquiry({
        referenceId: "investor-123",
        email: "investor@example.com",
      });

      expect(result.id).toBe("inq_123");
      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.withpersona.com/api/v1/inquiries",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            Authorization: "Bearer test-api-key",
            "Content-Type": "application/json",
            "Persona-Version": "2023-01-05",
          }),
        })
      );
    });

    it("should include optional name fields when provided", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            id: "inq_456",
            type: "inquiry",
            attributes: { status: "created", "reference-id": "ref-456" },
          },
        }),
      });

      const { createInquiry } = require("@/lib/persona");

      await createInquiry({
        referenceId: "investor-456",
        email: "john@example.com",
        firstName: "John",
        lastName: "Doe",
      });

      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.data.attributes.fields["name-first"]).toBe("John");
      expect(callBody.data.attributes.fields["name-last"]).toBe("Doe");
    });

    it("should use custom templateId when provided", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            id: "inq_789",
            type: "inquiry",
            attributes: { status: "created" },
          },
        }),
      });

      const { createInquiry } = require("@/lib/persona");

      await createInquiry({
        referenceId: "investor-789",
        email: "test@example.com",
        templateId: "custom_template_id",
      });

      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.data.attributes["inquiry-template-id"]).toBe("custom_template_id");
    });

    it("should throw error when API returns error response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ errors: [{ detail: "Invalid request" }] }),
      });

      const { createInquiry } = require("@/lib/persona");

      await expect(
        createInquiry({
          referenceId: "bad-ref",
          email: "test@example.com",
        })
      ).rejects.toThrow("Failed to create Persona inquiry: 400");
    });

    it("should throw error when template ID is missing", async () => {
      process.env.PERSONA_TEMPLATE_ID = "";

      // Need to re-import to pick up env change
      jest.resetModules();
      const { createInquiry } = require("@/lib/persona");

      await expect(
        createInquiry({
          referenceId: "ref-123",
          email: "test@example.com",
        })
      ).rejects.toThrow("Persona template ID is required");
    });

    it("should throw error when API key is missing", async () => {
      delete process.env.PERSONA_API_KEY;

      jest.resetModules();
      const { createInquiry } = require("@/lib/persona");

      await expect(
        createInquiry({
          referenceId: "ref-123",
          email: "test@example.com",
        })
      ).rejects.toThrow("PERSONA_API_KEY environment variable is not set");
    });
  });

  describe("getInquiry", () => {
    it("should retrieve inquiry by ID", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            id: "inq_existing",
            type: "inquiry",
            attributes: {
              status: "completed",
              "reference-id": "ref-existing",
              "completed-at": "2024-01-15T12:00:00Z",
            },
          },
        }),
      });

      const { getInquiry } = require("@/lib/persona");

      const result = await getInquiry("inq_existing");

      expect(result.id).toBe("inq_existing");
      expect(result.attributes.status).toBe("completed");
      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.withpersona.com/api/v1/inquiries/inq_existing",
        expect.objectContaining({ method: "GET" })
      );
    });

    it("should throw error when inquiry not found", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const { getInquiry } = require("@/lib/persona");

      await expect(getInquiry("nonexistent")).rejects.toThrow(
        "Failed to get Persona inquiry: 404"
      );
    });
  });

  describe("resumeInquiry", () => {
    it("should return session token for resuming", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          meta: {
            "session-token": "session_token_abc123",
          },
        }),
      });

      const { resumeInquiry } = require("@/lib/persona");

      const result = await resumeInquiry("inq_resume");

      expect(result.sessionToken).toBe("session_token_abc123");
      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.withpersona.com/api/v1/inquiries/inq_resume/resume",
        expect.objectContaining({ method: "POST" })
      );
    });

    it("should return empty string when session token missing", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ meta: {} }),
      });

      const { resumeInquiry } = require("@/lib/persona");

      const result = await resumeInquiry("inq_no_token");

      expect(result.sessionToken).toBe("");
    });

    it("should throw error on API failure", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const { resumeInquiry } = require("@/lib/persona");

      await expect(resumeInquiry("inq_error")).rejects.toThrow(
        "Failed to resume Persona inquiry: 500"
      );
    });
  });

  describe("mapPersonaStatus", () => {
    it("should map created to PENDING", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("created")).toBe("PENDING");
    });

    it("should map pending to PENDING", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("pending")).toBe("PENDING");
    });

    it("should map completed to APPROVED", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("completed")).toBe("APPROVED");
    });

    it("should map approved to APPROVED", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("approved")).toBe("APPROVED");
    });

    it("should map declined to DECLINED", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("declined")).toBe("DECLINED");
    });

    it("should map failed to DECLINED", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("failed")).toBe("DECLINED");
    });

    it("should map expired to EXPIRED", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("expired")).toBe("EXPIRED");
    });

    it("should map needs_review to NEEDS_REVIEW", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("needs_review")).toBe("NEEDS_REVIEW");
    });

    it("should handle case-insensitive status", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("COMPLETED")).toBe("APPROVED");
      expect(mapPersonaStatus("Pending")).toBe("PENDING");
    });

    it("should return PENDING for unknown status", () => {
      const { mapPersonaStatus } = require("@/lib/persona");
      expect(mapPersonaStatus("unknown_status")).toBe("PENDING");
    });
  });

  describe("verifyWebhookSignature", () => {
    it("should return true for valid signature", () => {
      const crypto = require("crypto");
      crypto.timingSafeEqual.mockReturnValue(true);

      const { verifyWebhookSignature } = require("@/lib/persona");

      const result = verifyWebhookSignature(
        '{"data":{}}',
        "expectedhash123",
        "webhook_secret"
      );

      expect(result).toBe(true);
    });

    it("should return false for invalid signature", () => {
      const crypto = require("crypto");
      crypto.timingSafeEqual.mockReturnValue(false);

      const { verifyWebhookSignature } = require("@/lib/persona");

      const result = verifyWebhookSignature(
        '{"data":{}}',
        "wronghash",
        "webhook_secret"
      );

      expect(result).toBe(false);
    });

    it("should return false for signature length mismatch", () => {
      const crypto = require("crypto");
      crypto.createHmac.mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue("expectedhash123456789"), // Different length
      });

      const { verifyWebhookSignature } = require("@/lib/persona");

      const result = verifyWebhookSignature(
        '{"data":{}}',
        "short",
        "webhook_secret"
      );

      expect(result).toBe(false);
    });

    it("should return false for malformed signature", () => {
      const crypto = require("crypto");
      crypto.timingSafeEqual.mockImplementation(() => {
        throw new Error("Invalid buffer");
      });

      const { verifyWebhookSignature } = require("@/lib/persona");

      const result = verifyWebhookSignature(
        '{"data":{}}',
        "not_hex_at_all!!!",
        "webhook_secret"
      );

      expect(result).toBe(false);
    });
  });

  describe("parseWebhookEvent", () => {
    it("should parse webhook event correctly", () => {
      const { parseWebhookEvent } = require("@/lib/persona");

      const payload = {
        data: {
          type: "event",
          id: "evt_123",
          attributes: {
            name: "inquiry.completed",
            payload: {
              data: {
                type: "inquiry",
                id: "inq_456",
                attributes: {
                  status: "completed",
                  "reference-id": "investor-789",
                  "completed-at": "2024-01-15T12:00:00Z",
                },
              },
            },
          },
        },
      };

      const result = parseWebhookEvent(payload);

      expect(result.eventName).toBe("inquiry.completed");
      expect(result.inquiryId).toBe("inq_456");
      expect(result.status).toBe("completed");
      expect(result.referenceId).toBe("investor-789");
    });

    it("should handle missing optional fields", () => {
      const { parseWebhookEvent } = require("@/lib/persona");

      const payload = {
        data: {
          type: "event",
          id: "evt_789",
          attributes: {
            name: "inquiry.created",
            payload: {
              data: {
                type: "inquiry",
                id: "inq_new",
                attributes: {},
              },
            },
          },
        },
      };

      const result = parseWebhookEvent(payload);

      expect(result.eventName).toBe("inquiry.created");
      expect(result.inquiryId).toBe("inq_new");
      expect(result.status).toBe("");
      expect(result.referenceId).toBe("");
    });
  });

  describe("isPersonaConfigured", () => {
    it("should return true when both API key and template ID are set", () => {
      const { isPersonaConfigured } = require("@/lib/persona");
      expect(isPersonaConfigured()).toBe(true);
    });

    it("should return false when API key is missing", () => {
      delete process.env.PERSONA_API_KEY;
      jest.resetModules();
      const { isPersonaConfigured } = require("@/lib/persona");
      expect(isPersonaConfigured()).toBe(false);
    });

    it("should return false when template ID is missing", () => {
      delete process.env.PERSONA_TEMPLATE_ID;
      jest.resetModules();
      const { isPersonaConfigured } = require("@/lib/persona");
      expect(isPersonaConfigured()).toBe(false);
    });
  });

  describe("getPersonaEnvironmentId", () => {
    it("should return environment ID from env", () => {
      const { getPersonaEnvironmentId } = require("@/lib/persona");
      expect(getPersonaEnvironmentId()).toBe("env_test456");
    });

    it("should return empty string when not set", () => {
      delete process.env.PERSONA_ENVIRONMENT_ID;
      jest.resetModules();
      const { getPersonaEnvironmentId } = require("@/lib/persona");
      expect(getPersonaEnvironmentId()).toBe("");
    });
  });

  describe("getPersonaTemplateId", () => {
    it("should return template ID from env", () => {
      const { getPersonaTemplateId } = require("@/lib/persona");
      expect(getPersonaTemplateId()).toBe("tmpl_test123");
    });

    it("should return empty string when not set", () => {
      delete process.env.PERSONA_TEMPLATE_ID;
      jest.resetModules();
      const { getPersonaTemplateId } = require("@/lib/persona");
      expect(getPersonaTemplateId()).toBe("");
    });
  });
});
