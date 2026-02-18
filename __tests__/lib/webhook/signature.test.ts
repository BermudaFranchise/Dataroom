// @ts-nocheck
/**
 * Tests for lib/webhook/signature.ts and lib/webhook/send-webhooks.ts
 * Covers: HMAC-SHA256 signing, JSON determinism, QStash integration
 */

// Test the signature module directly (it uses Web Crypto API)
import { createWebhookSignature } from "@/lib/webhook/signature";

describe("createWebhookSignature", () => {
  it("generates a hex string signature", async () => {
    const sig = await createWebhookSignature("my-secret", { event: "test" });

    expect(typeof sig).toBe("string");
    expect(sig).toMatch(/^[0-9a-f]+$/);
    expect(sig.length).toBe(64); // SHA-256 = 32 bytes = 64 hex chars
  });

  it("produces consistent signatures for same input", async () => {
    const body = { event: "document.completed", data: { id: "doc-1" } };

    const sig1 = await createWebhookSignature("secret-123", body);
    const sig2 = await createWebhookSignature("secret-123", body);

    expect(sig1).toBe(sig2);
  });

  it("produces different signatures for different secrets", async () => {
    const body = { event: "test" };

    const sig1 = await createWebhookSignature("secret-A", body);
    const sig2 = await createWebhookSignature("secret-B", body);

    expect(sig1).not.toBe(sig2);
  });

  it("produces different signatures for different bodies", async () => {
    const secret = "shared-secret";

    const sig1 = await createWebhookSignature(secret, { event: "a" });
    const sig2 = await createWebhookSignature(secret, { event: "b" });

    expect(sig1).not.toBe(sig2);
  });

  it("throws when secret is empty", async () => {
    await expect(
      createWebhookSignature("", { event: "test" })
    ).rejects.toThrow("A secret must be provided");
  });

  it("handles complex nested body objects", async () => {
    const complexBody = {
      event: "investor.committed",
      data: {
        investor: { id: "inv-1", name: "John" },
        amount: 500000,
        metadata: { tags: ["vip", "accredited"] },
      },
      timestamp: "2024-01-01T00:00:00Z",
    };

    const sig = await createWebhookSignature("secret", complexBody);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("handles array body", async () => {
    const sig = await createWebhookSignature("secret", [1, 2, 3]);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("handles string body", async () => {
    const sig = await createWebhookSignature("secret", "plain string");
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("handles null body", async () => {
    const sig = await createWebhookSignature("secret", null);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("JSON serialization order affects signature (known behavior)", async () => {
    // This test documents that JSON key order matters for signature verification
    // Both JSON.stringify outputs are deterministic per-call but order depends on construction
    const body1 = { a: 1, b: 2 };
    const body2 = { b: 2, a: 1 };

    // In V8, objects maintain insertion order, so these WILL produce different JSON
    const json1 = JSON.stringify(body1);
    const json2 = JSON.stringify(body2);

    if (json1 === json2) {
      // If engine happens to normalize, signatures match
      const sig1 = await createWebhookSignature("secret", body1);
      const sig2 = await createWebhookSignature("secret", body2);
      expect(sig1).toBe(sig2);
    } else {
      // Different JSON → different signatures (this is the expected V8 behavior)
      const sig1 = await createWebhookSignature("secret", body1);
      const sig2 = await createWebhookSignature("secret", body2);
      expect(sig1).not.toBe(sig2);
    }
  });
});

describe("sendWebhooks", () => {
  // Mock QStash
  const mockPublishJSON = jest.fn().mockResolvedValue({ messageId: "msg-123" });

  jest.mock("@/lib/cron", () => ({
    qstash: {
      publishJSON: mockPublishJSON,
    },
  }));

  jest.mock("@/lib/webhook/transform", () => ({
    prepareWebhookPayload: jest.fn((trigger, data) => ({
      id: "evt-123",
      event: trigger,
      data,
      timestamp: "2024-01-01T00:00:00Z",
    })),
  }));

  // Need to import after mocks
  let sendWebhooks: any;

  beforeAll(async () => {
    const mod = await import("@/lib/webhook/send-webhooks");
    sendWebhooks = mod.sendWebhooks;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.NEXT_PUBLIC_BASE_URL = "https://app.fundroom.ai";
  });

  it("returns early for empty webhooks array", async () => {
    const result = await sendWebhooks({
      webhooks: [],
      trigger: "document.completed",
      data: { documentId: "doc-1" },
    });

    expect(result).toBeUndefined();
    expect(mockPublishJSON).not.toHaveBeenCalled();
  });

  it("publishes to QStash for each webhook", async () => {
    await sendWebhooks({
      webhooks: [
        { pId: "wh-1", url: "https://example.com/hook1", secret: "sec1" },
        { pId: "wh-2", url: "https://example.com/hook2", secret: "sec2" },
      ],
      trigger: "investor.committed",
      data: { investorId: "inv-1" },
    });

    expect(mockPublishJSON).toHaveBeenCalledTimes(2);
  });

  it("includes X-BFFund-Signature header", async () => {
    await sendWebhooks({
      webhooks: [{ pId: "wh-1", url: "https://example.com/hook", secret: "my-secret" }],
      trigger: "document.viewed",
      data: {},
    });

    const call = mockPublishJSON.mock.calls[0][0];
    expect(call.headers["X-BFFund-Signature"]).toBeDefined();
    expect(call.headers["X-BFFund-Signature"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sets callback URL with webhook ID and event info", async () => {
    await sendWebhooks({
      webhooks: [{ pId: "wh-1", url: "https://example.com/hook", secret: "sec" }],
      trigger: "document.completed",
      data: {},
    });

    const call = mockPublishJSON.mock.calls[0][0];
    expect(call.callback).toContain("/api/webhooks/callback");
    expect(call.callback).toContain("webhookId=wh-1");
    expect(call.callback).toContain("eventId=evt-123");
  });

  it("sets failure callback to same URL", async () => {
    await sendWebhooks({
      webhooks: [{ pId: "wh-1", url: "https://example.com/hook", secret: "sec" }],
      trigger: "test",
      data: {},
    });

    const call = mockPublishJSON.mock.calls[0][0];
    expect(call.failureCallback).toBe(call.callback);
  });
});
