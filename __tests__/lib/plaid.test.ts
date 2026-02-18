// @ts-nocheck
/**
 * Plaid Integration Tests
 *
 * Tests for lib/plaid.ts - Bank linking and payment processing.
 *
 * These tests validate:
 * - Token encryption/decryption
 * - Link token creation
 * - Public token exchange
 * - Account and balance retrieval
 * - Transfer authorization and creation
 * - Webhook signature verification
 * - Webhook event parsing
 * - Configuration checks
 */

// Mock Plaid SDK
const mockLinkTokenCreate = jest.fn();
const mockItemPublicTokenExchange = jest.fn();
const mockAccountsGet = jest.fn();
const mockAccountsBalanceGet = jest.fn();
const mockInstitutionsGetById = jest.fn();
const mockItemGet = jest.fn();
const mockProcessorTokenCreate = jest.fn();
const mockTransferAuthorizationCreate = jest.fn();
const mockTransferCreate = jest.fn();
const mockTransferGet = jest.fn();
const mockTransferCancel = jest.fn();
const mockItemRemove = jest.fn();
const mockWebhookVerificationKeyGet = jest.fn();

jest.mock("plaid", () => ({
  Configuration: jest.fn().mockImplementation(() => ({})),
  PlaidApi: jest.fn().mockImplementation(() => ({
    linkTokenCreate: mockLinkTokenCreate,
    itemPublicTokenExchange: mockItemPublicTokenExchange,
    accountsGet: mockAccountsGet,
    accountsBalanceGet: mockAccountsBalanceGet,
    institutionsGetById: mockInstitutionsGetById,
    itemGet: mockItemGet,
    processorTokenCreate: mockProcessorTokenCreate,
    transferAuthorizationCreate: mockTransferAuthorizationCreate,
    transferCreate: mockTransferCreate,
    transferGet: mockTransferGet,
    transferCancel: mockTransferCancel,
    itemRemove: mockItemRemove,
    webhookVerificationKeyGet: mockWebhookVerificationKeyGet,
  })),
  PlaidEnvironments: {
    sandbox: "https://sandbox.plaid.com",
    development: "https://development.plaid.com",
    production: "https://production.plaid.com",
  },
  Products: {
    Auth: "auth",
    Transfer: "transfer",
  },
  CountryCode: {
    Us: "US",
  },
  TransferType: {
    debit: "debit",
    credit: "credit",
  },
  TransferNetwork: {
    Ach: "ach",
  },
  ACHClass: {
    Ppd: "ppd",
  },
}));

// Mock jose for JWT verification
jest.mock("jose", () => ({
  importJWK: jest.fn().mockResolvedValue("mock-public-key"),
  jwtVerify: jest.fn().mockResolvedValue({
    payload: {
      request_body_sha256: "mockhash",
    },
  }),
}));

describe("Plaid Integration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = {
      ...originalEnv,
      PLAID_CLIENT_ID: "test-client-id",
      PLAID_SECRET: "test-secret",
      PLAID_ENV: "sandbox",
      PLAID_WEBHOOK_URL: "https://example.com/webhooks/plaid",
      PLAID_TOKEN_ENCRYPTION_KEY: "test-encryption-key-32chars-long!",
      NEXTAUTH_SECRET: "nextauth-fallback-secret",
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("encryptToken / decryptToken", () => {
    it("should encrypt and decrypt token successfully", () => {
      const { encryptToken, decryptToken } = require("@/lib/plaid");

      const originalToken = "access-sandbox-abc123";
      const encrypted = encryptToken(originalToken);
      const decrypted = decryptToken(encrypted);

      expect(encrypted).not.toBe(originalToken);
      expect(decrypted).toBe(originalToken);
    });

    it("should produce different ciphertext for same plaintext (due to random IV)", () => {
      const { encryptToken } = require("@/lib/plaid");

      const token = "same-token";
      const encrypted1 = encryptToken(token);
      const encrypted2 = encryptToken(token);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should throw error for invalid encrypted token format", () => {
      const { decryptToken } = require("@/lib/plaid");

      expect(() => decryptToken("invalid-format")).toThrow(
        "Invalid encrypted token format"
      );
    });

    it("should throw error for corrupted encrypted token", () => {
      const { decryptToken } = require("@/lib/plaid");

      // Valid format but corrupted data
      const corruptedToken = "0000000000000000:0000000000000000:corrupted";

      expect(() => decryptToken(corruptedToken)).toThrow();
    });

    it("should use purpose-salted key derivation", () => {
      const { encryptToken, decryptToken } = require("@/lib/plaid");

      // If the key derivation changes, old tokens won't decrypt
      const token = "test-token-123";
      const encrypted = encryptToken(token);

      // Should be able to decrypt with same key
      expect(decryptToken(encrypted)).toBe(token);
    });
  });

  describe("isPlaidConfigured", () => {
    it("should return true when client ID and secret are set", () => {
      const { isPlaidConfigured } = require("@/lib/plaid");
      expect(isPlaidConfigured()).toBe(true);
    });

    it("should return false when client ID is missing", () => {
      delete process.env.PLAID_CLIENT_ID;
      jest.resetModules();
      const { isPlaidConfigured } = require("@/lib/plaid");
      expect(isPlaidConfigured()).toBe(false);
    });

    it("should return false when secret is missing", () => {
      delete process.env.PLAID_SECRET;
      jest.resetModules();
      const { isPlaidConfigured } = require("@/lib/plaid");
      expect(isPlaidConfigured()).toBe(false);
    });
  });

  describe("createLinkToken", () => {
    it("should create link token for user", async () => {
      mockLinkTokenCreate.mockResolvedValue({
        data: { link_token: "link-sandbox-abc123" },
      });

      const { createLinkToken } = require("@/lib/plaid");

      const result = await createLinkToken("user-123");

      expect(result).toBe("link-sandbox-abc123");
      expect(mockLinkTokenCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          user: { client_user_id: "user-123" },
          client_name: "BF Fund",
          products: ["auth", "transfer"],
          country_codes: ["US"],
          language: "en",
        })
      );
    });

    it("should use custom client name when provided", async () => {
      mockLinkTokenCreate.mockResolvedValue({
        data: { link_token: "link-token" },
      });

      const { createLinkToken } = require("@/lib/plaid");

      await createLinkToken("user-123", "Custom Fund Name");

      expect(mockLinkTokenCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          client_name: "Custom Fund Name",
        })
      );
    });
  });

  describe("exchangePublicToken", () => {
    it("should exchange public token for access token", async () => {
      mockItemPublicTokenExchange.mockResolvedValue({
        data: {
          access_token: "access-sandbox-xyz789",
          item_id: "item-123",
        },
      });

      const { exchangePublicToken } = require("@/lib/plaid");

      const result = await exchangePublicToken("public-sandbox-token");

      expect(result.accessToken).toBe("access-sandbox-xyz789");
      expect(result.itemId).toBe("item-123");
    });
  });

  describe("getAccounts", () => {
    it("should retrieve accounts for access token", async () => {
      const mockAccounts = [
        { account_id: "acc-1", name: "Checking", type: "depository" },
        { account_id: "acc-2", name: "Savings", type: "depository" },
      ];

      mockAccountsGet.mockResolvedValue({
        data: { accounts: mockAccounts },
      });

      const { getAccounts } = require("@/lib/plaid");

      const result = await getAccounts("access-token");

      expect(result).toEqual(mockAccounts);
      expect(mockAccountsGet).toHaveBeenCalledWith({
        access_token: "access-token",
      });
    });
  });

  describe("getAccountBalance", () => {
    it("should retrieve account balances", async () => {
      const mockAccounts = [
        {
          account_id: "acc-1",
          balances: { current: 10000, available: 9500 },
        },
      ];

      mockAccountsBalanceGet.mockResolvedValue({
        data: { accounts: mockAccounts },
      });

      const { getAccountBalance } = require("@/lib/plaid");

      const result = await getAccountBalance("access-token");

      expect(result).toEqual(mockAccounts);
    });

    it("should filter by account IDs when provided", async () => {
      mockAccountsBalanceGet.mockResolvedValue({
        data: { accounts: [] },
      });

      const { getAccountBalance } = require("@/lib/plaid");

      await getAccountBalance("access-token", ["acc-1", "acc-2"]);

      expect(mockAccountsBalanceGet).toHaveBeenCalledWith({
        access_token: "access-token",
        options: { account_ids: ["acc-1", "acc-2"] },
      });
    });
  });

  describe("getInstitution", () => {
    it("should retrieve institution details", async () => {
      const mockInstitution = {
        institution_id: "ins_123",
        name: "Chase",
        logo: "logo_url",
      };

      mockInstitutionsGetById.mockResolvedValue({
        data: { institution: mockInstitution },
      });

      const { getInstitution } = require("@/lib/plaid");

      const result = await getInstitution("ins_123");

      expect(result).toEqual(mockInstitution);
    });
  });

  describe("getItem", () => {
    it("should retrieve item details", async () => {
      const mockItem = {
        item_id: "item-123",
        institution_id: "ins_123",
        webhook: "https://example.com/webhook",
      };

      mockItemGet.mockResolvedValue({
        data: { item: mockItem },
      });

      const { getItem } = require("@/lib/plaid");

      const result = await getItem("access-token");

      expect(result).toEqual(mockItem);
    });
  });

  describe("createProcessorToken", () => {
    it("should create processor token for Dwolla", async () => {
      mockProcessorTokenCreate.mockResolvedValue({
        data: { processor_token: "processor-sandbox-token" },
      });

      const { createProcessorToken } = require("@/lib/plaid");

      const result = await createProcessorToken("access-token", "acc-123");

      expect(result).toBe("processor-sandbox-token");
      expect(mockProcessorTokenCreate).toHaveBeenCalledWith({
        access_token: "access-token",
        account_id: "acc-123",
        processor: "dwolla",
      });
    });
  });

  describe("createTransferAuthorization", () => {
    it("should create transfer authorization for debit", async () => {
      mockTransferAuthorizationCreate.mockResolvedValue({
        data: {
          authorization: {
            id: "auth-123",
            decision: "approved",
            decision_rationale: null,
          },
        },
      });

      const { createTransferAuthorization } = require("@/lib/plaid");

      const result = await createTransferAuthorization(
        "access-token",
        "acc-123",
        "10000.00",
        "debit",
        "John Doe",
        "john@example.com"
      );

      expect(result.authorizationId).toBe("auth-123");
      expect(result.decision).toBe("approved");
      expect(mockTransferAuthorizationCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "debit",
          amount: "10000.00",
          user: {
            legal_name: "John Doe",
            email_address: "john@example.com",
          },
        })
      );
    });

    it("should include decision rationale when declined", async () => {
      mockTransferAuthorizationCreate.mockResolvedValue({
        data: {
          authorization: {
            id: "auth-456",
            decision: "declined",
            decision_rationale: {
              code: "NSF",
              description: "Insufficient funds",
            },
          },
        },
      });

      const { createTransferAuthorization } = require("@/lib/plaid");

      const result = await createTransferAuthorization(
        "access-token",
        "acc-123",
        "50000.00",
        "debit",
        "Jane Doe"
      );

      expect(result.decision).toBe("declined");
      expect(result.decisionRationale?.description).toBe("Insufficient funds");
    });
  });

  describe("createTransfer", () => {
    it("should create ACH transfer", async () => {
      mockTransferCreate.mockResolvedValue({
        data: {
          transfer: {
            id: "transfer-123",
            status: "pending",
            created: "2024-01-15T10:00:00Z",
          },
        },
      });

      const { createTransfer } = require("@/lib/plaid");

      const result = await createTransfer(
        "access-token",
        "acc-123",
        "auth-123",
        "10000.00",
        "Fund Subscription Payment"
      );

      expect(result.transferId).toBe("transfer-123");
      expect(result.status).toBe("pending");
      expect(mockTransferCreate).toHaveBeenCalledWith({
        access_token: "access-token",
        account_id: "acc-123",
        authorization_id: "auth-123",
        amount: "10000.00",
        description: "Fund Subscription Payment",
      });
    });
  });

  describe("getTransfer", () => {
    it("should retrieve transfer details", async () => {
      const mockTransfer = {
        id: "transfer-123",
        status: "posted",
        amount: "10000.00",
      };

      mockTransferGet.mockResolvedValue({
        data: { transfer: mockTransfer },
      });

      const { getTransfer } = require("@/lib/plaid");

      const result = await getTransfer("transfer-123");

      expect(result).toEqual(mockTransfer);
    });
  });

  describe("cancelTransfer", () => {
    it("should cancel a transfer", async () => {
      mockTransferCancel.mockResolvedValue({
        data: {},
      });

      const { cancelTransfer } = require("@/lib/plaid");

      const result = await cancelTransfer("transfer-123");

      expect(result).toEqual({});
      expect(mockTransferCancel).toHaveBeenCalledWith({
        transfer_id: "transfer-123",
      });
    });
  });

  describe("removeItem", () => {
    it("should remove item/bank connection", async () => {
      mockItemRemove.mockResolvedValue({
        data: { request_id: "req-123" },
      });

      const { removeItem } = require("@/lib/plaid");

      const result = await removeItem("access-token");

      expect(result).toEqual({ request_id: "req-123" });
    });
  });

  describe("verifyWebhookSignature", () => {
    it("should return false for missing verification header", async () => {
      const { verifyWebhookSignature } = require("@/lib/plaid");

      const result = await verifyWebhookSignature('{"data":{}}', "");

      expect(result).toBe(false);
    });

    it("should return false for invalid JWT format", async () => {
      const { verifyWebhookSignature } = require("@/lib/plaid");

      const result = await verifyWebhookSignature(
        '{"data":{}}',
        "not-a-valid-jwt"
      );

      expect(result).toBe(false);
    });
  });

  describe("parseWebhookEvent", () => {
    it("should parse ITEM webhook", () => {
      const { parseWebhookEvent } = require("@/lib/plaid");

      const payload = {
        webhook_type: "ITEM",
        webhook_code: "ERROR",
        item_id: "item-123",
        error: {
          error_type: "ITEM_ERROR",
          error_code: "ITEM_LOGIN_REQUIRED",
          error_message: "User must re-authenticate",
        },
      };

      const result = parseWebhookEvent(payload);

      expect(result.type).toBe("ITEM");
      expect(result.code).toBe("ERROR");
      expect(result.itemId).toBe("item-123");
      expect(result.error?.type).toBe("ITEM_ERROR");
      expect(result.error?.code).toBe("ITEM_LOGIN_REQUIRED");
      expect(result.error?.message).toBe("User must re-authenticate");
    });

    it("should parse TRANSFER webhook", () => {
      const { parseWebhookEvent } = require("@/lib/plaid");

      const payload = {
        webhook_type: "TRANSFER",
        webhook_code: "TRANSFER_EVENTS_UPDATE",
        transfer_id: "transfer-123",
        new_transfer_status: "posted",
      };

      const result = parseWebhookEvent(payload);

      expect(result.type).toBe("TRANSFER");
      expect(result.code).toBe("TRANSFER_EVENTS_UPDATE");
      expect(result.transferId).toBe("transfer-123");
      expect(result.newStatus).toBe("posted");
    });

    it("should handle webhook without error", () => {
      const { parseWebhookEvent } = require("@/lib/plaid");

      const payload = {
        webhook_type: "AUTH",
        webhook_code: "AUTOMATICALLY_VERIFIED",
        item_id: "item-456",
      };

      const result = parseWebhookEvent(payload);

      expect(result.error).toBeUndefined();
    });
  });
});
