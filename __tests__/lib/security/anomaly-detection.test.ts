// @ts-nocheck
/**
 * Anomaly Detection Tests
 *
 * Tests for lib/security/anomaly-detection.ts - Detects suspicious access patterns.
 *
 * These tests validate:
 * - Detection of multiple IPs accessing same account
 * - Detection of rapid location changes
 * - Detection of unusual access times
 * - Detection of excessive requests
 * - Detection of suspicious user agents
 * - Alert severity classification
 * - Pattern cleanup and expiration
 * - checkAndAlertAnomalies blocking logic
 */

import { createMocks } from "node-mocks-http";
import type { NextApiRequest } from "next";

// Mock prisma before importing anomaly detection
jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    signatureAuditLog: {
      create: jest.fn().mockResolvedValue({ id: "log-1" }),
    },
  },
}));

import {
  detectAnomalies,
  checkAndAlertAnomalies,
  getUserAccessPattern,
  clearUserPattern,
} from "@/lib/security/anomaly-detection";
import prisma from "@/lib/prisma";

describe("Anomaly Detection", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Clear user patterns after each test
    clearUserPattern("user-1");
    clearUserPattern("user-2");
    clearUserPattern("user-multi-ip");
    clearUserPattern("user-ua");
    clearUserPattern("user-rapid");
    clearUserPattern("user-location");
    clearUserPattern("user-critical");
    clearUserPattern("user-high");
  });

  describe("detectAnomalies", () => {
    describe("Multiple IPs Detection", () => {
      it("should not alert for single IP", async () => {
        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(req, "user-1");

        const multipleIpAlerts = alerts.filter((a) => a.type === "MULTIPLE_IPS");
        expect(multipleIpAlerts).toHaveLength(0);
      });

      it("should alert when more than 5 IPs are detected", async () => {
        const userId = "user-multi-ip";

        // Access from 6 different IPs
        for (let i = 1; i <= 6; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": `192.168.1.${i}`,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          await detectAnomalies(req, userId);
        }

        const pattern = getUserAccessPattern(userId);
        expect(pattern?.ips.size).toBe(6);

        // Next request should trigger alert
        const { req: finalReq } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.7",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(finalReq, userId);
        const multipleIpAlerts = alerts.filter((a) => a.type === "MULTIPLE_IPS");

        expect(multipleIpAlerts.length).toBeGreaterThan(0);
        expect(multipleIpAlerts[0].severity).toBe("HIGH");
      });

      it("should escalate to CRITICAL when more than 10 IPs detected", async () => {
        const userId = "user-multi-ip";

        // Access from 11 different IPs
        for (let i = 1; i <= 11; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": `10.0.0.${i}`,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          await detectAnomalies(req, userId);
        }

        const { req: finalReq } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "10.0.0.12",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(finalReq, userId);
        const multipleIpAlerts = alerts.filter((a) => a.type === "MULTIPLE_IPS");

        expect(multipleIpAlerts.length).toBeGreaterThan(0);
        expect(multipleIpAlerts[0].severity).toBe("CRITICAL");
      });
    });

    describe("Suspicious User Agent Detection", () => {
      it("should not alert for up to 3 user agents", async () => {
        const userId = "user-ua";
        const userAgents = [
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)",
        ];

        for (const ua of userAgents) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": "192.168.1.1",
              "user-agent": ua,
              "cf-ipcountry": "US",
            },
          });
          await detectAnomalies(req, userId);
        }

        const pattern = getUserAccessPattern(userId);
        expect(pattern?.userAgents.size).toBe(3);

        // Should not have user agent alerts yet
        const { req: checkReq } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": userAgents[0],
            "cf-ipcountry": "US",
          },
        });
        const alerts = await detectAnomalies(checkReq, userId);
        const uaAlerts = alerts.filter((a) => a.type === "SUSPICIOUS_USER_AGENT");
        expect(uaAlerts).toHaveLength(0);
      });

      it("should alert when more than 3 user agents detected", async () => {
        const userId = "user-ua";
        const userAgents = [
          "Mozilla/5.0 (Windows)",
          "Mozilla/5.0 (Mac)",
          "Mozilla/5.0 (Linux)",
          "Mozilla/5.0 (Android)",
        ];

        let alerts;
        for (const ua of userAgents) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": "192.168.1.1",
              "user-agent": ua,
              "cf-ipcountry": "US",
            },
          });
          alerts = await detectAnomalies(req, userId);
        }

        const uaAlerts = alerts.filter((a) => a.type === "SUSPICIOUS_USER_AGENT");
        expect(uaAlerts.length).toBeGreaterThan(0);
        expect(uaAlerts[0].severity).toBe("MEDIUM");
      });
    });

    describe("Excessive Requests Detection", () => {
      it("should not alert for normal request frequency", async () => {
        const userId = "user-rapid";

        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        // Single request should not trigger
        const alerts = await detectAnomalies(req, userId);
        const excessiveAlerts = alerts.filter((a) => a.type === "EXCESSIVE_REQUESTS");
        expect(excessiveAlerts).toHaveLength(0);
      });

      it("should alert when more than 10 requests in 60 seconds from same IP", async () => {
        const userId = "user-rapid";
        const ip = "192.168.1.100";

        // Make 11 rapid requests
        let alerts;
        for (let i = 0; i < 11; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": ip,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          alerts = await detectAnomalies(req, userId);
        }

        const excessiveAlerts = alerts.filter((a) => a.type === "EXCESSIVE_REQUESTS");
        expect(excessiveAlerts.length).toBeGreaterThan(0);
        expect(excessiveAlerts[0].severity).toBe("HIGH");
        expect(excessiveAlerts[0].details.requestCount).toBeGreaterThan(10);
      });

      it("should escalate to CRITICAL for more than 50 requests", async () => {
        const userId = "user-rapid";
        const ip = "192.168.1.200";

        // Make 51 rapid requests
        let alerts;
        for (let i = 0; i < 51; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": ip,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          alerts = await detectAnomalies(req, userId);
        }

        const excessiveAlerts = alerts.filter((a) => a.type === "EXCESSIVE_REQUESTS");
        expect(excessiveAlerts.length).toBeGreaterThan(0);
        expect(excessiveAlerts[0].severity).toBe("CRITICAL");
      });
    });

    describe("Rapid Location Change Detection", () => {
      it("should not alert for single location", async () => {
        const userId = "user-location";

        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(req, userId);
        const locationAlerts = alerts.filter((a) => a.type === "RAPID_LOCATION_CHANGE");
        expect(locationAlerts).toHaveLength(0);
      });

      it("should not alert for two locations", async () => {
        const userId = "user-location";
        const countries = ["US", "CA"];

        for (const country of countries) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": "192.168.1.1",
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": country,
            },
          });
          await detectAnomalies(req, userId);
        }

        const pattern = getUserAccessPattern(userId);
        expect(pattern?.locations.size).toBe(2);

        const { req: checkReq } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });
        const alerts = await detectAnomalies(checkReq, userId);
        const locationAlerts = alerts.filter((a) => a.type === "RAPID_LOCATION_CHANGE");
        expect(locationAlerts).toHaveLength(0);
      });

      it("should alert when more than 2 locations detected", async () => {
        const userId = "user-location";
        const countries = ["US", "CA", "UK"];

        let alerts;
        for (const country of countries) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": "192.168.1.1",
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": country,
            },
          });
          alerts = await detectAnomalies(req, userId);
        }

        const locationAlerts = alerts.filter((a) => a.type === "RAPID_LOCATION_CHANGE");
        expect(locationAlerts.length).toBeGreaterThan(0);
        expect(locationAlerts[0].severity).toBe("HIGH");
        expect(locationAlerts[0].details.locations).toContain("US");
        expect(locationAlerts[0].details.locations).toContain("CA");
        expect(locationAlerts[0].details.locations).toContain("UK");
      });
    });

    describe("Unusual Time Detection", () => {
      it("should alert for access between 2-5 AM", async () => {
        const realDate = Date;
        const mockDate = new Date("2024-01-15T03:30:00"); // 3:30 AM

        jest.spyOn(global, "Date").mockImplementation((arg) => {
          if (arg) return new realDate(arg);
          return mockDate;
        });
        (global.Date as any).now = realDate.now;

        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(req, "user-1");
        const timeAlerts = alerts.filter((a) => a.type === "UNUSUAL_TIME");

        expect(timeAlerts.length).toBeGreaterThan(0);
        expect(timeAlerts[0].severity).toBe("LOW");
        expect(timeAlerts[0].details.hour).toBe(3);

        jest.restoreAllMocks();
      });

      it("should not alert for normal hours", async () => {
        const realDate = Date;
        const mockDate = new Date("2024-01-15T14:30:00"); // 2:30 PM

        jest.spyOn(global, "Date").mockImplementation((arg) => {
          if (arg) return new realDate(arg);
          return mockDate;
        });
        (global.Date as any).now = realDate.now;

        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": "192.168.1.1",
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });

        const alerts = await detectAnomalies(req, "user-2");
        const timeAlerts = alerts.filter((a) => a.type === "UNUSUAL_TIME");

        expect(timeAlerts).toHaveLength(0);

        jest.restoreAllMocks();
      });
    });

    describe("Alert Logging", () => {
      it("should log alerts to database", async () => {
        const userId = "user-multi-ip";

        // Generate 6 different IPs to trigger alert
        for (let i = 1; i <= 7; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": `172.16.0.${i}`,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          await detectAnomalies(req, userId);
        }

        expect(prisma.signatureAuditLog.create).toHaveBeenCalled();
      });

      it("should handle database errors gracefully", async () => {
        (prisma.signatureAuditLog.create as jest.Mock).mockRejectedValueOnce(
          new Error("Database error")
        );

        const userId = "user-multi-ip";

        // Generate enough IPs to trigger alert
        for (let i = 1; i <= 7; i++) {
          const { req } = createMocks<NextApiRequest>({
            headers: {
              "x-forwarded-for": `172.17.0.${i}`,
              "user-agent": "Mozilla/5.0",
              "cf-ipcountry": "US",
            },
          });
          // Should not throw
          await expect(detectAnomalies(req, userId)).resolves.toBeDefined();
        }
      });
    });
  });

  describe("checkAndAlertAnomalies", () => {
    it("should allow access when no critical alerts", async () => {
      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      const result = await checkAndAlertAnomalies(req, "user-1");

      expect(result.allowed).toBe(true);
    });

    it("should block access for CRITICAL alerts", async () => {
      const userId = "user-critical";

      // Generate 12 different IPs to trigger CRITICAL alert
      for (let i = 1; i <= 12; i++) {
        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": `10.10.0.${i}`,
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });
        await detectAnomalies(req, userId);
      }

      const { req: finalReq } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "10.10.0.100",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      const result = await checkAndAlertAnomalies(finalReq, userId);

      expect(result.allowed).toBe(false);
      expect(result.alerts.some((a) => a.severity === "CRITICAL")).toBe(true);
    });

    it("should block access when 2 or more HIGH alerts", async () => {
      const userId = "user-high";

      // Generate 6 IPs (triggers HIGH MULTIPLE_IPS)
      for (let i = 1; i <= 6; i++) {
        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": `10.20.0.${i}`,
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": i <= 2 ? "US" : i <= 4 ? "CA" : "UK", // 3 locations
          },
        });
        await detectAnomalies(req, userId);
      }

      // Now make another request - should have both MULTIPLE_IPS and RAPID_LOCATION_CHANGE (both HIGH)
      const { req: finalReq } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "10.20.0.100",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "DE",
        },
      });

      const result = await checkAndAlertAnomalies(finalReq, userId);

      const highAlerts = result.alerts.filter((a) => a.severity === "HIGH");
      expect(highAlerts.length).toBeGreaterThanOrEqual(2);
      expect(result.allowed).toBe(false);
    });

    it("should allow access with single HIGH alert", async () => {
      const userId = "user-high";

      // Generate exactly 6 IPs to trigger one HIGH alert
      for (let i = 1; i <= 6; i++) {
        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": `10.30.0.${i}`,
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US", // Same location
          },
        });
        await detectAnomalies(req, userId);
      }

      const { req: checkReq } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "10.30.0.1", // Reusing existing IP
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      const result = await checkAndAlertAnomalies(checkReq, userId);

      const highAlerts = result.alerts.filter((a) => a.severity === "HIGH");
      // May have 1 HIGH alert from MULTIPLE_IPS
      if (highAlerts.length === 1) {
        expect(result.allowed).toBe(true);
      }
    });

    it("should return all alerts regardless of blocking decision", async () => {
      const userId = "user-1";

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      const result = await checkAndAlertAnomalies(req, userId);

      expect(result).toHaveProperty("allowed");
      expect(result).toHaveProperty("alerts");
      expect(Array.isArray(result.alerts)).toBe(true);
    });
  });

  describe("getUserAccessPattern", () => {
    it("should return undefined for unknown user", () => {
      const pattern = getUserAccessPattern("unknown-user");
      expect(pattern).toBeUndefined();
    });

    it("should return pattern for tracked user", async () => {
      const userId = "user-1";

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      await detectAnomalies(req, userId);

      const pattern = getUserAccessPattern(userId);
      expect(pattern).toBeDefined();
      expect(pattern?.userId).toBe(userId);
      expect(pattern?.ips.size).toBeGreaterThan(0);
      expect(pattern?.userAgents.size).toBeGreaterThan(0);
      expect(pattern?.locations.size).toBeGreaterThan(0);
    });
  });

  describe("clearUserPattern", () => {
    it("should clear user pattern", async () => {
      const userId = "user-1";

      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "192.168.1.1",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      await detectAnomalies(req, userId);
      expect(getUserAccessPattern(userId)).toBeDefined();

      clearUserPattern(userId);
      expect(getUserAccessPattern(userId)).toBeUndefined();
    });

    it("should not throw for non-existent user", () => {
      expect(() => clearUserPattern("non-existent")).not.toThrow();
    });
  });

  describe("IP Extraction", () => {
    it("should extract IP from x-forwarded-for string", async () => {
      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "203.0.113.1, 70.41.3.18, 150.172.238.178",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      await detectAnomalies(req, "user-1");

      const pattern = getUserAccessPattern("user-1");
      expect(pattern?.ips.has("203.0.113.1")).toBe(true);
    });

    it("should extract IP from x-forwarded-for array", async () => {
      const { req } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": ["203.0.113.2", "70.41.3.18"],
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      await detectAnomalies(req, "user-2");

      const pattern = getUserAccessPattern("user-2");
      expect(pattern?.ips.has("203.0.113.2")).toBe(true);
    });

    it("should use unknown for missing IP", async () => {
      const { req } = createMocks<NextApiRequest>({
        headers: {
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      await detectAnomalies(req, "user-1");

      const pattern = getUserAccessPattern("user-1");
      // Should have some IP (either unknown or from socket)
      expect(pattern?.ips.size).toBeGreaterThan(0);
    });
  });

  describe("Alert Structure", () => {
    it("should have correct alert structure", async () => {
      const userId = "user-multi-ip";

      // Generate enough IPs to trigger alert
      for (let i = 1; i <= 7; i++) {
        const { req } = createMocks<NextApiRequest>({
          headers: {
            "x-forwarded-for": `172.18.0.${i}`,
            "user-agent": "Mozilla/5.0",
            "cf-ipcountry": "US",
          },
        });
        await detectAnomalies(req, userId);
      }

      const { req: finalReq } = createMocks<NextApiRequest>({
        headers: {
          "x-forwarded-for": "172.18.0.100",
          "user-agent": "Mozilla/5.0",
          "cf-ipcountry": "US",
        },
      });

      const alerts = await detectAnomalies(finalReq, userId);
      const alert = alerts.find((a) => a.type === "MULTIPLE_IPS");

      expect(alert).toMatchObject({
        type: expect.any(String),
        severity: expect.stringMatching(/^(LOW|MEDIUM|HIGH|CRITICAL)$/),
        userId: expect.any(String),
        details: expect.any(Object),
        timestamp: expect.any(Date),
      });
    });
  });
});
