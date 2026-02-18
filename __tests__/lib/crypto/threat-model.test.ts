/**
 * Threat Model Tests
 *
 * Tests for lib/crypto/threat-model.ts - Security threat model definitions,
 * threat categorization, and security control documentation.
 *
 * These tests verify the threat model structure and helper functions.
 */

import {
  THREAT_MODEL,
  getThreatsByCategory,
  getHighImpactThreats,
  getSecurityControlSummary,
  ThreatCategory,
  Sensitivity,
} from "@/lib/crypto/threat-model";

describe("Threat Model", () => {
  describe("THREAT_MODEL Structure", () => {
    it("should have required top-level properties", () => {
      expect(THREAT_MODEL).toHaveProperty("name");
      expect(THREAT_MODEL).toHaveProperty("version");
      expect(THREAT_MODEL).toHaveProperty("lastUpdated");
      expect(THREAT_MODEL).toHaveProperty("assets");
      expect(THREAT_MODEL).toHaveProperty("threats");
      expect(THREAT_MODEL).toHaveProperty("securityControls");
      expect(THREAT_MODEL).toHaveProperty("complianceRequirements");
      expect(THREAT_MODEL).toHaveProperty("futureEnhancements");
    });

    it("should have correct name for document vault", () => {
      expect(THREAT_MODEL.name).toContain("Investor Dataroom");
      expect(THREAT_MODEL.name).toContain("Security");
    });

    it("should have valid version format", () => {
      expect(THREAT_MODEL.version).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it("should have valid date format", () => {
      expect(THREAT_MODEL.lastUpdated).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
  });

  describe("Assets", () => {
    it("should define investor PII asset", () => {
      const piiAsset = THREAT_MODEL.assets.find((a) => a.id === "A1");

      expect(piiAsset).toBeTruthy();
      expect(piiAsset?.name).toContain("PII");
      expect(piiAsset?.sensitivity).toBe("HIGH");
    });

    it("should define signature data asset", () => {
      const signatureAsset = THREAT_MODEL.assets.find((a) => a.id === "A2");

      expect(signatureAsset).toBeTruthy();
      expect(signatureAsset?.name).toContain("Signature");
      expect(signatureAsset?.sensitivity).toBe("HIGH");
    });

    it("should define fund documents asset as critical", () => {
      const docAsset = THREAT_MODEL.assets.find((a) => a.id === "A3");

      expect(docAsset).toBeTruthy();
      expect(docAsset?.name).toContain("Documents");
      expect(docAsset?.sensitivity).toBe("CRITICAL");
    });

    it("should define authentication credentials as critical", () => {
      const authAsset = THREAT_MODEL.assets.find((a) => a.id === "A4");

      expect(authAsset).toBeTruthy();
      expect(authAsset?.sensitivity).toBe("CRITICAL");
    });

    it("should define financial data as critical", () => {
      const finAsset = THREAT_MODEL.assets.find((a) => a.id === "A5");

      expect(finAsset).toBeTruthy();
      expect(finAsset?.sensitivity).toBe("CRITICAL");
    });

    it("should have protections defined for each asset", () => {
      for (const asset of THREAT_MODEL.assets) {
        expect(asset.protections).toBeDefined();
        expect(asset.protections.length).toBeGreaterThan(0);
      }
    });
  });

  describe("Threats", () => {
    it("should cover all STRIDE categories", () => {
      const categories = THREAT_MODEL.threats.map((t) => t.category);
      const strideCategories: ThreatCategory[] = [
        "SPOOFING",
        "TAMPERING",
        "REPUDIATION",
        "INFORMATION_DISCLOSURE",
        "DENIAL_OF_SERVICE",
        "ELEVATION_OF_PRIVILEGE",
      ];

      for (const category of strideCategories) {
        expect(categories).toContain(category);
      }
    });

    it("should have identity spoofing threat", () => {
      const spoofingThreat = THREAT_MODEL.threats.find(
        (t) => t.category === "SPOOFING"
      );

      expect(spoofingThreat).toBeTruthy();
      expect(spoofingThreat?.mitigations.length).toBeGreaterThan(0);
    });

    it("should have document tampering threat", () => {
      const tamperingThreat = THREAT_MODEL.threats.find(
        (t) => t.category === "TAMPERING"
      );

      expect(tamperingThreat).toBeTruthy();
      expect(tamperingThreat?.impact).toBe("CRITICAL");
    });

    it("should have signature repudiation threat", () => {
      const repudiationThreat = THREAT_MODEL.threats.find(
        (t) => t.category === "REPUDIATION"
      );

      expect(repudiationThreat).toBeTruthy();
      expect(
        repudiationThreat?.mitigations.some((m) => m.includes("ESIGN"))
      ).toBe(true);
    });

    it("should have data breach threat", () => {
      const disclosureThreat = THREAT_MODEL.threats.find(
        (t) => t.category === "INFORMATION_DISCLOSURE"
      );

      expect(disclosureThreat).toBeTruthy();
      expect(disclosureThreat?.impact).toBe("CRITICAL");
    });

    it("should have privilege escalation threat", () => {
      const elevationThreat = THREAT_MODEL.threats.find(
        (t) => t.category === "ELEVATION_OF_PRIVILEGE"
      );

      expect(elevationThreat).toBeTruthy();
      expect(elevationThreat?.description).toContain("LP");
      expect(elevationThreat?.description).toContain("GP");
    });

    it("should have valid likelihood values", () => {
      const validLikelihoods = ["LOW", "MEDIUM", "HIGH"];

      for (const threat of THREAT_MODEL.threats) {
        expect(validLikelihoods).toContain(threat.likelihood);
      }
    });

    it("should have valid impact values", () => {
      const validImpacts = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

      for (const threat of THREAT_MODEL.threats) {
        expect(validImpacts).toContain(threat.impact);
      }
    });
  });

  describe("Security Controls", () => {
    describe("Encryption Controls", () => {
      it("should specify AES-256-GCM for at-rest encryption", () => {
        expect(THREAT_MODEL.securityControls.encryption.atRest.algorithm).toBe(
          "AES-256-GCM"
        );
      });

      it("should use PBKDF2 for key derivation", () => {
        expect(
          THREAT_MODEL.securityControls.encryption.atRest.keyDerivation
        ).toContain("PBKDF2");
        expect(
          THREAT_MODEL.securityControls.encryption.atRest.keyDerivation
        ).toContain("100,000");
      });

      it("should use TLS 1.3 for in-transit encryption", () => {
        expect(THREAT_MODEL.securityControls.encryption.inTransit.protocol).toBe(
          "TLS 1.3"
        );
      });

      it("should specify client-side encryption for signatures", () => {
        expect(
          THREAT_MODEL.securityControls.encryption.clientSide.algorithm
        ).toBe("AES-GCM-256");
        expect(
          THREAT_MODEL.securityControls.encryption.clientSide.purpose
        ).toContain("signature");
      });

      it("should specify PDF encryption library", () => {
        expect(THREAT_MODEL.securityControls.encryption.pdf.library).toBe(
          "pdf-lib-plus-encrypt"
        );
      });
    });

    describe("Authentication Controls", () => {
      it("should list authentication methods", () => {
        const methods = THREAT_MODEL.securityControls.authentication.methods;

        expect(methods).toContain("Magic links");
        expect(methods).toContain("Google OAuth");
      });

      it("should specify session management approach", () => {
        expect(
          THREAT_MODEL.securityControls.authentication.sessionManagement
        ).toContain("Database-backed");
      });

      it("should specify token format", () => {
        expect(
          THREAT_MODEL.securityControls.authentication.tokenFormat
        ).toContain("SHA-256");
      });
    });

    describe("Authorization Controls", () => {
      it("should use RBAC model", () => {
        expect(THREAT_MODEL.securityControls.authorization.model).toContain(
          "RBAC"
        );
      });

      it("should define GP and LP roles", () => {
        const roles = THREAT_MODEL.securityControls.authorization.roles;

        expect(roles.some((r) => r.includes("GP"))).toBe(true);
        expect(roles.some((r) => r.includes("LP"))).toBe(true);
      });

      it("should specify enforcement mechanism", () => {
        expect(
          THREAT_MODEL.securityControls.authorization.enforcement
        ).toContain("Middleware");
      });
    });

    describe("Audit Logging Controls", () => {
      it("should log security-relevant events", () => {
        const events = THREAT_MODEL.securityControls.auditLogging.events;

        expect(events).toContain("Document views");
        expect(events).toContain("Signature events");
        expect(events).toContain("Login attempts");
      });

      it("should specify indefinite retention for SEC compliance", () => {
        expect(THREAT_MODEL.securityControls.auditLogging.retention).toContain(
          "SEC"
        );
      });

      it("should protect against deletion", () => {
        expect(THREAT_MODEL.securityControls.auditLogging.protection).toContain(
          "Restrict"
        );
      });
    });

    describe("Input Validation Controls", () => {
      it("should use Zod for validation", () => {
        expect(
          THREAT_MODEL.securityControls.inputValidation.framework
        ).toContain("Zod");
      });

      it("should protect against ReDoS", () => {
        expect(THREAT_MODEL.securityControls.inputValidation.patterns).toContain(
          "ReDoS"
        );
      });

      it("should use Prisma for SQL parameterization", () => {
        expect(
          THREAT_MODEL.securityControls.inputValidation.sanitization
        ).toContain("Prisma");
      });
    });
  });

  describe("Compliance Requirements", () => {
    it("should include SEC Rule 506(c)", () => {
      const secCompliance = THREAT_MODEL.complianceRequirements.find(
        (c) => c.regulation.includes("506")
      );

      expect(secCompliance).toBeTruthy();
      expect(secCompliance?.status).toBe("IMPLEMENTED");
    });

    it("should include ESIGN Act", () => {
      const esignCompliance = THREAT_MODEL.complianceRequirements.find(
        (c) => c.regulation.includes("ESIGN")
      );

      expect(esignCompliance).toBeTruthy();
      expect(
        esignCompliance?.requirements.some((r) => r.toLowerCase().includes("consent"))
      ).toBe(true);
    });

    it("should track SOC 2 compliance", () => {
      const soc2Compliance = THREAT_MODEL.complianceRequirements.find(
        (c) => c.regulation.includes("SOC 2")
      );

      expect(soc2Compliance).toBeTruthy();
    });

    it("should have valid status values", () => {
      const validStatuses = ["IMPLEMENTED", "PARTIAL", "PLANNED", "NOT_STARTED"];

      for (const compliance of THREAT_MODEL.complianceRequirements) {
        expect(validStatuses).toContain(compliance.status);
      }
    });
  });

  describe("Future Enhancements", () => {
    it("should include HSM integration", () => {
      const hsm = THREAT_MODEL.futureEnhancements.find(
        (e) => e.feature.includes("HSM")
      );

      expect(hsm).toBeTruthy();
      expect(hsm?.priority).toBe("HIGH");
    });

    it("should include timestamp authority", () => {
      const tsa = THREAT_MODEL.futureEnhancements.find(
        (e) => e.feature.includes("Timestamp")
      );

      expect(tsa).toBeTruthy();
    });

    it("should have valid priority values", () => {
      const validPriorities = ["LOW", "MEDIUM", "HIGH"];

      for (const enhancement of THREAT_MODEL.futureEnhancements) {
        expect(validPriorities).toContain(enhancement.priority);
      }
    });
  });

  describe("getThreatsByCategory", () => {
    it("should return threats for SPOOFING category", () => {
      const threats = getThreatsByCategory("SPOOFING");

      expect(threats.length).toBeGreaterThan(0);
      expect(threats.every((t) => t.category === "SPOOFING")).toBe(true);
    });

    it("should return threats for TAMPERING category", () => {
      const threats = getThreatsByCategory("TAMPERING");

      expect(threats.length).toBeGreaterThan(0);
      expect(threats.every((t) => t.category === "TAMPERING")).toBe(true);
    });

    it("should return empty array for unknown category", () => {
      const threats = getThreatsByCategory("UNKNOWN_CATEGORY");

      expect(threats).toEqual([]);
    });

    it("should return all STRIDE category threats", () => {
      const categories: ThreatCategory[] = [
        "SPOOFING",
        "TAMPERING",
        "REPUDIATION",
        "INFORMATION_DISCLOSURE",
        "DENIAL_OF_SERVICE",
        "ELEVATION_OF_PRIVILEGE",
      ];

      for (const category of categories) {
        const threats = getThreatsByCategory(category);
        expect(threats.length).toBeGreaterThan(0);
      }
    });
  });

  describe("getHighImpactThreats", () => {
    it("should return only HIGH and CRITICAL impact threats", () => {
      const threats = getHighImpactThreats();

      expect(threats.length).toBeGreaterThan(0);
      expect(
        threats.every((t) => t.impact === "HIGH" || t.impact === "CRITICAL")
      ).toBe(true);
    });

    it("should not include LOW or MEDIUM impact threats", () => {
      const threats = getHighImpactThreats();

      expect(
        threats.some((t) => t.impact === "LOW" || t.impact === "MEDIUM")
      ).toBe(false);
    });

    it("should include critical threats", () => {
      const threats = getHighImpactThreats();
      const criticalThreats = threats.filter((t) => t.impact === "CRITICAL");

      expect(criticalThreats.length).toBeGreaterThan(0);
    });
  });

  describe("getSecurityControlSummary", () => {
    it("should return encryption algorithms", () => {
      const summary = getSecurityControlSummary();

      expect(summary).toHaveProperty("encryptionAlgorithms");
      expect(summary.encryptionAlgorithms).toContain("AES-256-GCM");
    });

    it("should return authentication methods", () => {
      const summary = getSecurityControlSummary();

      expect(summary).toHaveProperty("authenticationMethods");
      expect(summary.authenticationMethods.length).toBeGreaterThan(0);
    });

    it("should return compliance status", () => {
      const summary = getSecurityControlSummary();

      expect(summary).toHaveProperty("complianceStatus");
      expect(summary.complianceStatus.length).toBeGreaterThan(0);
      expect(summary.complianceStatus[0]).toHaveProperty("regulation");
      expect(summary.complianceStatus[0]).toHaveProperty("status");
    });
  });

  describe("Type Definitions", () => {
    it("should have ThreatCategory type with all STRIDE values", () => {
      const categories: ThreatCategory[] = [
        "SPOOFING",
        "TAMPERING",
        "REPUDIATION",
        "INFORMATION_DISCLOSURE",
        "DENIAL_OF_SERVICE",
        "ELEVATION_OF_PRIVILEGE",
      ];

      // Type check passes if this compiles
      expect(categories).toHaveLength(6);
    });

    it("should have Sensitivity type with all levels", () => {
      const levels: Sensitivity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

      // Type check passes if this compiles
      expect(levels).toHaveLength(4);
    });
  });
});
