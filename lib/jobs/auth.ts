import crypto from "crypto";

interface PublicTokenOptions {
  scopes: {
    read: {
      tags: string[];
    };
  };
  expirationTime: string;
}

export const auth = {
  createPublicToken: async (options: PublicTokenOptions): Promise<string> => {
    const payload = {
      tags: options.scopes.read.tags,
      exp: Date.now() + parseExpirationTime(options.expirationTime),
      jti: crypto.randomUUID(),
    };
    return Buffer.from(JSON.stringify(payload)).toString("base64url");
  },
};

function parseExpirationTime(time: string): number {
  const match = time.match(/^(\d+)([smh])$/);
  if (!match) return 15 * 60 * 1000;
  const value = parseInt(match[1], 10);
  switch (match[2]) {
    case "s":
      return value * 1000;
    case "m":
      return value * 60 * 1000;
    case "h":
      return value * 60 * 60 * 1000;
    default:
      return 15 * 60 * 1000;
  }
}

export function verifyToken(
  token: string,
): { tags: string[]; expired: boolean } | null {
  try {
    const payload = JSON.parse(
      Buffer.from(token, "base64url").toString("utf-8"),
    );
    return {
      tags: payload.tags || [],
      expired: payload.exp < Date.now(),
    };
  } catch {
    return null;
  }
}
