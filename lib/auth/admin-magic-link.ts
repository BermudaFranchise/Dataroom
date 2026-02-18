import { randomUUID } from "crypto";

import prisma from "@/lib/prisma";
import { isUserAdminAsync } from "@/lib/constants/admins";

const ADMIN_MAGIC_LINK_EXPIRY_MINUTES = 60; // 1 hour expiry for admin magic links

export async function createAdminMagicLink({
  email,
  redirectPath,
  baseUrl,
}: {
  email: string;
  redirectPath?: string;
  baseUrl: string;
}): Promise<{ magicLink: string; token: string } | null> {
  try {
    const normalizedEmail = email.trim().toLowerCase();
    
    // Check if user is an admin (static list OR database)
    const isAdmin = await isUserAdminAsync(normalizedEmail);
    if (!isAdmin) {
      console.error("[ADMIN_MAGIC_LINK] Email not an admin:", normalizedEmail);
      return null;
    }

    const token = randomUUID();
    const expires = new Date(Date.now() + ADMIN_MAGIC_LINK_EXPIRY_MINUTES * 60 * 1000);

    await prisma.verificationToken.create({
      data: {
        identifier: `admin-magic:${normalizedEmail}`,
        token: token,
        expires,
      },
    });

    const params = new URLSearchParams({
      token,
      email: normalizedEmail,
    });
    
    if (redirectPath) {
      params.set("redirect", redirectPath);
    }

    const magicLink = `${baseUrl}/api/auth/admin-magic-verify?${params.toString()}`;
    console.log("[ADMIN_MAGIC_LINK] Created magic link for:", normalizedEmail);
    
    return { magicLink, token };
  } catch (error) {
    console.error("[ADMIN_MAGIC_LINK] Error creating magic link:", error);
    return null;
  }
}

export async function verifyAdminMagicLink({
  token,
  email,
}: {
  token: string;
  email: string;
}): Promise<boolean> {
  try {
    const normalizedEmail = email.trim().toLowerCase();
    const identifier = `admin-magic:${normalizedEmail}`;
    
    console.log("[ADMIN_MAGIC_LINK] Verifying token for:", { email: normalizedEmail, identifier });
    
    // Check if user is an admin (static list OR database)
    const isAdmin = await isUserAdminAsync(normalizedEmail);
    if (!isAdmin) {
      console.log("[ADMIN_MAGIC_LINK] User is not an admin:", normalizedEmail);
      return false;
    }
    console.log("[ADMIN_MAGIC_LINK] User is admin, checking token...");

    // First try to find by token alone (since token has @unique)
    const verification = await prisma.verificationToken.findUnique({
      where: { token: token },
    });

    console.log("[ADMIN_MAGIC_LINK] Token lookup result:", {
      found: !!verification,
      identifierMatch: verification?.identifier === identifier,
      storedIdentifier: verification?.identifier,
      expectedIdentifier: identifier,
      expires: verification?.expires?.toISOString(),
    });

    if (!verification) {
      console.log("[ADMIN_MAGIC_LINK] Token not found in database");
      return false;
    }

    // Verify the identifier matches (security check)
    if (verification.identifier !== identifier) {
      console.log("[ADMIN_MAGIC_LINK] Identifier mismatch - possible email spoofing");
      return false;
    }

    if (verification.expires < new Date()) {
      console.log("[ADMIN_MAGIC_LINK] Token expired at:", verification.expires);
      await prisma.verificationToken.delete({
        where: { token: token },
      });
      return false;
    }

    // Token is valid - delete it (single use)
    await prisma.verificationToken.delete({
      where: { token: token },
    });
    
    console.log("[ADMIN_MAGIC_LINK] Token verified and consumed successfully");
    return true;
  } catch (error) {
    console.error("[ADMIN_MAGIC_LINK] Error verifying magic link:", error);
    return false;
  }
}
