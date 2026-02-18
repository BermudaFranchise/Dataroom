import crypto from "crypto";
import { sendEmail } from "@/lib/resend";
import prisma from "@/lib/prisma";
import { serverInstance as rollbar } from "@/lib/rollbar";

import LoginLink from "@/components/emails/verification-link";

import { generateChecksum } from "../utils/generate-checksum";

export const sendVerificationRequestEmail = async (params: {
  email: string;
  url: string;
}) => {
  const { url, email } = params;
  
  const callbackUrlObj = new URL(url);
  const callbackHost = callbackUrlObj.host;
  const nextauthUrl = process.env.NEXTAUTH_URL || 'not-set';
  const nextauthHost = nextauthUrl !== 'not-set' ? new URL(nextauthUrl).host : 'not-set';
  
  console.log("[EMAIL] Sending verification email to:", email);
  console.log("[EMAIL] Original NextAuth callback URL:", url.substring(0, 100) + "...");
  console.log("[EMAIL] Callback host:", callbackHost, "| NEXTAUTH_URL host:", nextauthHost);
  
  rollbar.info("[EMAIL] Creating magic link", {
    email: email.substring(0, 3) + "***",
    callbackHost,
    nextauthHost,
    hostMatch: callbackHost === nextauthHost,
    env: process.env.NODE_ENV,
  });
  
  const emailLower = email.toLowerCase();
  
  await prisma.magicLinkCallback.deleteMany({
    where: { identifier: emailLower },
  });
  console.log("[EMAIL] Cleaned up old MagicLinkCallbacks for:", emailLower);
  
  const magicLinkToken = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
  
  await prisma.magicLinkCallback.create({
    data: {
      identifier: emailLower,
      token: magicLinkToken,
      callbackUrl: url,
      authTokenHash: "",
      expires: expiresAt,
    },
  });
  
  console.log("[EMAIL] Created MagicLinkCallback entry for:", email);
  console.log("[EMAIL] Stored callbackUrl:", url.substring(0, 100) + "...");
  
  const checksum = generateChecksum(magicLinkToken);
  const verificationUrlParams = new URLSearchParams({
    id: magicLinkToken,
    checksum,
  });

  const baseUrl = process.env.VERIFICATION_EMAIL_BASE_URL || process.env.NEXTAUTH_URL;
  const verificationUrl = `${baseUrl}/verify?${verificationUrlParams}`;
  console.log("[EMAIL] Verification URL (secure, no callback):", verificationUrl.substring(0, 80) + "...");
  
  const emailTemplate = LoginLink({ url: verificationUrl });
  try {
    await sendEmail({
      to: email as string,
      from: "BF Fund Portal <dataroom@investors.bermudafranchisegroup.com>",
      subject: "Your BF Fund Portal Login Link",
      react: emailTemplate,
    });
    console.log("[EMAIL] Verification email sent successfully");
  } catch (e) {
    console.error("[EMAIL] Error sending verification email:", e);
    throw e;
  }
};
