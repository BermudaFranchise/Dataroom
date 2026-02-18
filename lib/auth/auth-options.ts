import { PrismaAdapter } from "@auth/prisma-adapter";
import PasskeyProvider from "@teamhanko/passkeys-next-auth-provider";
import { type NextAuthOptions } from "next-auth";
import { type Adapter } from "next-auth/adapters";
import { Provider } from "next-auth/providers/index";
import EmailProvider from "next-auth/providers/email";
import GoogleProvider from "next-auth/providers/google";
import LinkedInProvider from "next-auth/providers/linkedin";

import { identifyUser, trackAnalytics } from "@/lib/analytics";
import { sendVerificationRequestEmail } from "@/lib/emails/send-verification-request";
import { sendWelcomeEmail } from "@/lib/emails/send-welcome";
import hanko from "@/lib/hanko";
import prisma from "@/lib/prisma";
import { serverInstance as rollbar } from "@/lib/rollbar";
import { CreateUserEmailProps, CustomUser } from "@/lib/types";
import { subscribe } from "@/lib/unsend";

function getMainDomainUrl(): string {
  if (process.env.NODE_ENV === "development") {
    return process.env.NEXTAUTH_URL || "http://localhost:3000";
  }
  // Use NEXTAUTH_URL from environment — no hardcoded tenant domains.
  // Falls back to the FundRoom AI login portal if not configured.
  return process.env.NEXTAUTH_URL || "https://app.login.fundroom.ai";
}

const providers: Provider[] = [
  GoogleProvider({
    clientId: process.env.GOOGLE_CLIENT_ID as string,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
  }),
  LinkedInProvider({
    clientId: process.env.LINKEDIN_CLIENT_ID as string,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET as string,
    authorization: {
      params: { scope: "openid profile email" },
    },
    issuer: "https://www.linkedin.com/oauth",
    jwks_endpoint: "https://www.linkedin.com/oauth/openid/jwks",
    profile(profile, tokens) {
      const defaultImage =
        "https://cdn-icons-png.flaticon.com/512/174/174857.png";
      return {
        id: profile.sub,
        name: profile.name,
        email: profile.email,
        image: profile.picture ?? defaultImage,
      };
    },
  }),
  EmailProvider({
    maxAge: 20 * 60,
    async sendVerificationRequest({ identifier, url }) {
      console.log("[AUTH-EMAIL] sendVerificationRequest called with url:", url);
      const hasValidNextAuthUrl = !!process.env.NEXTAUTH_URL;
      console.log("[AUTH-EMAIL] NEXTAUTH_URL valid:", hasValidNextAuthUrl, "Value:", process.env.NEXTAUTH_URL);
      let finalUrl = url;

      if (!hasValidNextAuthUrl) {
        const mainDomainUrl = getMainDomainUrl();
        const urlObj = new URL(url);
        const mainDomainObj = new URL(mainDomainUrl);
        urlObj.hostname = mainDomainObj.hostname;
        urlObj.protocol = mainDomainObj.protocol;
        urlObj.port = mainDomainObj.port || "";

        finalUrl = urlObj.toString();
      }

      await sendVerificationRequestEmail({
        url: finalUrl,
        email: identifier,
      });
    },
  }),
];

if (hanko) {
  providers.push(
    PasskeyProvider({
      tenant: hanko,
      async authorize({ userId }) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) return null;
        return user;
      },
    }),
  );
}

export const authOptions: NextAuthOptions = {
  pages: {
    error: "/login",
  },
  providers,
  adapter: PrismaAdapter(prisma) as Adapter,
  session: { 
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // Update session every 24 hours
  },
  cookies: {
    // Secure flag: true if NODE_ENV is production OR NEXTAUTH_URL is HTTPS.
    // Fallback to NEXTAUTH_URL check handles Replit where NODE_ENV may not be set
    // but the app is served over HTTPS.
    sessionToken: {
      name: `next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax" as const,
        path: "/",
        secure: process.env.NODE_ENV === 'production' || !!process.env.NEXTAUTH_URL?.startsWith('https://'),
      },
    },
    callbackUrl: {
      name: `next-auth.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "lax" as const,
        path: "/",
        secure: process.env.NODE_ENV === 'production' || !!process.env.NEXTAUTH_URL?.startsWith('https://'),
      },
    },
    csrfToken: {
      name: `next-auth.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax" as const,
        path: "/",
        secure: process.env.NODE_ENV === 'production' || !!process.env.NEXTAUTH_URL?.startsWith('https://'),
      },
    },
  },
  debug: process.env.NODE_ENV === 'development' && process.env.AUTH_DEBUG === 'true',
  callbacks: {
    signIn: async ({ user, account }) => {
      const signInContext = {
        userId: user?.id,
        email: user?.email?.substring(0, 3) + "***",
        provider: account?.provider,
        env: process.env.NODE_ENV,
        nextauthUrl: process.env.NEXTAUTH_URL?.substring(0, 50),
      };
      console.log("[AUTH] signIn callback triggered:", signInContext);
      rollbar.info("[AUTH] signIn callback", signInContext);
      return true;
    },
    redirect: async ({ url, baseUrl }) => {
      if (url.startsWith("/")) {
        const path = url.split("?")[0];
        if (path === "/" || path.startsWith("/login")) {
          return `${baseUrl}/viewer-redirect`;
        }
        return `${baseUrl}${url}`;
      }
      
      try {
        const urlObj = new URL(url);
        if (urlObj.origin !== baseUrl) {
          return `${baseUrl}/viewer-redirect`;
        }
        const path = urlObj.pathname;
        if (path === "/" || path.startsWith("/login")) {
          return `${baseUrl}/viewer-redirect`;
        }
        return url;
      } catch {
        return `${baseUrl}/viewer-redirect`;
      }
    },
    jwt: async ({ token, user, trigger }) => {
      // On initial sign in, add user data to token
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.picture = user.image; // Use 'picture' for consistency with session callback

        // Check if user has admin team membership (makes them GP)
        const [dbUser, adminTeam] = await Promise.all([
          prisma.user.findUnique({
            where: { id: user.id },
            select: { role: true, createdAt: true },
          }),
          prisma.userTeam.findFirst({
            where: {
              userId: user.id,
              role: { in: ["OWNER", "ADMIN", "SUPER_ADMIN"] },
              status: "ACTIVE",
            },
          }),
        ]);

        // If user has admin team role, they should be GP
        token.role = adminTeam ? "GP" : (dbUser?.role || "LP");
        token.createdAt = dbUser?.createdAt?.toISOString();

        // Set loginPortal if not already set by a custom flow (admin-magic-verify
        // or verify-link.ts both set this explicitly in their JWTs).
        // For standard NextAuth sign-ins (Google, LinkedIn, email callback),
        // default based on whether user has admin team role.
        if (!token.loginPortal) {
          token.loginPortal = adminTeam ? "ADMIN" : "VISITOR";
        }
      }
      return token;
    },
    session: async ({ session, token }) => {
      // For JWT strategy, user data comes from token
      if (token) {
        (session.user as CustomUser).id = token.id as string;
        (session.user as CustomUser).email = token.email as string;
        (session.user as CustomUser).name = token.name as string;
        (session.user as CustomUser).image = token.picture as string;
        const role = token.role as string;
        (session.user as CustomUser).role = (role === "GP" || role === "LP") ? role : "LP";
        (session.user as CustomUser).createdAt = token.createdAt ? new Date(token.createdAt as string) : undefined;
        // Include loginPortal so it's available to client-side code
        (session.user as CustomUser).loginPortal = token.loginPortal as "ADMIN" | "VISITOR" | undefined;
      }
      return session;
    },
  },
  events: {
    async createUser(message) {
      console.log("[AUTH] createUser event triggered for:", message.user.email);
      
      const params: CreateUserEmailProps = {
        user: {
          name: message.user.name,
          email: message.user.email,
        },
      };

      await identifyUser(message.user.email ?? message.user.id);
      await trackAnalytics({
        event: "User Signed Up",
        email: message.user.email,
        userId: message.user.id,
      });

      console.log("[AUTH] Sending welcome email to:", message.user.email);
      await sendWelcomeEmail(params);
      console.log("[AUTH] Welcome email sent successfully");

      if (message.user.email) {
        await subscribe(message.user.email);
      }
    },
  },
};
