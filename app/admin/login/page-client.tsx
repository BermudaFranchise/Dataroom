"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import { useState, useEffect, useMemo } from "react";

import { signIn, useSession } from "next-auth/react";
import { toast } from "sonner";
import { z } from "zod";

import { cn } from "@/lib/utils";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { X, Building2 } from "lucide-react";

export default function AdminLoginClient() {
  const searchParams = useSearchParams();
  const next = useMemo(() => {
    const nextParam = searchParams?.get("next");
    if (!nextParam) return null;
    const decoded = decodeURIComponent(nextParam);
    // Prevent redirect loops - if next points to a login page, ignore it
    if (decoded.includes("/login") || decoded.includes("/admin/login") || decoded.includes("/lp/login")) {
      return null;
    }
    return decoded;
  }, [searchParams]);
  const router = useRouter();
  const sessionData = useSession();
  const session = sessionData?.data;
  const status = sessionData?.status ?? "loading";

  // Log session changes
  useEffect(() => {
    if (status === "authenticated") {
      router.push(next || "/hub");
    }
  }, [status, router, next]);

  // Handle authentication errors from URL params
  const authError = searchParams?.get("error");
  useEffect(() => {
    if (authError) {
      const errorMessages: Record<string, string> = {
        Verification: "Your login link has expired or was already used. Please request a new one.",
        AccessDenied: "Access denied. You may not have admin permission.",
        Configuration: "There was a configuration error. Please try again.",
        Default: "An error occurred during sign in. Please try again.",
      };
      const message = errorMessages[authError] || errorMessages.Default;
      toast.error(message);
      // Clear the error from URL without refresh
      window.history.replaceState({}, '', '/admin/login');
    }
  }, [authError]);

  const [clickedMethod, setClickedMethod] = useState<"email" | undefined>(
    undefined,
  );
  const [email, setEmail] = useState<string>("");
  const [emailButtonText, setEmailButtonText] = useState<string>(
    "Continue with Email",
  );
  const [showAccessNotice, setShowAccessNotice] = useState(false);

  const emailSchema = z
    .string()
    .trim()
    .toLowerCase()
    .min(3, { message: "Please enter a valid email." })
    .email({ message: "Please enter a valid email." });

  const emailValidation = emailSchema.safeParse(email);

  return (
    <div className="flex h-screen w-full flex-wrap bg-gray-950">
      <div className="flex w-full items-center justify-center bg-gray-950 md:w-1/2 lg:w-1/2">
        <div
          className="absolute inset-x-0 top-10 -z-10 flex transform-gpu justify-center overflow-hidden blur-3xl"
          aria-hidden="true"
        ></div>
        <div className="z-10 mx-5 h-fit w-full max-w-md overflow-hidden rounded-lg sm:mx-0">
          <div className="items-left flex flex-col space-y-3 px-4 py-6 pt-8 sm:px-12">
            {/* FundRoom AI branding — will be overridden by tenant branding when loaded */}
            <div className="mb-6 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600">
                <Building2 className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold text-white">FundRoom AI</span>
            </div>
            <Link href="/">
              <span className="text-balance text-3xl font-semibold text-white">
                Admin Portal
              </span>
            </Link>
            <h3 className="text-sm text-gray-300">
              Authorized administrators only
            </h3>
          </div>
          <div className="mx-4 mt-2 mb-6 sm:mx-12 rounded-lg border border-amber-500/50 bg-amber-500/10 p-4">
            <p className="text-sm text-amber-200 text-center">
              This login is for organization administrators only. If you are an investor, please use the{" "}
              <Link href="/login" className="underline hover:text-amber-100">
                investor login
              </Link>.
            </p>
          </div>
          <div className="px-4 sm:px-12">
            <p className="mb-4 text-center text-gray-300">
              Enter your admin email to receive a secure login link
            </p>
          </div>
          <form
            className="flex flex-col gap-4 px-4 sm:px-12"
            onSubmit={async (e) => {
              e.preventDefault();

              if (!emailValidation.success) {
                toast.error(emailValidation.error.errors[0].message);
                return;
              }

              setClickedMethod("email");

              try {
                const loginRes = await fetch("/api/auth/admin-login", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    email: emailValidation.data,
                    redirectPath: next || "/hub",
                  }),
                  credentials: "include",
                });

                const data = await loginRes.json();

                if (!loginRes.ok) {
                  setClickedMethod(undefined);
                  if (loginRes.status === 403) {
                    setShowAccessNotice(true);
                  } else {
                    toast.error(data.error || "Unable to send login link. Please try again.");
                  }
                  return;
                }

                setEmail("");
                setEmailButtonText("Email sent - check your inbox!");
                toast.success("Email sent - check your inbox!");
                setShowAccessNotice(false);
                setClickedMethod(undefined);
              } catch (error) {
                setClickedMethod(undefined);
                toast.error("Unable to send login link. Please try again.");
              }
            }}
          >
            <Label className="sr-only" htmlFor="email">
              Email
            </Label>
            <Input
              id="email"
              placeholder="admin@yourorg.com"
              type="email"
              autoCapitalize="none"
              autoComplete="email"
              autoCorrect="off"
              disabled={clickedMethod === "email"}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={cn(
                "flex h-10 w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white ring-0 transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50",
                email.length > 0 && !emailValidation.success
                  ? "border-red-500"
                  : "border-gray-700",
              )}
            />
            <div className="relative">
              <Button
                type="submit"
                loading={clickedMethod === "email"}
                disabled={!emailValidation.success || !!clickedMethod}
                className={cn(
                  "focus:shadow-outline w-full transform rounded px-4 py-2 text-white transition-colors duration-300 ease-in-out focus:outline-none",
                  clickedMethod === "email"
                    ? "bg-blue-600"
                    : "bg-blue-600 hover:bg-blue-700",
                )}
              >
                {emailButtonText}
              </Button>
            </div>
          </form>
          {showAccessNotice && (
            <div className="mx-4 mt-4 sm:mx-12 relative rounded-lg border border-red-500/50 bg-red-500/10 p-4">
              <button
                onClick={() => setShowAccessNotice(false)}
                className="absolute right-2 top-2 p-1 text-gray-400 hover:text-white transition-colors"
                aria-label="Close notice"
              >
                <X className="h-4 w-4" />
              </button>
              <p className="text-sm text-red-200 pr-6 mb-3">
                This email is not authorized for admin access. This portal is only for organization administrators.
              </p>
              <p className="text-sm text-red-200 pr-6 mb-3">
                If you are an investor looking to access the dataroom, please use the investor portal instead.
              </p>
              <Link
                href="/login"
                className="inline-block w-full text-center py-2 px-4 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors text-sm font-medium"
              >
                Go to Investor Login
              </Link>
            </div>
          )}
          <p className="mt-6 w-full max-w-md px-4 text-xs text-gray-500 sm:px-12">
            By clicking continue, you acknowledge that you have read and agree
            to FundRoom AI&apos;s{" "}
            <a
              href="https://fundroom.ai/terms"
              className="underline text-gray-400 hover:text-white"
            >
              Terms of Service
            </a>{" "}
            and{" "}
            <a
              href="https://fundroom.ai/privacy"
              className="underline text-gray-400 hover:text-white"
            >
              Privacy Policy
            </a>
            .
          </p>
          <div className="mt-6 w-full max-w-md px-4 text-center sm:px-12">
            <p className="text-sm text-gray-500">
              Don&apos;t have an organization yet?{" "}
              <Link
                href="/signup"
                className="text-blue-400 hover:text-blue-300"
              >
                Get started
              </Link>
            </p>
          </div>
          <div className="mt-4 mb-4 w-full max-w-md px-4 text-center sm:px-12">
            <Link
              href="/login"
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              Back to investor login
            </Link>
          </div>
        </div>
      </div>
      <div className="relative hidden w-full justify-center overflow-hidden bg-gradient-to-br from-gray-900 via-blue-950/30 to-gray-900 md:flex md:w-1/2 lg:w-1/2">
        <div className="relative m-0 flex h-full min-h-[700px] w-full p-0">
          <div
            className="relative flex h-full w-full flex-col justify-between"
            id="features"
          >
            <div
              className="flex h-full w-full flex-col items-center justify-center"
            >
              <div className="mb-8 flex h-20 w-20 items-center justify-center rounded-2xl bg-blue-600">
                <Building2 className="h-10 w-10 text-white" />
              </div>
              <div className="max-w-xl text-center px-8">
                <h2 className="text-balance text-2xl font-bold leading-8 text-white sm:text-3xl mb-4">
                  FundRoom AI
                </h2>
                <p className="text-balance font-normal leading-7 text-gray-300 sm:text-lg">
                  Secure fundraising infrastructure for funds and startups
                </p>
                <p className="mt-6 text-balance font-semibold text-blue-400 text-xl">
                  Raise smarter. Close faster.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
