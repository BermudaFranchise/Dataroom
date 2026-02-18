"use client";

import { useState, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Loader2, ShieldCheck, AlertTriangle } from "lucide-react";

// Helper to log cookies from client
function logCookies(step: string) {
  const cookies = document.cookie;
  const cookieList = cookies ? cookies.split(';').map(c => c.trim().split('=')[0]) : [];
  const hasSession = cookieList.some(c => c.includes('session-token'));
  console.log(`[VERIFY-CLIENT] ${step}:`, {
    cookieCount: cookieList.length,
    cookieNames: cookieList,
    hasSessionToken: hasSession,
    url: window.location.href,
  });
}

export default function VerifyPageClient() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isValidating, setIsValidating] = useState(true);
  const [isLinkValid, setIsLinkValid] = useState(false);
  
  const id = searchParams?.get("id") ?? null;
  const checksum = searchParams?.get("checksum") ?? null;
  
  // Log on mount
  useEffect(() => {
    console.log("[VERIFY-CLIENT] Page mounted", {
      hasId: !!id,
      hasChecksum: !!checksum,
      idLength: id?.length || 0,
    });
    logCookies("Initial load");
  }, [id, checksum]);
  
  useEffect(() => {
    async function validateOnLoad() {
      if (!id || !checksum) {
        console.log("[VERIFY-CLIENT] Missing id or checksum, skipping validation");
        setIsValidating(false);
        return;
      }
      
      console.log("[VERIFY-CLIENT] Starting link validation...");
      logCookies("Before validation");
      
      try {
        const response = await fetch("/api/auth/verify-link", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id, checksum, action: "validate" }),
          credentials: "include",
        });
        
        const data = await response.json();
        console.log("[VERIFY-CLIENT] Validation response:", { status: response.status, valid: data.valid, error: data.error });
        
        if (response.ok && data.valid) {
          setIsLinkValid(true);
          setError(null);
          console.log("[VERIFY-CLIENT] Link is valid, ready for sign-in");
        } else {
          setError(data.error || "This link is invalid or has expired.");
          setIsLinkValid(false);
          console.log("[VERIFY-CLIENT] Link validation failed:", data.error);
        }
      } catch (err) {
        console.error("[VERIFY-CLIENT] Validation fetch error:", err);
        setError("Failed to validate link. Please try again.");
        setIsLinkValid(false);
      } finally {
        setIsValidating(false);
        logCookies("After validation");
      }
    }
    
    validateOnLoad();
  }, [id, checksum]);
  
  const handleSignIn = () => {
    if (!id || !checksum) {
      setError("Invalid verification link");
      return;
    }
    
    console.log("[VERIFY-CLIENT] Sign-in button clicked");
    logCookies("Before form submit");
    
    setIsLoading(true);
    setError(null);
    
    // Create and submit a form for proper browser redirect with cookie handling
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/api/auth/verify-link';
    
    const idInput = document.createElement('input');
    idInput.type = 'hidden';
    idInput.name = 'id';
    idInput.value = id;
    form.appendChild(idInput);
    
    const checksumInput = document.createElement('input');
    checksumInput.type = 'hidden';
    checksumInput.name = 'checksum';
    checksumInput.value = checksum;
    form.appendChild(checksumInput);
    
    const actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'sign_in';
    form.appendChild(actionInput);
    
    document.body.appendChild(form);
    form.submit();
  };
  
  if (!id || !checksum) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <AlertTriangle className="mx-auto h-12 w-12 text-yellow-500 mb-4" />
            <CardTitle>Invalid Link</CardTitle>
            <CardDescription>
              This verification link is invalid or has expired.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button onClick={() => router.push("/login")} variant="outline">
              Return to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }
  
  if (isValidating) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Loader2 className="mx-auto h-12 w-12 text-gray-400 animate-spin mb-4" />
            <CardTitle>Verifying Link...</CardTitle>
            <CardDescription>
              Please wait while we verify your login link.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }
  
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <ShieldCheck className="mx-auto h-12 w-12 text-green-600 mb-4" />
          <CardTitle>Complete Your Sign In</CardTitle>
          <CardDescription>
            Click the button below to securely sign in to your BF Fund Portal account.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div className="rounded-md bg-red-50 p-4 text-sm text-red-700">
              {error}
            </div>
          )}
          
          <Button
            onClick={handleSignIn}
            disabled={isLoading || !isLinkValid}
            className="w-full"
            size="lg"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              "Sign In to Portal"
            )}
          </Button>
          
          {!isLinkValid && !error && (
            <Button
              onClick={() => router.push("/login")}
              variant="outline"
              className="w-full"
            >
              Request New Login Link
            </Button>
          )}
          
          <p className="text-center text-xs text-gray-500">
            This extra step ensures that only you can access your account,
            even if email security software scans your links.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
