import { Metadata } from "next";
import { Suspense } from "react";

import { GTMComponent } from "@/components/gtm-component";

import LoginClient from "./page-client";

const data = {
  description: "Login to your investor portal",
  title: "Login | FundRoom AI",
  url: "/login",
};

export const metadata: Metadata = {
  metadataBase: new URL("https://fundroom.ai"),
  title: data.title,
  description: data.description,
  openGraph: {
    title: data.title,
    description: data.description,
    url: data.url,
    siteName: "FundRoom AI",
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: data.title,
    description: data.description,
    creator: "@fundroomai",
  },
};

export default function LoginPage() {
  return (
    <>
      <GTMComponent />
      <Suspense fallback={<div className="flex min-h-screen items-center justify-center">Loading...</div>}>
        <LoginClient />
      </Suspense>
    </>
  );
}
