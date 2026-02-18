import { Metadata } from "next";
import { Suspense } from "react";

import LPLoginClient from "./page-client";

const data = {
  description: "Investor Login - FundRoom AI",
  title: "Investor Login | FundRoom AI",
  url: "/lp/login",
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

export default function LPLoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-emerald-500" />
      </div>
    }>
      <LPLoginClient />
    </Suspense>
  );
}
