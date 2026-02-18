import { Metadata } from "next";
import { Suspense } from "react";

import { GTMComponent } from "@/components/gtm-component";

import AdminLoginClient from "./page-client";

const data = {
  description: "Admin Login - FundRoom AI",
  title: "Admin Login | FundRoom AI",
  url: "/admin/login",
};

export const metadata: Metadata = {
  metadataBase: new URL("https://app.login.fundroom.ai"),
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

export default function AdminLoginPage() {
  return (
    <>
      <GTMComponent />
      <Suspense fallback={<div className="flex min-h-screen items-center justify-center">Loading...</div>}>
        <AdminLoginClient />
      </Suspense>
    </>
  );
}
