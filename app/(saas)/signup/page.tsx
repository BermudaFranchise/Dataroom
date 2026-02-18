import { Metadata } from "next";

import SignupClient from "./page-client";

const data = {
  description:
    "Create your organization on FundRoom AI — secure investor portals, datarooms, and fundraising infrastructure.",
  title: "Get Started | FundRoom AI",
  url: "/signup",
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

export default function SignupPage() {
  return <SignupClient />;
}
