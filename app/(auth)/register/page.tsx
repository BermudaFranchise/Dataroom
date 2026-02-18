import { Metadata } from "next";

import RegisterClient from "./page-client";

const data = {
  description: "Create your account on FundRoom AI",
  title: "Register | FundRoom AI",
  url: "/register",
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

export default function RegisterPage() {
  return <RegisterClient />;
}
