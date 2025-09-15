import React from "react";
import FullPage from "@/app/components/location/FullPage";
import Banner from "@/app/components/Home/Banner";
import { Metadata } from "next";
import Navbar from "../components/Navbar";
import { headers } from "next/headers";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const contentData: any = contactContent.locationPageContent;

export const metadata: Metadata = {
  title: {
    absolute: contentData.metaTitle,
  },
  description: contentData.metaDescription?.split("[location]").join( ContactInfo.location)
  ?.split("[phone]").join(ContactInfo.No),
  alternates: {
    canonical: `${ContactInfo.baseUrl}locations/`,
  },
};

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function getSubdomainData() {
  const headersList = headers();
  const proto: any = headersList.get("x-forwarded-proto") || "http";
  const host = headersList.get("host");
  const baseUrl = `${proto}://${host}`;
  const res = await fetch(`${baseUrl}/api/subdomains`, { cache: "no-store" });
  return res.json().catch(() => ({}));
}

const page = async () => {
  let subdomains: any[] = [];
  try {
    const data = await getSubdomainData();
    if (data && data.subdomains) {
      subdomains = data.subdomains;
    }
  } catch (e) {}
  return (
    <div className="">
      <Navbar />
      <div>
        <Banner
          h1={contentData.h1Banner}
          image={contentData.bannerImage}
          header={contentData.bannerQuote}
          p1={contentData.metaDescription?.split("[location]").join( ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
        />
        <div className="py-10">
          <FullPage subdomains={subdomains} />
        </div>
      </div>
    </div>
  );
};

export default page;
