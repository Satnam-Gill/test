import Banner from "@/app/components/Home/Banner";
import React from "react";
import Service from "@/app/components/Home/Service";
import contentData from "@/components/Content/servicePage.json";
import NavbarState from "@/app/components/State/NavbarState";
import { headers } from "next/headers";

import contactContent from "@/app/Data/content";
import subdomainContent from "@/app/Data/FinalContent";

const ContactInfo: any = contactContent.contactContent;
const content: any = subdomainContent.subdomainData;

export function generateMetadata({ params }: { params: { services: string } }) {
  const headersList = headers();
  const subdomain = headersList.get("x-subdomain") as
    | keyof typeof content
    | null;
  let subdomainKey = subdomain as any;
  if (subdomainKey?.includes("-")) {
    subdomainKey = subdomainKey.split("-").pop();
  }

  if (!subdomain || !(subdomain in content)) {
    // Handle the case where subdomain is null or not in content
    return <div>Error: Invalid subdomain</div>;
  }
  const Data: any = content[subdomain];
  return {
    title: {
      absolute: contentData.h1Banner?.split("[location]").join(Data?.name || ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No),
    },
    description: contentData.metaDescription?.split("[location]").join(Data?.name || ContactInfo.location)
    ?.split("[phone]").join(ContactInfo.No),
    alternates: {
      canonical: `https://${Data.slug}.${ContactInfo.host}/services/`,
    },
  };
}
const page = () => {
  const headersList = headers();
  const subdomain = headersList.get("x-subdomain") as
    | keyof typeof content
    | null;
  let subdomainKey = subdomain as any;
  if (subdomainKey?.includes("-")) {
    subdomainKey = subdomainKey.split("-").pop();
  }

  if (!subdomain || !(subdomain in content)) {
    // Handle the case where subdomain is null or not in content
    return <div>Error: Invalid subdomain</div>;
  }
  const Data: any = content[subdomain];
console.log(contentData.h1Banner)

  return (
    <div className="">
      <NavbarState />
      <div>
        <Banner
          h1={contentData.h1Banner?.split("[location]").join(Data?.name || ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
          image={contentData.bannerImage}
          header={contentData.bannerQuote?.split("[location]").join(Data?.name || ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
          p1={contentData.metaDescription?.split("[location]").join(Data?.name || ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
        />

        {/* Content 1 */}
        <div className="">
          {/* <Affordable /> */}
          <Service value={subdomain}/>
          {/* <TypeOfDumpster /> */}
        </div>
        {/* Content 1 */}
      </div>
    </div>
  );
};

export default page;
