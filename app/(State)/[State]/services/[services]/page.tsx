import Banner from "@/app/components/Home/Banner";
import React from "react";
import Image from "next/image";
import Service from "@/app/components/Home/Service";
import { headers } from "next/headers";
import CtaSimple from "@/app/components/CtaSimple";
import NavbarState from "@/app/components/State/NavbarState";
import contactContent from "@/app/Data/content";
import subdomainContent from "@/app/Data/FinalContent";

const ContactInfo: any = contactContent.contactContent;
const data: any = contactContent.servicePageContent;
const content: any = subdomainContent.subdomainData;
const Servicedata = data?.serviceData;

export function generateMetadata({ params }: { params: { services: string } }) {
  const serviceData: any = Servicedata.lists.find(
    (service: any) => service.slug === params.services,
  );
  const headersList = headers();
  const subdomain = headersList.get("x-subdomain");
  const Data: any = content[subdomain as keyof typeof content];
  return {
    title: serviceData.title
      ?.split(ContactInfo.location)
      .join(Data?.name || ContactInfo.location)
      ?.split("[phone]")
      .join(ContactInfo.No),
    description: serviceData.description
      ?.split(ContactInfo.location)
      .join(Data?.name || ContactInfo.location)
      ?.split("[phone]")
      .join(ContactInfo.No),
    alternates: {
      canonical: `https://${Data.slug}.${ContactInfo.host}/services/${params.services}/`,
    },
  };
}

const page = ({ params }: { params: { services: string } }) => {
  const serviceData: any = Servicedata.lists.find(
    (service: any) => service.slug === params.services,
  );
  const headersList = headers();
  const subdomain = headersList.get("x-subdomain");
  const Data: any = content[subdomain as keyof typeof content];
  const locationName = Data?.name || ContactInfo.location;
  return (
    <div className="">
      <NavbarState />
      <div className="">
        <Banner
          h1={serviceData.title.split(ContactInfo.location).join(locationName)}
          header=""
          p1={serviceData.description
            ?.split(ContactInfo.location)
            .join(Data?.name || ContactInfo.location)
            ?.split("[phone]")
            .join(ContactInfo.No)}
        />
        <div className="mx-4 mt-6 print:hidden md:mx-10">
          {/* who */}
          <div className="my-20 grid w-full grid-cols-1 items-center justify-center gap-6 px-8 md:grid-cols-2">
            <div className="flex flex-col justify-center">
              <div className="text-3xl font-bold">
                <h2>
                  {" "}
                  {serviceData.title.split(ContactInfo.location).join(locationName)}
                </h2>
                <br />
              </div>
              <div
                className="text-justify "
                dangerouslySetInnerHTML={{
                  __html: serviceData.p2
                    ?.split(ContactInfo.location)
                    .join(ContactInfo.location)
                    ?.split("[phone]")
                    .join(ContactInfo.No),
                }}
              ></div>
            </div>
            <div className="w-full pt-10">
              <Image
                src={serviceData.imageUrl}
                className="h-80 rounded-lg border object-cover shadow-lg"
                alt={
                  serviceData.title.split("/").pop()?.split(".")[0] || "image"
                }
                width={1000}
                height={1000}
              />
            </div>
          </div>
          {/* who */}
        </div>
        <div className="my-20 bg-main text-white">
          <div className="text- mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
            <h2 className=" text-center text-3xl font-bold">
              {serviceData.h3.split(ContactInfo.location).join(locationName)}
            </h2>
            <div
              className="mt-4 flex flex-wrap justify-center gap-4">
              {serviceData.p3.split("|").map((Item: string) => (
                <p key={Item} className="m-2  rounded-md border  p-4 font-bold">
                  {Item}
                </p>
              ))}
            </div>
          </div>
        </div>

        <Service value={subdomain} />
        <div className="my-20">
          <CtaSimple />
        </div>
        {serviceData.seoContent && (
          <div className="bg-gray-100 text-black ">
            <div className="mx-auto max-w-4xl px-4 py-12 text-center sm:px-6 lg:px-8">
              <div
                className="mt-4 "
                dangerouslySetInnerHTML={{
                  __html: serviceData.seoContent
                    ?.split(ContactInfo.location)
                    .join(ContactInfo.location)
                    ?.split("[phone]")
                    .join(ContactInfo.No),
                }}
              ></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default page;