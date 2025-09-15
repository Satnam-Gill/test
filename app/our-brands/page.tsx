import Banner from "@/app/components/Home/Banner";
import React from "react";
import { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import Navbar from "../components/Navbar";
import brandsContent from "@/app/Data/content";

const ContactInfo:any = brandsContent.contactContent;
const contentData:any[any] = brandsContent.brandsContent;

export const metadata: Metadata = {
  title: {
    absolute: contentData.metaTitle,
  },
  description: contentData.metaDescription
    ?.split("[location]")
    .join(ContactInfo.location)
    ?.split("[phone]")
    .join(ContactInfo.No),
  alternates: {
    canonical: `${ContactInfo.baseUrl}our-brands/`,
  },
};
const page = () => {
  return (
    <div>
      <Navbar />
      <Banner
        h1={contentData.h1Banner}
        image={contentData.bannerImage}
        header=""
        p1={contentData.metaDescription
          ?.split("[location]")
          .join(ContactInfo.location)
          ?.split("[phone]")
          .join(ContactInfo.No)}
      />

      {/* Content 1 */}
      <div className="my-10 grid  grid-cols-1 gap-6 px-4 md:grid-cols-2 md:px-24 ">
        <div className="flex flex-col justify-center    ">
          <h2 className="text-first text-3xl font-bold">{contentData.h2}</h2>
          <div
            className="mt-4  text-justify"
            dangerouslySetInnerHTML={{ __html: contentData.p2 }}
          ></div>
        </div>
        <div className="">
          <Image
            height={10000}
            width={10000}
            src={`${contentData.h2Image}`}
            className=" h-full w-full rounded-lg object-cover shadow-lg"
            alt={contentData.h2Image.split(".")[0]}
            title={contentData.h2Image.split(".")[0]}
          />
        </div>
      </div>
      {/* Content 1 */}
      {contentData.brandslist && (
        <div className=" flex  flex-col justify-center bg-slate-50 py-10">
          {contentData.brandslist.map((i:any, index:number) => (
            <div
              key={index}
              className="mx-auto grid max-w-6xl items-center justify-center gap-4 border-b border-black p-4 md:py-10"
            >
              <p className="w-1/2 text-3xl text-main duration-100 ease-in-out hover:underline">
                <Link href={i.brandLink}>{i.brandName}</Link>
              </p>
              <p className="">{i.brandDescription}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default page;
