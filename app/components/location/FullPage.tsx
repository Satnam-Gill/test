"use client";
import React from "react";
import Link from "next/link";
import contactContent from "@/app/Data/content";
import SubdomainContent from "@/app/Data/FinalContent";

const ContactInfo: any = contactContent.contactContent;
const data1: any = SubdomainContent.subdomainData;
type Props = { subdomains?: any[] };

const Page = ({ subdomains }: Props) => {
  // Build a map when subdomains are provided; fallback to static bundle
  const data: any = subdomains && subdomains.length
    ? Object.fromEntries(subdomains.map((s: any) => [s.slug || s.name, s]))
    : data1;
  return (
    <div className="">
      <div>
        <div className="mx-10 mt-10 flex h-fit w-auto flex-wrap items-center   justify-center gap-4">
          {Object.keys(data)
            .sort()
            .map((City: any, index: number) => {
              return (
                <div className="" key={index}>
                  <Link
                    href={`https://${data[City].slug}.${ContactInfo.host}`}
                    className="text-center"
                  >
                    <button
                      type="button"
                      className="mb-2  me-2 rounded-lg bg-main px-5 py-2.5 text-xs font-medium text-white hover:bg-main/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
                    >
                      {data[City].name}
                    </button>
                  </Link>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
};

export default Page;
