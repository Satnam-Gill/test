"use client";
import React, { useState } from "react";
import Link from "next/link";
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

const AreaWeServe = ({ slugs }: any) => {
  const [showAll, setShowAll] = useState(false);
  const initialCount = 25;

  const handleReadMore = () => {
    setShowAll(true);
  };

  const handleShowLess = () => {
    setShowAll(false);
  };

  return (
    <div className="mx-6 mt-4 flex h-fit w-auto flex-wrap items-center justify-center gap-4 md:mx-10">
      {slugs
        .sort()
        .slice(0, showAll ? slugs.length : initialCount)
        .map((City: any, index: number) => {
          return (
            <div className="" key={index}>
              <a
                href={`https://${City.slug}.${ContactInfo.host}`}
                className="text-center"
              >
                <button
                  type="button"
                  className="mb-2 me-2 rounded-lg bg-main px-5 py-2.5 text-xs font-medium text-white hover:bg-main/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
                >
                  {City.name}
                </button>
              </a>
            </div>
          );
        })}
      {!showAll && slugs.length > initialCount && (
        <button
        onClick={handleReadMore}
          className="mb-2 me-2 rounded-lg bg-minor px-5 py-2.5 text-xs font-medium text-white hover:bg-minor/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
        >
          
          View All
        </button>
      )}
      {showAll && (
        <button
          onClick={handleShowLess}
          className="mb-2 me-2 rounded-lg bg-minor px-5 py-2.5 text-xs font-medium text-white hover:bg-minor/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
        >
          Show Less
        </button>
      )}
    </div>
  );
};

export default AreaWeServe;
