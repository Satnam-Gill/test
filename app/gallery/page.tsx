import { Metadata } from "next";
import React from "react";
import Navbar from "../components/Navbar";
import contactContent from "@/app/Data/content";
import GalleryGrid from "./GalleryGrid";

const ContactInfo: any = contactContent.contactContent;
const galleryContent: any = contactContent.galleryContent;

export const metadata: Metadata = {
  title: "Gallery - Photo Collection",
  description: "Browse our photo gallery collection",
  alternates: {
    canonical: `${ContactInfo.baseUrl}gallery/`,
  },
};

const page = () => {
  return (
    <div className="">
      <Navbar />
      <div className="bg-white">
        <div className="mx-auto max-w-7xl px-4 py-8">
          {/* Simple Header */}
          <div className="mb-8 text-center">
            <h1 className="text-4xl font-bold text-main">Gallery</h1>
            <p className="mt-2 ">Our work portfolio</p>
          </div>

          {/* Gallery Grid Component */}
          <GalleryGrid galleryData={galleryContent.galleries} />
        </div>
      </div>
    </div>
  );
};

export default page;