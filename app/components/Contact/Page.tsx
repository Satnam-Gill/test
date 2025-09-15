import Image from "next/image";
import Link from "next/link";
import React from "react";
import { FaPhoneVolume } from "react-icons/fa6";
import Banner from "../Home/Banner";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const contentData: any = contactContent.contactPageContent;

const Page = () => {

  return (
    <div className="flex flex-col justify-center items-center bg-white text-black">
    <div className="cursor-default w-screen md:w-full text-lg">
      {/* Poster */}
      <Banner
        h1={contentData.h1Banner?.split("[location]").join( ContactInfo.location)
          ?.split("[phone]").join(ContactInfo.No)}
        image={contentData.bannerImage}
        header={contentData?.bannerQuote}
        p1={contentData.metaDescription?.split("[location]").join( ContactInfo.location)
          ?.split("[phone]").join(ContactInfo.No)}
      />
      {/* Poster */}

      {/* Content1 */}
      <div className="flex justify-center items-center">
        <div className="md:px-20 px-4 mt-10">
          <div className="gap-6  mt-10 grid grid-cols-1 md:grid-cols-2 items-center">
            <Image
              src={`${contentData.h2Image}`}
              width={500}
              height={400}
              title={contentData.h2Image.split("/").pop()?.split(".")[0] || "image"}
              alt={contentData.h2Image.split("/").pop()?.split(".")[0] || "image"}
              className="object-cover w-full"
            />
            <div className="flex flex-col justify-center items-center">
              <div className="w-full">
                <h2 className="text-3xl mt-4 md:mt-0 font-bold">
                  {contentData.h2}
                </h2>
              </div>
              <p
                className="mt-4 text-justify"
                dangerouslySetInnerHTML={{ __html: contentData.p2?.split("[location]").join( ContactInfo.location)
                  ?.split("[phone]").join(ContactInfo.No) }}
              ></p>
              <Link id='cta-id' href={`tel:${ContactInfo.tel}`}>
                <button id='cta-id'
                  className="bg-main hover:bg-minor text-white font-bold p-4 rounded-3xl mt-10 text-xl flex justify-center border items-center"
                >
                  <FaPhoneVolume className="text-3xl mr-2" />
                  Call Us Now
                </button>
              </Link>
            </div>
          </div>
        </div>
      </div>
      {/* Content1 */}

      {/* Let's Start a Conversation */}
      <div className="mt-16">
        <div className="text-main text-4xl font-extrabold text-center">
          Let&apos;s Start a Conversation
        </div>
        <div className="text-center border-double">
          <a id='cta-id' href={`tel:${ContactInfo.tel}`}>
            <button id='cta-id'
              className="bg-main hover:bg-minor shadow-lg rounded-lg py-3 px-4 tracking-wide mt-3 text-white font-bold"
            >
              {ContactInfo.No}
            </button>
          </a>
        </div>
      </div>
      {/* Let's Start a Conversation */}

      {/* Content 2 */}
      <div className="grid grid-cols-1 w-full md:grid-cols-2 gap-6 mt-16 md:px-24 px-4 items-center">
        <div className="flex flex-col justify-around w-full gap-3">
          <div>
            <h2 className="text-3xl font-bold">{contentData?.h3?.split("[location]").join( ContactInfo.location)
                ?.split("[phone]").join(ContactInfo.No)
                }</h2>
            <div
              className="mt-10 text-justify"
              dangerouslySetInnerHTML={{ __html: contentData.p3?.split("[location]").join( ContactInfo.location)
                ?.split("[phone]").join(ContactInfo.No) }}
            ></div>
          </div>
        </div>
        <div>
          <Image
            src={`${contentData.h3Image}`}
            className="border rounded-lg w-full h-[350px] shadow-lg object-cover"
            alt={contentData.h3Image.split("/").pop()?.split(".")[0] || "image"}
            width={1000}
            height={500}
          />
        </div>
      </div>
      {/* Content 2 */}

      {/* Call to Action */}
      <div className="xl:w-full w-11/12 mx-4 md:mx-0 mt-16 md:mb-4 px-10 flex flex-col gap-6 md:flex-row justify-center items-center group md:space-x-2">
        <Image
          aria-hidden="true"
          src="https://ik.imagekit.io/h7rza8886p/img1.webp?updatedAt=1747997044944"
          alt="Calling icon"
          width={200}
          height={200}
          className="group-hover:-translate-y-4 ease-in duration-300"
        />
        <Link id='cta-id' href={`tel:${ContactInfo.tel}`} className="w-full grid place-items-center">
          <p id='cta-id'
            className="bg-white w-[90%] text-2xl font-semibold text-center rounded-lg m-h-64 p-2 ring ring-main transform hover:shadow-minor group-hover:translate-y-4 hover:shadow-xl transition ease-in duration-300"
            dangerouslySetInnerHTML={{ __html: contentData.ctaText?.split("[location]").join( ContactInfo.location)?.split("[phone]").join(ContactInfo.No) }}
          ></p>
        </Link>
      </div>
      {/* Call to Action */}

      {/* Map */}
      <div className="w-full mt-10">
        <iframe
          src={contentData.mapLink}
          height="350"
          className="border w-full rounded-lg mt-10"
          loading="lazy"
          title="map"
        ></iframe>
      </div>
      {/* Map */}
    </div>
  </div>
  );
};

export default Page;
