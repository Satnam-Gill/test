import { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import React from "react";
import { FaCrown } from "react-icons/fa6";
import Banner from "@/app/components/Home/Banner";
import contentData from "@/components/Content/about.json"
import Navbar from "../components/Navbar";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const aboutContent: any = contactContent.aboutContent;

export const metadata: Metadata = {
  title: {
    absolute: contentData.metaTitle?.split("[location]").join( ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No),
  },
  description: contentData.metaDescription?.split("[location]").join( ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No),
  alternates: {
    canonical: `${ContactInfo.baseUrl}about/`,
  },
}
const page = () => {
  return (
    <div className="">
      <Navbar/>
      <div className="max-[1200px] flex flex-col items-center justify-center bg-white text-black">
      <div className="flex flex-col max-[1200px] justify-center items-center  bg-white text-black ">
      <div className="  cursor-default w-screen md:w-full  min-w-[375px] text-lg">
        {/* poster */}
        <Banner
          h1={contentData.h1Banner?.split("[location]").join( ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
          image={contentData.bannerImage}
          header={contentData.bannerQuote}
          p1={contentData.metaDescription?.split("[location]").join( ContactInfo.location)
            ?.split("[phone]").join(ContactInfo.No)}
        />
        {/* poster */}
        {/* -----------------------------------------About Start------------------------ */}
        <div className="md:mx-10 mx-4 mt-6 print:hidden">
          {/* who */}
          <div className="grid grid-cols-1  md:grid-cols-2 w-full gap-6 my-20 px-8 justify-center items-center">
            <div className="flex flex-col justify-center    ">
              <div className="text-">ABOUT </div>
              <h2 className="text-3xl font-bold ">
                {" "}
                Who We Are?<br></br>
              </h2>
              <div className="mt-6 "></div>
              <div className="  text-justify" dangerouslySetInnerHTML={{ __html: contentData.p2?.split("[location]").join( ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No) }}>
              </div>
            </div>
            <div className="w-full pt-10">
              <Image
                src={`${contentData.h2Image}`}
                className="border rounded-lg shadow-lg  object-cover "
                alt={contentData.h2Image.split("/").pop()?.split(".")[0] || "image"}
                width={1000}
                height={1000}
              />
            </div>
          </div>
          {/* who */}
          {/* Commitment */}
          {/* <div className="md:mx-10 mx-4 mt-6 flex md:flex-row flex-col gap-8 ">
            
            <div className="bg-[#191e34] text-white md:w-[40%] h-full rounded-lg font-extrabold text-3xl text-center p-6 space-y-2 "> <div className="">Call Now to get</div> <div className="">Best Dryer</div> <div className="text-">Vent Cleaning Price</div> <div className="flex justify-between items-center"><BsBookmarkStarFill className="text-3xl"/>
            <button className=" rounded-lg  hover:translate-y-2  bg-transparent  text-white font-bold">
              <a href="tel:8884398896"> (888) 271-6884</a>
            </button>
            <BsBookmarkStarFill className="text-3xl"/></div>
            </div>
            
            <div className="border-2 mt-2  rounded-lg border-[#191e34] w-full">
              <h2 className="text-2xl font-bold p-2 text-center">Our Expertise</h2>
              <div className=" p-4 text-justify">With over 15 years in the field, we boast a wealth of experience, having improved thousands of dryer systems. Our certified technicians employ the latest cleaning technology, offering personalized, effective solutions to meet the diverse needs of our customers, ensuring safety and efficiency.</div>

            </div>
          </div> */}
          {/* Commitment */}

        </div>
        {/* -----------------------------------------About End------------------------ */}
        {/* Mission */}
        <div className="md:mx-10 mx-4 mt-6 flex md:flex-row flex-col gap-8 md:px-32 relative  h-full">


          <div className="p-4  rounded-lg w-full grid grid-cols-1 md:grid-cols-3 gap-8 ">
            <div className="border-[3px] hover:bg-main  hover:text-white ease-in-out duration-300  rounded-lg border-main ">
              <h2 className="text-2xl font-bold p-2 text-center">{contentData.missionSection[0].title}</h2>
              <div className=" p-4 text-center" dangerouslySetInnerHTML={{ __html: contentData.missionSection[0].description?.split("[location]").join( ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No)}}></div>
            </div>

            <div className="border-[3px] bg-main  hover:bg-transparent hover:text-black  text-white ease-in-out duration-300  rounded-lg border-main ">
              <h2 className="text-2xl font-bold p-2 text-center">{contentData.missionSection[1].title}</h2>
              <div className=" p-4 text-center" dangerouslySetInnerHTML={{ __html: contentData.missionSection[1].description?.split("[location]").join( ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No)}}></div>
            </div>

            <div className="border-[3px] hover:bg-main hover:text-white ease-in-out duration-300  rounded-lg border-main ">
              <h2 className="text-2xl font-bold p-2 text-center">{contentData.missionSection[2].title}</h2>
              <div className=" p-4 text-center" dangerouslySetInnerHTML={{ __html: contentData.missionSection[2].description?.split("[location]").join( ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No)}}></div>
            </div>

          </div>

        </div>
        {/* Mission */}
        {/* -----------------------------------------Conversation ------------------------ */}
        <div className="my-20">
          <div className={`text-main text-4xl font-extrabold text-center`}>
            Let&apos;s Start a Conversation
          </div>
          <div className="text-center mt-4 border-double">
            <button id='cta-id' className={`bg-main hover:bg-minor shadow-lg rounded-lg py-3 px-4 tracking-wide mt-3     text-white font-bold`}>
              <a id='cta-id' href={`tel:${ContactInfo.tel}`}> {ContactInfo.No}</a>
            </button>
          </div>
        </div>
        {/* -----------------------------------------Conversation End------------------------ */}
        {/* all */}
        <div className="md:mx-20 mx-4 my-20">
          <div className="text-2xl font-bold "><div className="flex justify-center gap-2 "><FaCrown className={`text-2xl text-main `} />Areas We Serve</div></div>
          <div className=" mt-2 text-xl text-center" dangerouslySetInnerHTML={{ __html: contentData.areaweserveSection.description?.split("[location]").join(ContactInfo.location)
      ?.split("[phone]").join(ContactInfo.No) }}> 
            
          </div>
          <div className="flex justify-center">
          <Link href={`${ContactInfo?.baseUrl}locations`} className=" font-bold text-main hover:tracking-wide ease-in duration-150 text-xl text-center ">{contentData.areaweserveSection.linkText}</Link>
          </div>
          
          

        </div>
        {/* all */}
        {/* -----------------------------------------Our Mission Start------------------------ */}
        {/* <div className="flex-col md:flex md:flex-row border  md:mx-8 mx-4 py-4 rounded-lg gap-6 mt-10 mb-10 md:px-8 px-4">
          <div className="md:w-1/4">
            <img
              src="/our-mission-ideas.jpeg"
              className="border rounded-lg shadow-lg "
              alt="Star Dryer Vent Cleaning"
            />
          </div>
          <div className="mt-2 md:mt-0 flex flex-col justify-center  w-full gap-3 ">
            <div className="text-2xl font-bold">Our Mission</div>
            <div className="md:mt-3 mt-2 text-base">
              Our mission is to provide top-tier dryer vent cleaning services focused on safety, efficiency, and customer satisfaction. We strive for excellence in every service, using eco-friendly methods to enhance your home or business while ensuring a smooth and professional experience.
            </div>
          </div>
        </div> */}
        {/* -----------------------------------------Our Mission End------------------------ */}
      </div>
    </div>
      </div>
    </div>
  );
};

export default page;
