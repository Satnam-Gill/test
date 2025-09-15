import React from "react";
import { BsFillTelephoneFill } from "react-icons/bs";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

const CtaSimple = () => {
  return (
    <div className=" overflow-hidden w-full">   
     <div className=" text-center z-[2]  grid gap-4 font-bold py-6 text-white bg-main group  relative  ">
      <div className="text-lg animate-bounce transition">24/7 Customer Service</div>
      <p className="text-4xl  flex justify-center   items-center cursor-pointer ease-in duration-200 delay-150 group-hover:scale-105 group ">
        <a href={`tel:${ContactInfo?.tel}`} className="flex gap-2 ">
          <BsFillTelephoneFill className="group-hover:rotate-[135deg] ease-in-out duration-300 delay-100"/>
          {ContactInfo?.No}
        </a>
      </p>
    </div>
    </div>

  );
};

export default CtaSimple;