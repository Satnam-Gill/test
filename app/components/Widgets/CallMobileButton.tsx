import React from "react";
import { FaHouseDamage, FaPhoneVolume } from "react-icons/fa";
import contactContent from "@/app/Data/content";
const ContactInfo: any = contactContent.contactContent;

const CallButtonMobile = () => {
  return (
    <div>
      <div className=" fixed  w-full md:block z-[200]">
        <div className="group fixed bottom-0 flex w-full items-center justify-center bg-main py-2 transition duration-200 ease-in group px-2 max-w-screen-2xl mx-auto ">
          <div className="p-2 bg-main rounded-full -mt-8" >

          <FaHouseDamage  className="text-white text-5xl m-2 md:hidden " />
          </div>
          <a id="cta-id" href={`tel:${ContactInfo.tel}`} className="w-fit text-center">
            <p className="flex gap-2 justify-around items-center px-4 text-center font-bold text-white text-base md:text-2xl py-2 capitalize group-hover:scale-110 transition">
              <FaPhoneVolume className="text-2xl md:text-3xl" />
              Call Us:- {ContactInfo.No}
            </p>
          </a>
        </div>
      </div>
    </div>
  );
};

export default CallButtonMobile;