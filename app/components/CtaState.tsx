import React from "react";
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;



const CtaState = () => {
  return (
    <div>
      <div className=" relative  my-10 overflow-hidden">
        <div className="relative flex h-full w-full flex-col items-center justify-around bg-gradient-to-r from-main    to-gray-600 py-8 text-white md:flex-row">
          <div className="text-center">
            <div className="">
              Call us for a{" "}
              <span className="font-bold text-minor">Cost estimate</span>{" "}
              over free phone
            </div>
            <div className="text-5xl ">{ContactInfo.No}</div>
          </div>
          <div className="mt-10 md:mt-0">
            <a id='cta-id' href={`tel:${ContactInfo.tel}`}>
            <button className="rounded-full bg-main px-5 py-1 text-3xl duration-100 ease-in-out hover:translate-y-2">
              Order Service now
            </button>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CtaState;
