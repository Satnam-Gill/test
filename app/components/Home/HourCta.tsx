import React from "react";
import { FaPhoneSquareAlt } from "react-icons/fa";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const home: any = contactContent.homePageContent;
const HourCta = () => {
  const data = home?.hourCtaWidget;
  return (
    <div>
      <div className=" flex h-full  w-full  flex-col items-center justify-center  bg-main">
        <div className=" w-full overflow-hidden  px-4 py-5 md:px-20 ">
          <div className="flex flex-col  items-start  justify-center gap-10 text-white ">
            <div
              className="w-full pt-4 text-center text-xl font-semibold leading-snug  md:pt-0 md:text-[35px] "
              dangerouslySetInnerHTML={{ __html: data.title }}
            ></div>
            <a
              id="cta-id"
              href={`tel:${ContactInfo.tel}`}
              className="flex    w-full justify-center px-0 md:text-xl"
            >
              <div
                id="cta-id"
                className="flex w-full items-center justify-center gap-6 md:w-fit md:justify-start  "
              >
                <FaPhoneSquareAlt className="text-7xl" />

                <div
                  id="cta-id"
                  className="jsutify-center flex flex-col items-center  "
                >
                  <div
                    id="cta-id"
                    className="jsutify-center flex items-center text-left text-xl"
                  >
                    CALL TODAY
                  </div>
                  <div id="cta-id" className="mt-1 md:text-4xl ">
                    {ContactInfo.No}{" "}
                  </div>
                </div>
              </div>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HourCta;
