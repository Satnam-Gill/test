import React from "react";
import { GrUserWorker } from "react-icons/gr";
import { FaRegThumbsUp } from "react-icons/fa";
import { GiReceiveMoney } from "react-icons/gi";

import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const home: any = contactContent.homePageContent;

const Affordable = () => {
  const content = home?.affordableWidget;
  return (
    <div className="bg-gray-100 px-6 py-12">
      <div className="mx-auto flex h-full max-w-7xl flex-col items-center justify-center gap-10 text-center lg:flex-row">
        <div className="lg:w-[40%]">
          <h2 className="text-3xl font-bold text-gray-800">{content.title}</h2>
          <p className="mt-4 text-gray-600">{content.description}</p>
          <a id="cta-id" href={`tel:${ContactInfo.tel}`}>
            <button
              id="cta-id"
              className="mt-8 rounded-lg bg-minor px-6 py-3 text-white transition duration-700 ease-in hover:bg-main"
            >
              {content.ctaText}
            </button>
          </a>
        </div>
        <div className="mt-8 flex flex-col justify-center gap-6 lg:flex-row">
          {content.cards.map((card:any, index:number) => (
            <div
              key={index}
              className={`flex w-full max-w-sm flex-col items-center rounded-lg ${
                index === 1 ? "border border-main" : "bg-white"
              } p-6 shadow-md`}
            >
              <div
                className={`flex h-12 w-12 items-center justify-center rounded-full ${
                  index === 1 ? "bg-green-100" : "bg-minor/20"
                }`}
              >
                {index === 0 && <GiReceiveMoney className="text-xl" />}
                {index === 1 && <GrUserWorker className="text-xl text-main" />}
                {index === 2 && <FaRegThumbsUp className="text-xl" />}
              </div>
              <h3 className="mt-4 text-lg font-bold text-gray-800">
                {card.title}
              </h3>
              <p className="mt-2 text-gray-600">{card.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Affordable;
