import React from "react";
import { RiGlobalLine } from "react-icons/ri";

const StateCards = ({state}: {state: string}) => {
  return (
    <div>
      <div className="my-10 px-10  2xl:px-80 text-center">
        <h2 className="text-3xl font-bold">
          Why You Should Hire A Professional in {state}?
        </h2>
        <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-8 "> 
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" text-xl font-bold ">
              Local Professionals & Global Standards:
            </div>
            Our adept professionals deliver services that meet global quality
            standards tailored to local needs.
          </div>
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" mb-2 text-xl font-bold">
              Work with Skilled Experts :
            </div>
            Our certified technicians bring years of experience and expertise to
            every job.
          </div>
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" text-xl font-bold ">
              Instant, No-Obligation Estimates:
            </div>
            Get a quick and transparent quote for your specific needs with no
            hidden fees.
          </div>
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" mb-2 text-xl font-bold ">Customize Solutions:</div>
            We listen to your needs and customize our services to provide the
            most value.
          </div>
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" mb-2 text-xl font-bold ">100% Guaranteed:</div>
            With our comprehensive service, you can rest easy knowing your home
            is safer and more efficient.
          </div>
          <div className="w-60 rounded-xl  p-5 shadow-xl">
            <div className=" text-xl font-bold ">24/7 Availability:</div>
            We understand that dryer vent issues can arise anytime, so we offer
            round-the-clock service for your convenience.
          </div>
        </div>
      </div>
    </div>
  );
};

export default StateCards;
