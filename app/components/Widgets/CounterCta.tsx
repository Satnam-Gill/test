import React from "react";
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

import Image from "next/image";

const CounterCta = () => {
  return (
    // <div className="mt-20 bg-main text-white">
    //   <div className="item-center flex flex-col justify-around border px-10 py-10 md:flex-row md:py-20">
    //     <div className="md:w-[45%]">
    //       <div className="w-fit rounded-full border border-white p-1 px-2 text-sm  font-semibold text-minor">
    //         NUMBER TALKS
    //       </div>
    //       <div className="mt-2 text-5xl">
    //       Unparalleled <span className="text-minor">Furnace</span> Services for All Your Heating Needs
    //       </div>
    //       <div className="mt-2">
    //       Whether you&apos;re seeking expert furnace installation, prompt repairs, or routine maintenance for your premises, Paramount Plumber delivers exceptional solutions that keep you warm and worry-free. Experience the ultimate comfort with our dedicated and skilled team of Plumbers!
    //       </div>
    //       <div className="mt-4 hidden gap-4 md:flex">
    //         <a href={`tel:${ContactInfo.tel}`}>
    //           <p className="flex  h-14 w-14 items-center justify-center rounded-full bg-minor text-2xl duration-150 ease-in-out hover:scale-[1.2]">
    //             <IoCallSharp />
    //           </p>
    //         </a>
    //         <div className="flex flex-col text-lg ">
    //           <div className="">Need Help?</div>
    //           <div className=" font-bold">
    //             <a href={`tel:${ContactInfo.tel}`}>{ContactInfo.No}</a>
    //           </div>
    //         </div>
    //       </div>
    //     </div>
    //     <div className="mdjustify-center mt-4 grid  grid-cols-2 gap-4 md:mt-0 md:w-[40%]">
    //       <div className="flex flex-col items-center justify-center rounded-2xl border p-4 px-4 md:w-60 md:p-0 ">
    //         <div className="flex flex-col items-center  justify-between gap-4  font-bold md:flex-row ">
    //           <FaBuildingCircleCheck className="text-6xl text-minor" />
    //           <CouterUpWithK end={40} />
    //         </div>
    //         <div className="mt-2 text-center">Our Project Complete</div>
    //       </div>
    //       <div className="flex flex-col items-center justify-center rounded-2xl border p-4 px-4 md:w-60 md:p-0 ">
    //         <div className="flex flex-col items-center  justify-between gap-4  font-bold md:flex-row ">
    //           <RiTeamFill className="text-6xl text-minor" />
    //           <CouterUpWithK end={3} />
    //         </div>
    //         <div className="mt-2 text-center">Our Tæm Member</div>
    //       </div>
    //       <div className="flex flex-col items-center justify-center rounded-2xl border p-4 px-4 md:w-60 md:p-0 ">
    //         <div className="flex flex-col items-center  justify-between gap-4  font-bold md:flex-row ">
    //           <VscPreview className="text-6xl text-minor" />
    //           <CouterUpWithK end={11} />
    //         </div>
    //         <div className="mt-2 text-center">Clients Reviews</div>
    //       </div>
    //       <div className="flex flex-col items-center justify-center rounded-2xl border p-4 px-4 md:w-60 md:p-0 ">
    //         <div className="flex flex-col items-center  justify-between gap-4  font-bold md:flex-row ">
    //           <FaAward className="text-6xl text-minor" />
    //           <CouterUpWithK end={1} />
    //         </div>
    //         <div className="mt-2 text-center">Our Winning Award</div>
    //       </div>
    //     </div>
    //     <div className="mt-10 flex gap-4 md:hidden">
    //       <a href={`tel:${ContactInfo.tel}`}>
    //         <p className="flex  h-14 w-14 items-center justify-center rounded-full bg-minor text-2xl duration-150 ease-in-out hover:scale-[1.2]">
    //           <IoCallSharp />
    //         </p>
    //       </a>
    //       <div className="flex flex-col text-lg ">
    //         <div className="">Need Help?</div>
    //         <div className=" font-bold">
    //           <a href={`tel:${ContactInfo.tel}`}>{ContactInfo.No}</a>
    //         </div>
    //       </div>
    //     </div>
    //   </div>
    // </div>
    <div className="relative  mt-20 text-white">
      <div className=""></div>
      <div className="item-center relative z-20 flex flex-col items-center justify-around bg-black/70 px-4 py-10 md:flex-row md:px-10 md:py-10">
        <div className="relative mx-auto max-w-4xl text-center ">
          {/* <div className="w-fit rounded-full border border-white p-1 px-2 text-sm  font-semibold text-minor">
      NUMBER TALKS
    </div> */}
          <div className="mt-2 text-4xl">
            Unparalleled <span className="text-minor">Furnace</span> Services
            for All Your Heating Needs
          </div>
          <div className="mt-2">
            Whether you&apos;re seeking expert furnace installation, prompt
            repairs, or routine maintenance for your premises, Paramount Plumber
            delivers exceptional solutions that keep you warm and worry-free.
            Experience the ultimate comfort with our dedicated and skilled team
            of Plumbers!
          </div>
          <div className="mt-4  flex justify-center gap-4 ">
            <div
              id="cta-id"
              className="flex flex-col rounded-md  border bg-white px-4 py-2 text-lg"
            >
              <div id="cta-id" className=" font-bold text-main">
                <a id="cta-id" href={`tel:${ContactInfo.tel}`}>
                  {ContactInfo.No}
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div className="absolute bottom-0 left-0 right-0  top-0 ">
        <Image
          height={1000}
          width={1000}
          className="h-full w-full object-cover object-center "
          src="/medium home.jpeg"
          alt="counter-cta"
        />
      </div>
    </div>
  );
};

export default CounterCta;
