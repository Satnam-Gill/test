import Image from "next/image";
import React from "react";

const ProcessWidgetComponent = ({data}: any) => {
  return (
    <div className="mt-20">
      <h2 className="text-center text-3xl font-bold ">
        {data.title}
      </h2>
      <div className="mt-10 grid grid-cols-1 gap-5 px-10 sm:grid-cols-2 md:px-20 lg:grid-cols-4">
        <div className="rounded-md  p-4 shadow-xl duration-150 ease-in-out group md:hover:bg-main md:hover:text-white flex flex-col justify-center">
          <div className=" flex justify-around items-center w-full">
            <Image
              src="/inspection.png"
              className="group-hover:invert rounded-lg w-16"
              alt="Initial Inspection"
              width={1000}
              height={500}
            />
          <h3 className=" text-xl  text-main group-hover:text-white font-bold ease-in-out duration-150" >{data.processData[0].title}</h3>
          </div>
          <div className="mt-6 text-center">
          {data.processData[0].description}
          </div>
        </div>
        <div className="rounded-md  p-4 shadow-xl duration-150 ease-in-out group md:hover:bg-main md:hover:text-white flex flex-col justify-center">
          <div className=" flex justify-around items-center w-full">
            <Image
              src="/project.png"
              className="group-hover:invert rounded-lg w-16"
              alt="Final Testing"
              width={1000}
              height={500}
            />
          <h3 className=" text-xl  text-main group-hover:text-white font-bold ease-in-out duration-150" >{data.processData[1].title}</h3>
          </div>
          <div className="mt-6 text-center">
          {data.processData[1].description}
          </div>
        </div>
        <div className="rounded-md  p-4 shadow-xl duration-150 ease-in-out group md:hover:bg-main md:hover:text-white flex flex-col justify-center">
          <div className=" flex justify-around items-center w-full">
            <Image
              src="/sanitizer.png"
              className="group-hover:invert rounded-lg w-16"
              alt="Advanced Sanitization"
              width={1000}
              height={500}
            />
          <h3 className=" text-xl  text-main group-hover:text-white font-bold ease-in-out duration-150" >{data.processData[2].title}</h3>
          </div>
          <div className="mt-6 text-center">
          {data.processData[2].description}
          </div>
        </div>
        <div className="rounded-md  p-4 shadow-xl duration-150 ease-in-out group md:hover:bg-main md:hover:text-white flex flex-col justify-center">
          <div className=" flex justify-around items-center w-full">
            <Image
              src="/evaluation.png"
              className="group-hover:invert rounded-lg w-16"
              alt="Comprehensive Vent Assessment"
              width={1000}
              height={500}
            />
          <h3 className=" text-xl  text-main group-hover:text-white font-bold ease-in-out duration-150" >{data.processData[3].title}</h3>
          </div>
          <div className="mt-6 text-center">
          {data.processData[3].description}
          </div>
        </div>
    
        {/* <div className="group rounded-md border p-4 shadow-xl duration-150 ease-in-out md:hover:bg-main md:hover:text-white">
          <div className="w-20">
            <Image
              src="/project.png"
              className="w-full rounded-lg"
              alt="Final Testing"
              width={1000}
              height={500}
            />
          </div>
          <h3 className="mt-6 text-xl  font-bold">{data.processData[1].title}</h3>
          <div className="mt-6 ">
            {" "}
            {data.processData[1].description}
          </div>
        </div> */}
        {/* <div className="rounded-md border p-4 shadow-xl duration-150 ease-in-out md:hover:bg-main md:hover:text-white">
          <div className="w-20">
            <Image
              src="/sanitizer.png"
              className="w-full rounded-lg"
              alt="Advanced Sanitization"
              width={1000}
              height={500}
            />
          </div>
          <h3 className="mt-6 text-xl  font-bold">{data.processData[2].title}</h3>
          <div className="mt-6 ">
          {data.processData[2].description}
          </div>
        </div> */}
        {/* <div className="rounded-md border p-4 shadow-xl duration-150 ease-in-out md:hover:bg-main md:hover:text-white">
          <div className="w-20">
            <Image
              src="/evaluation.png"
              className="w-full rounded-lg"
              alt="Comprehensive Vent Assessment"
              width={1000}
              height={500}
            />
          </div>
          <h3 className="mt-6 text-xl  font-bold">
          {data.processData[3].title}
          </h3>
          <div className="mt-6 ">
          {data.processData[3].description}
          </div>
        </div> */}
      </div>
    </div>
  );
};

export default ProcessWidgetComponent;
