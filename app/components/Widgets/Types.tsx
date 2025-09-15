import Image from "next/image";
import React from "react";
import data1 from "@/components/Content/servicePage.json";

const Types = () => {
  const data = data1.serviceData;
  return (
    <div className="mt-16 px-4 md:px-24">
      <h2 className="text-center text-3xl font-extrabold text-main">
        {data.title}
      </h2>
      <p className="mt-4 text-center text-lg">{data.p}</p>

      <div className=" my-16 hidden  grid-cols-1 content-center  justify-center gap-10 sm:grid-cols-2 lg:grid lg:grid-cols-4 ">
        {data.lists?.map((items: any, index: number) => (
          <div key={index} className=" flex items-center justify-center">
            <div className="group h-80 w-80 [perspective:1000px] ">
              <div className="relative h-full w-full rounded-xl shadow-xl transition-all duration-700 [transform-style:preserve-3d] group-hover:[transform:rotateY(180deg)] ">
                <div className="absolute inset-0 overflow-hidden rounded-xl [backface-visibility:hidden]">
                  <div className="absolute  bottom-0 left-0 right-0 top-0 flex items-center justify-center bg-black/60 p-4 text-center text-3xl font-bold text-white  ">
                    {items.title}
                  </div>
                  <Image
                    height={1000}
                    width={1000}
                    className="h-full w-full rounded-xl object-cover shadow-xl shadow-black/40"
                    src={`/${items.imageUrl}`}
                    alt={items.title}
                    loading="lazy"
                  />
                </div>
                <div className="absolute inset-0 h-full w-full overflow-hidden  rounded-xl bg-main text-center text-slate-200 [backface-visibility:hidden] [transform:rotateY(180deg)]">
                  {/* <Image
                    height={1000}
                    width={1000}
                    className="absolute bottom-0 left-0 right-0 top-0 h-full  w-full rounded-xl object-cover shadow-xl shadow-black/40 [transform:rotateY(180deg)]"
                    src={`/${items.imageUrl}`}
                    alt={items.title}
                    loading="lazy"
                  /> */}
                  <div className="relative flex min-h-full flex-col items-center justify-center ">
                    <div className="mt-3 px-4 text-lg">{items.description}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="block px-4 py-5 lg:hidden">
        {data.lists?.map((item: any) => (
          <div
            className=" rounded-2xl border   p-3 shadow-xl"
            key={item?.title}
          >
            <div className="flex items-center justify-start gap-4">
              <div className="h-14 w-14 overflow-hidden rounded-full object-cover">
                <Image
                  aria-hidden="true"
                  src={`/${item.imageUrl}`}
                  alt={`${item.imageUrl.split(".")}`}
                  title={`${item.imageUrl.split(".")}`}
                  width="900"
                  height="550"
                  className="h-14 w-14 object-cover "
                />
              </div>
              <h3 className="w-[75%]  text-lg font-bold text-main">
                {item.title}{" "}
              </h3>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Types;
