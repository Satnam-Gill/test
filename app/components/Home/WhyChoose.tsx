import Image from 'next/image'
import React from 'react'

const WhyChoose = ({data}:any) => {
    const items = data.whyChooseData
  return (
    <div className="mt-20 ">
    <h2 className="text-center text-3xl font-extrabold">
      Why Choose{" "}
      <span className="text-main">{data.title}</span>
    </h2>
    {/* -----------------------------------------card Start------------------------ */}
    <div className=" md:px-24 px-4 mt-16 grid grid-cols-1   sm:grid-cols-2 md:grid-cols-3 gap-10 text-center text-lg ">
    {items.map((items:any, index:number) => (
      <div className=" 1 border rounded-md px-4 py-4 hover:-translate-y-4 shadow-md   ease-in duration-300 " key={index}>
        <div className="flex justify-center">
          {/* <Image
            aria-hidden="true"
            src={`/${items.imageUrl}`}
            alt={items?.imageUrl.split(".")[0]}
            title={items?.imageUrl.split(".")[0]}
            loading="lazy"
            width={100}
            height={100}
            className=" w-[100px] h-35"
          /> */}
        </div>
        <h3 className="1 text-xl mt-2 font-bold  text-main">
          {items?.title}
        </h3>
        <p className="mt-4">
          {items?.description}
        </p>
      </div>
    ))}
    </div>
    {/* -----------------------------------------card End------------------------ */}
  </div>
  )
}

export default WhyChoose