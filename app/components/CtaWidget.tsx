import Link from 'next/link'
import React from 'react'
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

import { FiPhoneCall } from "react-icons/fi";

const CtaWidget = () => {
  return (
      <div className="mt-28  flex flex-col items-center justify-center bg-main p-6 px-6 text-center text-white md:px-24">
      <p className="text-4xl font-bold ">Do You Need A Roofer? </p>
      <p className="text-[20px] mt-1"> Get the Free Quotes!
      </p>
      <div className="mt-10 md:mt-0">
            <a id='cta-id' href={`tel:${ContactInfo.tel}`}>
            <button className="rounded-full mt-2 font-semibold px-5 py-1 text-3xl duration-100 ease-in-out hover:translate-y-2 flex gap-2">
            <FiPhoneCall className='mt-1'/> {ContactInfo.No}
            </button>
            </a>
          </div>
      
    </div>
  )
}

export default CtaWidget