
import React from 'react';
import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
  } from "@/components/ui/accordion";
import Link from 'next/link';
const ZipAndNeighAccordian = ({ques , ans ,slug}:any) => {
  return (
    <div className='mt-10'>
      <Accordion type="multiple"  className="md:w-2/3 ">
    
        <AccordionItem value={`item-1`} className='no-underline' >
        <AccordionTrigger className="font-bold hover:no-underline text-center text-2xl text-main">
           {ques}
        </AccordionTrigger>
        <AccordionContent className=''>
        <div className="mx-10 mt-4 flex h-fit w-auto flex-wrap justify-center gap-4">
            {ans.map((item: any) => (
              <div className="" key={item}>
                <Link
                  target="_blank"
                  href={`https://www.google.com/maps/search/?api=1&query=${item}, ${slug},`}
                >
                  <p className="border bg-minor px-2 py-1 text-white duration-100 ease-in-out hover:text-main">
                    {item}
                  </p>
                </Link>
              </div>
            ))}
          </div>
        </AccordionContent>
      </AccordionItem>
   
      
    </Accordion></div>
  )
}

export default ZipAndNeighAccordian