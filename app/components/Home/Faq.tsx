"use client";
import React from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import contactContent from "@/app/Data/content";
import SubdomainContent from "@/app/Data/FinalContent";

const ContactInfo: any = contactContent.contactContent;

const Faq = ({ data = [], value }: { data?: any, value?:string }) => {
  return (
    <div className="mt-14 md:mt-20">
      <h2 className="text-center text-3xl font-bold text-main">
        FAQs about {ContactInfo.service} in {value || ContactInfo.location}
      </h2>
      <div className="mt-5 flex flex-col items-center justify-center px-6">
        <Accordion type="multiple" defaultValue={["item-0"]} className="md:w-2/3">
          {data.map((item: any, index: number) => {
            // Handle both formats: { ques, ans } and { FAQ, Answer }
            const question = item.FAQ || item.ques || "";
            const answer = item.Answer || item.ans || "";

            return (
              <AccordionItem
                value={`item-${index + 1}`}
                className="no-underline"
                key={index}
              >
                <AccordionTrigger className="font-semibold hover:no-underline">
                  Q: {question}
                </AccordionTrigger>
                <AccordionContent className="text-base">
                  <span>A: {answer}</span>
                </AccordionContent>
              </AccordionItem>
            );
          })}
        </Accordion>
      </div>
    </div>
  );
};

export default Faq;
