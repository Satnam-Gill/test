import React from "react";
import contactContent from "@/app/Data/content";

const home: any = contactContent.homePageContent;

const ProcessWidget = () => {
  const content = home?.processWidget;

  return (
    <div className="mx-auto mt-20 max-w-7xl px-6 md:px-20">
      <h2 className="text-center text-4xl font-extrabold text-main">
        {content.title}
      </h2>
      <p className="mx-auto mt-4 max-w-3xl  text-center text-lg">
        {content.description}
      </p>

      <div className="relative mt-20">
        {/* Vertical Line */}
        <div className="absolute left-1/2 top-0 z-0 hidden h-full w-1 -translate-x-1/2 bg-gray-300 md:block" />

        <div className="space-y-16">
          {content.steps.map((step:any, index:number) => {
            const isLeft = index % 2 === 0;
            return (
              <div
                key={index}
                className={`relative flex flex-col items-center md:flex-row md:items-start ${
                  isLeft ? "md:justify-start" : "md:justify-end"
                }`}
              >
                <div
                  className={`z-10 md:w-1/2 ${
                    isLeft ? "md:pr-8 md:text-right" : "md:pl-8 md:text-left"
                  } text-left`}
                >
                  <div className="rounded-xl border border-gray-100 bg-white p-6 shadow-xl">
                    <h3 className="text-xl font-semibold text-main">
                      {step.title}
                    </h3>
                    <p className="mt-3  text-sm md:text-base">
                      {step.description}
                    </p>
                  </div>
                </div>
                {/* Timeline Dot */}
                <div className="absolute left-1/2 top-6 z-20 hidden h-6 w-6 -translate-x-1/2 items-center justify-center rounded-full bg-main font-bold text-white shadow-md md:flex">
                  {index + 1}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ProcessWidget;
