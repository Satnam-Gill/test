import Image from "next/image";
import React from "react";
import { MdDoubleArrow } from "react-icons/md";

const Service = () => {
  const text = `text-[#f76610]`;
  const btn = `bg-[#f76610] hover:bg-[#c25210]`;
  const items = [
    {
      title: "Extensive Experience ",
      imageUrl: "/completed-concept-illustration.jpg",
      alt: "Extensive Experience ",
      description: `With over 15 years in the industry, our adept team has successfully cleaned over 10,000 dryer vents across Texas, ensuring protection and performance on your premises`,
    },
    {
      title: "High Customer Satisfaction",
      imageUrl: "/flat-feedback-concept.jpg",
      alt: "High Customer Satisfaction",
      description:
        "We boast a 98% customer satisfaction rate, reflecting our dedication to imparting incredible service and meeting the particular desires of each potential customer.",
    },
    {
      title: "Advanced Technology Usage",
      imageUrl: "/Advance_Technology.jpg",
      alt: "Advanced Technology Usage",
      description:
        "Utilizing a contemporary system, we've increased the efficiency of our cleansing procedure by using 40%, ensuring thorough and effective professional dryer vent cleanings every time.",
    },
    {
      title: "Safety Record",
      imageUrl: "/online-service-platform-vector-occupational-safety.jpg",
      alt: "Safety Record",
      description:
        "Our dedication to protection has significantly reduced fire hazards, with a 99.5% success rate in eliminating dryer-related fire risks in the properties we service.",
    },
    {
      title: "Rapid Response Time",
      imageUrl: "/landing-page-with-time-management-concept.jpg",
      alt: "Rapid Response Time",
      description:
        "We understand the urgency of dryer vent troubles, so our response time is 50% quicker than the industry average, ensuring quick and reliable service.",
    },
    {
      title: "Eco-Friendly Practices",
      imageUrl: "/organic-flat-csr-concept-illustrated.jpg",
      alt: "Eco-Friendly Practices",
      description:
        "Our eco-friendly cleansing solutions have reduced harmful chemical usage by 60%, aligning with our commitment to sustainability and environmental responsibility.",
    },
  ];
  return (
    <div className="mb-10 mt-16 px-4 md:px-6 xl:px-20">
      <div className={`text-lg`}>Why Choose</div>
      <h2 className="text-3xl font-bold">
        Our <span className={`${text} `}>Star Dryer Vent Cleaning?</span>
      </h2>
      <div className="mt-8 grid grid-cols-1 gap-6 border-t-2 px-4  text-center text-lg sm:grid-cols-2 md:grid-cols-3 md:px-24 ">
        {items.map((items, index) => (
          <div
            className=" 1 mt-10 overflow-hidden rounded-t-2xl border duration-300 ease-in  hover:-translate-y-4    md:rounded-none md:rounded-tl-2xl "
            key={index}
          >
            <div className="flex h-60 justify-center ">
              <Image
                aria-hidden="true"
                src={items.imageUrl}
                alt=""
                title=""
                width="900"
                height="550"
                className="object-cover"
              />
            </div>
            <h3
              className={`1 mt-4 px-4 text-xl font-bold  ${text}  flex justify-center gap-2 `}
            >
              <MdDoubleArrow className="text-bold text-3xl" />
              {items.title}
            </h3>
            <p className=" p-4 text-justify text-base">{items.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Service;
