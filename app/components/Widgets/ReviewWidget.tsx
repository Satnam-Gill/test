"use client";
import { useEffect, useState } from "react";
import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import Image from "next/image";

import contactContent from "@/app/Data/content";
import subdomainContent from "@/app/Data/FinalContent";


const ContactInfo: any = contactContent.contactContent;
const home: any = contactContent.homePageContent;
const content: any = subdomainContent.subdomainData;


interface Review {
  id: number;
  name: string;
  content: string;
}

interface ReviewWidgetProps {
  value?: string;
}

const ReviewWidget: React.FC<ReviewWidgetProps> = ({ value = "" }) => {
  const Testimonials = home?.reviews ;
  const [shuffledTestimonials, setShuffledTestimonials] = useState(Testimonials);

  useEffect(() => {
    // Shuffle testimonials on the client side after the component mounts
    setShuffledTestimonials([...Testimonials].sort(() => 0.5 - Math.random()));
  }, [Testimonials]);

  const contentData: { name: string } = content[value as keyof typeof content];
  const abbrevation = value?.split("-").pop()?.toUpperCase();
  const StateName = contentData?.name
    ? abbrevation
      ? `${contentData.name}, ${abbrevation}`
      : contentData.name
    : ContactInfo.location.split(",")[0].trim();

  const settings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 3,
    slidesToScroll: 1,
    arrow: true,
    autoplay: true,
    autoplaySpeed: 2000,
    cssEase: "linear",
    responsive: [
      {
        breakpoint: 1024,
        settings: {
          slidesToShow: 3,
          slidesToScroll: 3,
          infinite: true,
          dots: true,
        },
      },
      {
        breakpoint: 800,
        settings: {
          slidesToShow: 2,
          slidesToScroll: 2,
          initialSlide: 2,
        },
      },
      {
        breakpoint: 520,
        settings: {
          slidesToShow: 1,
          slidesToScroll: 1,
        },
      },
    ],
  };

  return (
    <div className="relative pb-10">
      <h2 className="text-first mb-10 mt-20 text-center text-3xl font-bold text-main">
        Testimonials
      </h2>
      <Slider {...settings}>
        {shuffledTestimonials.slice(0, 6).map((item: any, index: number) => (
          <div
            className="relative mb-10 p-5 lg:h-80 lg:bg-main lg:text-white"
            key={index} // Use a unique identifier for the key
          >
            <div className="flex items-center justify-center">
              <Image
                src="https://ik.imagekit.io/h7rza8886p/5Star.webp?updatedAt=1746874235628"
                alt="review"
                width={1000}
                height={500}
                className="w-40"
              />
            </div>
            <div className="mt-4">
              {item.Review.split("[location]").join(StateName)}
            </div>
          </div>
        ))}
      </Slider>
    </div>
  );
};

export default ReviewWidget;
