"use client";
import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import Image from "next/image";

interface Review {
  id: number;
  name: string;
  content: string;
}

interface ReviewSliderProps {
  data: Review[];
}
const ReviewSlider: React.FC<ReviewSliderProps> = ({data}:any) => {
// console.log(data)

  const testimonials = [
    {
      "id": 1,
      "name": "Michael Peterson",
      "content":
        "We had our old furnace replaced, and the experience was outstanding. The team walked us through the process, answered all our questions, and made sure everything was working perfectly. Our home has never felt more comfortable, and we’ve noticed a nice drop in our energy bills."
    },
    {
      "id": 2,
      "name": "Samantha Russo",
      "content":
        "Our air conditioner broke down in the middle of a heatwave, and they came out right away. The technician was professional, quick, and had everything fixed in no time. We were impressed by the service and grateful for how fast they got things up and running again."
    },
    {
      "id": 3,
      "name": "David Linwood",
      "content":
        "Upgrading to a more energy-efficient HVAC system felt overwhelming at first, but the installers made it a breeze. They helped us choose the best option for our needs and handled the installation smoothly. The difference in our home’s comfort level—and on our utility bills—is incredible."
    },
    {
      "id": 4,
      "name": "Jessica Marquez",
      "content":
        "We kept having issues with our heating system randomly shutting off. Their technician arrived on time, found the problem right away, and didn’t just fix it—he explained what was wrong and how to prevent it in the future. It was an honest and efficient service."
    },
    {
      "id": 5,
      "name": "Robert Fletcher",
      "content":
        "When our AC unit started leaking, we didn’t know what to do. Thankfully, Simpson Salute HVAC responded immediately, even on a weekend. The technician was friendly, efficient, and explained what had gone wrong. We’re grateful for the peace of mind they provided."
    },
    {
      "id": 6,
      "name": "Emily Sanders",
      "content":
        "Our furnace was making loud, unsettling noises, and I was worried it would stop working. The technician diagnosed the issue right away and made the necessary repairs. Now everything runs smoothly and quietly. The service was fast, professional, and left me feeling reassured."
    },
    {
      "id": 7,
      "name": "Christopher Nolan",
      "content":
        "From scheduling to service, Simpson Salute HVAC exceeded my expectations. They did a full HVAC tune-up, and I could tell they took their time to get it right. My system runs smoother than ever, and I’ve already noticed improved air quality in my home."
    },
    {
      "id": 8,
      "name": "Alexandra Bennett",
      "content":
        "Our office building had heating problems during a busy work week, and we needed a quick solution. The repair team was fantastic—efficient, respectful of our work environment, and had everything running again with minimal interruption. We couldn’t have asked for a better experience."
    }
  ]
 
  const settings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 3,
    slidesToScroll: 1,
    arrow:true,
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
          dots: true
        }
      },
      {
        breakpoint: 800,
        settings: {
          slidesToShow: 2,
          slidesToScroll: 2,
          initialSlide: 2
        }
      },
      {
        breakpoint: 520,
        settings: {
          slidesToShow: 1,
          slidesToScroll: 1
        }
      }
    ]
  };
  return (
    <div className="pb-10  relative">
      <h2 className="text-first text-3xl font-bold text-center text-main mt-20 mb-10">Testimonials</h2>
    <Slider {...settings} >
      {
        testimonials.map((item:any ,index:number) => (
          
          <div className="p-5 lg:h-80 mb-10  lg:bg-main lg:text-white relative" key={index+1}>
            <div className="flex justify-center items-center"><Image src="/5Star.png" alt="review" width={1000} height={500} className="w-40 "/></div>
            
            <h3 className="text-xl font-semibold mt-4  text-center">{item.name}</h3>
            <p className="mt-4 ">{item.content}</p>
          </div>
        ))
      }
      
    </Slider>
    </div>
  );
}

export default ReviewSlider;

