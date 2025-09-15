import Image from "next/image";
import Banner from "./Banner";
import WhyChoose from "./WhyChoose";
import HourCta from "./HourCta";
import Faq from "./Faq";
import Service from "@/app/components/Home/Service";
import Affordable from "./Affordable";
import ProcessWidget from "../Widgets/ProcessWidget";
import ReviewWidget from "../Widgets/ReviewWidget";
import Navbar from "../Navbar";
import Link from "next/link";

import contactContent from "@/app/Data/content";
import SubdomainContent from "@/app/Data/FinalContent";

const ContactInfo: any = contactContent.contactContent;
const homeData: any = contactContent.homePageContent;
const content: any = SubdomainContent.subdomainData;

const Hero = () => {
  const cityData: any = content;
  const slugs: any = Object.keys(cityData).map((key) => cityData[key]);
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: homeData.faq.map((faq: any) => ({
      "@type": "Question",
      name: faq?.FAQ?.split("[location]").join(
        ContactInfo.location.split(",")[0].trim(),
      ),
      acceptedAnswer: {
        "@type": "Answer",
        text: faq?.Answer?.split("[location]").join(
          ContactInfo.location.split(",")[0].trim(),
        ),
      },
    })),
  };
  return (
    <div className="">
      {jsonLd && (
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      )}
      <Navbar />
      <div className="w-screen overflow-hidden  md:flex md:w-full md:flex-col md:items-center md:justify-center">
        <div className="w-full overflow-hidden text-lg  print:hidden  dark:bg-white dark:text-black">
          {/* poster */}
          <Banner
            h1={homeData.h1Banner}
            image={homeData.bannerImage}
            header={homeData.bannerQuote}
            p1={`${homeData?.metaDescription
              ?.split("[location]")
              .join(ContactInfo.location)
              ?.split("[phone]")
              .join(ContactInfo.No)}`}
          />
          {/* poster */}
          {/* Section 1 */}
          <div className="my-10 grid  grid-cols-1 gap-6 px-4 md:grid-cols-2 md:px-24">
            <div className="flex flex-col justify-center    ">
              <h2 className="text-first text-3xl font-bold">{homeData.h2}</h2>
              <div
                className="mt-4  text-justify"
                dangerouslySetInnerHTML={{ __html: homeData.p2 }}
              ></div>
            </div>
            <div className="">
              <Image
                height={10000}
                width={10000}
                unoptimized={true}
                src={`${homeData.h2Image}`}
                className=" h-full w-full rounded-lg object-cover shadow-lg"
                alt={
                  homeData.h2Image.split("/").pop()?.split(".")[0] || "image"
                }
                title={
                  homeData.h2Image.split("/").pop()?.split(".")[0] || "image"
                }
              />
            </div>
          </div>
          {/* Section 1 */}
          {/* TYPES */}
          <Service />
          {/* TYPES*/}
          <Affordable />
          {/* Section 4 */}
          <WhyChoose data={homeData.whyChooseSection} />
          <ProcessWidget />
          {/* Section 4 */}
          {/* Section 1 */}
          <div className="my-10 grid  grid-cols-1 gap-6 px-4 md:grid-cols-2 md:px-24">
            <div className="">
              <Image
                height={10000}
                width={10000}
                src={`${homeData.h3Image}`}
                unoptimized={true}
                className=" h-full w-full rounded-lg object-cover shadow-lg"
                alt={
                  homeData.h3Image.split("/").pop()?.split(".")[0] || "image"
                }
                title={
                  homeData.h3Image.split("/").pop()?.split(".")[0] || "image"
                }
              />
            </div>
            <div className="flex flex-col justify-center    ">
              <h2 className="text-first text-3xl font-bold">{homeData.h3}</h2>
              <div
                className="mt-4  text-justify"
                dangerouslySetInnerHTML={{ __html: homeData.p3 }}
              ></div>
            </div>
          </div>
          {/* Section 1 */}
          {/* Area we Serve */}
          <div className="mx-auto mt-14 max-w-[95rem] md:mt-20">
            <div className="mt-10 flex rounded-xl bg-white  shadow-2xl  md:mb-10 md:h-96">
              <div className="md:w-[87%]">
                <div className="mt-4 p-1 text-center text-2xl font-bold text-main">
                  We Proudly Serve{" "}
                  <span className="text-mai">The Following Areas</span>
                </div>
                <div className="mx-6 mt-4 flex h-fit w-auto flex-wrap items-center justify-center gap-4 md:mx-10">
                  {slugs
                    .sort()
                    .slice(0, 15)
                    .map((City: any, index: number) => {
                      return (
                        <div className="" key={index}>
                          <a
                            href={`https://${City.slug}.${ContactInfo.host}`}
                            className="text-center"
                          >
                            <button
                              type="button"
                              className="mb-2 me-2 rounded-lg bg-main px-5 py-2.5 text-xs font-medium text-white hover:bg-main/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
                            >
                              {City.name}
                            </button>
                          </a>
                        </div>
                      );
                    })}
                  <Link href={`${ContactInfo.baseUrl}locations`}>
                    <button className="mb-2 me-2 rounded-lg bg-main px-5 py-2.5 text-xs font-medium text-white hover:bg-minor/90 focus:outline-none focus:ring-4 focus:ring-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:bg-gray-700 dark:focus:ring-gray-700">
                      View All
                    </button>
                  </Link>
                </div>
              </div>
              <div className="hidden h-full w-full md:flex ">
                <HourCta />
              </div>
            </div>
          </div>
          {/* Area we Serve */}
          {/* CTA */}
          <div className="mt-14 md:mt-20"></div>
          {/* CTA */}
          {/* FAQ */}
           <Faq data={homeData?.faq}/>
          {/* FAQ */}
          {/* Review */}
          <ReviewWidget />
          {/* Review */}
          {/* -----------------------------------------Map End---------------------------- */}
          <div className="block w-full  ">
            <div className=" mt-20 overflow-hidden rounded-xl border">
              <iframe
                title="Google Map"
                height="350"
                width={"100%"}
                src={homeData?.mapLink}
                loading="lazy"
              ></iframe>
            </div>
          </div>
          {/* -----------------------------------------Map End---------------------------- */}
        </div>
      </div>
    </div>
  );
};

export default Hero;
