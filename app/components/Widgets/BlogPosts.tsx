"use client";
import Image from "next/image";
import React, { useLayoutEffect } from "react";
import DateComponent from "@/app/components/Widgets/DateComponent";
import Link from "next/link";

function groupAndSortBycatagory(data: any) {
  const groupedData = data.reduce((acc: any, item: any) => {
    const catagory = item.catagory;
    if (!acc[catagory]) {
      acc[catagory] = [];
    }
    acc[catagory].push(item);
    return acc;
  }, {});

  const sortedcatagorys = Object.keys(groupedData).sort();

  const sortedOutput = sortedcatagorys.reduce((acc: any, catagory) => {
    acc[catagory] = groupedData[catagory];
    return acc;
  }, {});

  return sortedOutput;
}

const BlogPosts = ({ postData, catagorys }: any) => {

  const sortedDataBycatagory = groupAndSortBycatagory(postData);
  const reversedData = postData[postData.length - 1];
  // if (sortedDataBycatagory.roofing) {
  //   sortedDataBycatagory.roofing = [...sortedDataBycatagory.roofing, ...PushedData];
  // } else {
  //   sortedDataBycatagory.roofing = PushedData;
  // }

  postData.forEach((blog: any) => {
    // Push to its main category
    // if (sortedDataBycatagory[blog.catagory]) {
    //   sortedDataBycatagory[blog.catagory].push(blog);
    // } else {
    //   sortedDataBycatagory[blog.catagory] = [blog];
    // }

    // Check and push to other categories
    if (blog.otherCategory && Array.isArray(blog.otherCategory)) {
      blog.otherCategory.forEach((otherCat: string) => {
        if (sortedDataBycatagory[otherCat]) {
          sortedDataBycatagory[otherCat].push(blog);
        } else {
          sortedDataBycatagory[otherCat] = [blog];
        }
      });
    }
  });
  // console.log(reversedData[0]);
  return (
    <div className="relative px-4 py-10  md:px-14">
      <h1 className="heading flex items-center gap-4 text-3xl text-minor ">
        BLOGS
        <span className=" hidden  h-0.5 w-20 justify-center bg-main md:flex"></span>
      </h1>
      {/* Para */}
      <p className="heading my-6 text-sm lg:w-1/3">Explore the latest Blogs</p>
      {/* Para */}
      {/* Latest News */}
      <div className="Latest over  relative md:h-80 overflow-hidden rounded-lg   border-main mx-2 lg:flex lg:border-2">
        <div className=" h-fit  rounded-lg  lg:w-fit xl:w-[130%]">
          <Image
            src={`${reversedData.postImage.src}`}
            alt={reversedData.h1}
            width={10000}
            height={10000}
            className="h-fit object-cover "
            loading="lazy"
          />
        </div>
        <div className="container2 h-fit p-6  text-black md:pr-12 lg:w-[80%]">
          <h4 className="mt-2 w-fit text-center text-xl md:text-left">
            {reversedData.h1}
          </h4>
          <div className="mt-4 flex justify-between text-sm">
            <div className="font-semibold">{reversedData?.type}</div>
            <div className="">
              <DateComponent publishedAt={reversedData?.publishedAt} />
            </div>
          </div>
          <div className="mt-4 w-fit text-sm">
            {`${reversedData?.description}...`}
          </div>
          <div className="flex justify-center lg:justify-start">
          <Link
                href={`/blogs/${reversedData?.catagory.toLowerCase().split(" ").join("-")}/${reversedData?.slug}`}
              >
            <div className="mt-2  w-fit rounded-md bg-main px-4 py-2 text-base font-medium  text-white transition duration-150 ease-in-out hover:bg-minor hover:text-black">
              
                <button>Read More</button>
            </div>
              </Link>
          </div>
        </div>
      </div>
      {/* Latest News */}
      <div className="">
        {catagorys.map((catagory: any, index: number) => (
          <div className="mt-10 px-2" key={index + 1}>
            <div className="flex items-center justify-between text-3xl uppercase ">
              <Link href={`/blogs/${catagory.toLowerCase().split(" ").join("-")}`} className="hover:text-main ease-linear duration-150 transition-colors">
              {sortedDataBycatagory[catagory][0]?.categoryName}
              </Link>
              <Link
                  href={`/blogs/${catagory.toLowerCase().split(" ").join("-")}`}
                >
              <div className=" w-fit rounded-md bg-main px-4 py-2 text-base font-medium  text-white transition duration-150 ease-in-out hover:bg-minor hover:text-black">
                
                  <button>View All</button>
               
                {/* <Knowmore
                              link={`/dubai-communities/${item.location.toLowerCase().split(" ").join("-")}/${item.slug.current}`}
                            /> */}
              </div>
              </Link>
            </div>
            <div className="mt-4">
              {/* Cards */}
              <div className="Card my-10 grid gap-16  md:grid-cols-2 lg:grid-cols-3 ">
                {sortedDataBycatagory[catagory]
                  .reverse()
                  .slice(0, 3)
                  .map((item: any, index: number) => {
                    return (
                      <div
                        className="relative rounded-lg border text-black duration-300 ease-in-out md:w-11/12"
                        key={index}
                      >
                        <div className="overflow-hidden rounded-lg lg:w-fit">
                          <Image
                            src={`${item.postImage.src}`}
                            alt={item.h1}
                            width={10000}
                            height={10000}
                            className="h-60 object-cover"
                            loading="lazy"
                          />
                        </div>
                        <div className="container2 p-4  md:pr-12">
                          <div className="ml-2 flex items-center justify-center lg:block lg:w-fit">
                            {/* <Image
                        src={urlForImage(item.newsImage)}
                        alt="News Image"
                        width={150}
                        height={0}
                        className="-ml-2"
                        loading="lazy"
                      /> */}
                          </div>
                          <h2 className="mt-2 w-fit text-center text-xl md:text-left ">
                          <Link
                          href={`/blogs/${item?.catagory.toLowerCase().split(" ").join("-")}/${item.slug}`}
                        >{item.h1.toUpperCase()}</Link>
                          </h2>
                          <div className="mt-4 flex justify-between text-sm">
                          <div className=" font-semibold text-main underline-offset-8 duration-300 ease-in-out  hover:underline hover:underline-offset-2">
                        <Link
                          href={`/blogs/${item?.catagory.toLowerCase().split(" ").join("-")}/${item.slug}`}
                        >
                          Read More
                        </Link>
                      </div>
                            <div className="">
                              <DateComponent publishedAt={item.publishedAt} />
                            </div>
                          </div>
                          <div className="mt-4 w-fit text-sm">{`${item.description}...`}</div>
                        
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        ))}
        {/* Cards */}
      </div>
    </div>
  );
};

export default BlogPosts;
