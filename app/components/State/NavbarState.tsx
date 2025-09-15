"use client";
import Image from "next/image";
import Link from "next/link";
import React, { useState } from "react";
import { FaPhoneVolume } from "react-icons/fa";
import { AiOutlineClose, AiOutlineMenu } from "react-icons/ai";
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

const NavbarState = () => {
  const [nav, setNav] = useState(false);
  const handleNav = () => {
    setNav(!nav);
  };
  return (
    <>
      <nav className="sticky top-0 z-[999] flex h-[5rem]  w-screen items-center justify-center border-y-2 bg-gray-50 px-4 md:w-full md:px-0">
        <div className=" relative w-screen md:w-full md:max-w-[1280px] md:px-10  md:py-4">
          <div className="mt-0 flex flex-row justify-between space-x-8 rounded-2xl rounded-tr-none px-4 text-sm font-medium md:mr-6 md:justify-around">
            <div className="flex ">
              <Link href={ContactInfo?.baseUrl} aria-label="Home">
                <Image
                  src={ContactInfo?.logoImage}
                  className="h-full w-40 object-contain md:mr-3 md:w-56"
                  alt="logo of the company"
                  title=""
                  loading="lazy"
                  width={1000}
                  height={1000}
                />
              </Link>
            </div>
            <ul className=" mr-6 mt-0 hidden   flex-row items-center justify-around space-x-8 text-lg font-medium md:flex ">
              {["Home", "Services", "About", "Contact"].map((item) => (
                <li key={item}>
                  <Link
                    href={
                      item.toLowerCase() === "home"
                        ? `/`
                        : `/${item.toLowerCase().split(" ").join("-")}`
                    }
                    className="under  text-gray-900 decoration-minor decoration-2  duration-150 ease-in-out hover:underline "
                    aria-current="page"
                  >
                    {item}
                  </Link>
                </li>
              ))}
            </ul>
            <div className="  hidden items-center justify-center lg:flex   ">
              <a id="cta-id" href={`tel:${ContactInfo.tel}`}>
                <button
                  id="cta-id"
                  className="flex items-center justify-center rounded bg-main px-2 py-2 text-sm font-bold text-white   duration-200 ease-in-out hover:border-2 hover:border-main hover:bg-white hover:text-black md:px-4"
                >
                  <FaPhoneVolume className="text-3xl " />
                  {ContactInfo.No}
                </button>
              </a>
            </div>
          </div>
        </div>
        <div className="relative z-10 sm:hidden " onClick={handleNav}>
          {nav ? (
            <AiOutlineClose size={25} className="text-white" />
          ) : (
            <AiOutlineMenu size={25} />
          )}
        </div>
        <div
          className={
            nav
              ? " absolute bottom-0 left-0 right-0 top-0 flex   h-screen w-full items-center justify-center border border-main bg-main text-4xl text-white  duration-300 ease-in sm:hidden"
              : "absolute bottom-0 left-[-100%] right-0 top-0 flex   h-screen w-full items-center justify-center border border-main bg-main text-4xl text-white  duration-300 ease-in sm:hidden"
          }
        >
          <div className=" flex h-full w-full flex-col justify-around p-6 py-10 font-medium">
            <div className="">
              {/* <div className="text-xl font-bold ">Menu</div> */}
              <ul className="relative mt-5 flex flex-col gap-6 text-4xl font-semibold ">
                {["Home", "Services", "About", "Contact"].map((item) => (
                  <li key={item}>
                    <Link
                      onClick={handleNav}
                      href={
                        item.toLowerCase() === "home"
                          ? `./`
                          : `/${item.toLowerCase().split(" ").join("-")}`
                      }
                      className="under font-semibold text-white decoration-main decoration-2  duration-150 ease-in-out hover:underline "
                      aria-current="page"
                    >
                      {item}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </nav>
    </>
  );
};

export default NavbarState;