import Link from 'next/link'
import React from 'react'
import { MdOutlinePhoneCallback } from 'react-icons/md'
import ContactInfo from '@/components/Content/ContactInfo.json'

const WidgetPricingCards = () => {
  return (
    <div>
      <div className="relative z-10 mt-20 ">
          <div className="mx-4 text-center md:mx-20">
            <h2 className="mb-5  text-3xl font-bold">
              Star Dryer Vent Cleaning Services Pricing
            </h2>
            <p className="mb-10 ">
              Explore the ideal cleaning plan tailored to your specific needs
              with Star Dryer Vent Cleaning. Whether you&apos;re a homeowner,
              run a commercial establishment, or oversee mixed-use properties,
              we offer plans that deliver both value and efficiency. Enjoy the
              flexibility of no long-term contracts and the option to cancel
              anytime.
            </p>
          </div>
          <div className="mx-auto max-w-4xl px-10 md:flex md:px-0">
            <div className="mx-auto mb-3 w-full rounded-md bg-white px-8 py-8 shadow-lg shadow-gray-600 md:my-6 md:flex md:w-1/3 md:max-w-none md:flex-col md:px-10 md:py-10">
              <div className="w-full flex-grow">
                <h3 className="mb-4 text-center font-bold uppercase">
                  Residential Cleaning
                </h3>
                <p className="mb-5 text-center text-4xl font-bold">$99</p>
                <ul className="mb-8 px-5 text-sm">
                  <li className="mt-1">
                     For homes and
                    apartments.
                  </li>
                  <li className="mt-1">
                     Cleans vents
                    up to 15 feet.
                  </li>
                  <li className="mt-1">
                     Reduces fire
                    risk.
                  </li>
                  <li className="mt-1">
                     Improves
                    dryer efficiency.
                  </li>
                </ul>
              </div>
              <div className="w-full">
                <Link id='cta-id' href={`tel:${ContactInfo.tel}`}>
                  <button className="flex w-full items-center justify-center rounded-md bg-main px-10 py-2 font-bold text-white transition-colors duration-200 ease-in-out hover:scale-110">
                    <MdOutlinePhoneCallback className='text-2xl'/>
                    Call Now
                  </button>
                </Link>
              </div>
            </div>
            <div className="mx-auto mb-3 w-full rounded-md bg-white px-8 py-8 shadow-lg shadow-gray-600 md:relative md:z-50 md:-mx-3 md:mb-0 md:flex md:w-1/3 md:max-w-none md:flex-col md:px-10 md:py-10">
              <div className="w-full flex-grow">
                <h3 className="mb-4 text-center font-bold uppercase">
                  Commercial Cleaning
                </h3>
                <p className="mb-5 text-center text-4xl font-bold md:text-5xl">
                  $200
                </p>
                <ul className="mb-8 px-5 text-sm">
                  <li className="mt-1">
                    For
                    laundromats, hotels, and schools.
                  </li>
                  <li className="mt-1">
                    Tailored for
                    complex systems.
                  </li>
                  <li className="mt-1">
                     Ensures
                    safety compliance.
                  </li>
                  <li className="mt-1">
                     Extends dryer
                    lifespan.
                  </li>
                </ul>
              </div>
              <div className="w-full">
                <Link id='cta-id' href={`tel:${ContactInfo.tel}`}>
                  <button className="flex w-full items-center justify-center rounded-md bg-main px-10 py-2 font-bold text-white transition-colors duration-200 ease-in-out hover:scale-110">
                    <MdOutlinePhoneCallback className='text-2xl'/>
                    Call Now
                  </button>
                </Link>
              </div>
            </div>
            <div className="mx-auto mb-3 w-full rounded-md bg-white px-8 py-8 shadow-lg shadow-gray-600 md:my-6 md:flex md:w-1/3 md:max-w-none md:flex-col md:px-10 md:py-10">
              <div className="w-full flex-grow">
              <h3 className="mb-4 text-center font-bold uppercase">
              Mixed Use   Cleaning
                </h3>
                <p className="mb-5 text-center text-3xl font-bold">
                  $250 - $500
                </p>
                <ul className="mb-8 px-5 text-sm">
                  <li className="mt-1">
                     For property
                    managers.
                  </li>
                  <li className="mt-1">
                     Flexible
                    scheduling.
                  </li>
                  <li className="mt-1">
                     Blends
                    residential and commercial services.
                  </li>
                  <li className="mt-1">
                     Offers volume
                    discounts.
                  </li>
                </ul>
              </div>
              <div className="w-full">
                <Link  href={`tel:${ContactInfo.tel}`}>
                  <button className="flex w-full items-center justify-center rounded-md bg-main px-10 py-2 font-bold text-white transition-colors duration-200 ease-in-out hover:scale-110">
                    <MdOutlinePhoneCallback className='text-2xl'/>
                    Call Now
                  </button>
                </Link>
              </div>
            </div>
          </div>
        </div>
    </div>
  )
}

export default WidgetPricingCards