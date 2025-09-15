import Image from 'next/image'
import Link from 'next/link'
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;

 
export default function NotFound() {
  return (
    <div>
       <div className="flex h-[90vh] flex-col items-center justify-center gap-2 text-3xl dark:text-black">
          <Image src="https://ik.imagekit.io/h7rza8886p/WhatsApp%20Image%202025-06-13%20at%2012.49.09%20PM.jpeg?updatedAt=1749799411826" alt="error" width={300} height={300} />
          {} Page not found
          <button
            className={`bg-main  px-6 py-1 text-white`}
          >
            <Link href={ContactInfo?.baseUrl}>Back to home</Link>
          </button>
        </div>
    </div>
  )
}