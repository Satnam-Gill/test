import Hero from "./components/Home/Hero";
import contactContent from "@/app/Data/content";

const ContactInfo: any = contactContent.contactContent;
const homeData: any = contactContent.homePageContent;

export async function generateMetadata() {
  return {
    title: homeData.metaTitle,
    description: `${homeData?.metaDescription
      ?.split("[location]")
      .join(ContactInfo.location)
      ?.split("[phone]")
      .join(ContactInfo.No)}.`,
    alternates: {
      canonical: `https://${ContactInfo.host}`,
    },
  };
}

export default function Home() {
  const newData = JSON.parse(
    JSON.stringify(homeData)
      .split("[location]")
      .join(ContactInfo.location)
      .split("[phone]")
      .join(ContactInfo.No),
  );
  return (
    <div className="">
      <Hero />
    </div>
  );
}
