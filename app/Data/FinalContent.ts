import rawSubdomainData from "@/components/Content/subDomainUrlContent.json";

// Adjust path if needed
export interface SubdomainNeedsItem {
  title: string;
  description: string;
}

export interface SubdomainProcessItem {
  title: string;
  description: string;
}

export interface SubdomainFaqItem {
  ques: string;
  ans: string;
}

export interface SubdomainDataItem {
  name: string;
  slug: string;
  metaTitle?: string;
  metaDescription?: string;
  bannerImage?: string;
  h1Banner?: string;
  h2?: string;
  p2?: string;
  h2Image?: string;
  serviceTtile?: string;
  needsSection?: {
    title: string;
    description?: string;
    needslist: SubdomainNeedsItem[];
  };
  processSection?: {
    title: string;
    processData: SubdomainProcessItem[];
  };
  h5?: string;
  p5?: string;
  h5Image?: string;
  faq?: SubdomainFaqItem[];
  reviews?: { Review?: string }[];
  neighbourhoods?: string;
  zipCodes?: string;
  address?: string;
}

export type SubdomainDataMap = Record<string, SubdomainDataItem>;

const sanitizeSubdomain = (data: any): SubdomainDataItem => ({
  name: data?.name || "",
  slug: data?.slug || "",
  metaTitle: data?.metaTitle || "",
  metaDescription: data?.metaDescription || "",
  bannerImage: data?.bannerImage || "",
  h1Banner: data?.h1Banner || "",
  h2: data?.h2 || "",
  p2: data?.p2 || "",
  h2Image: data?.h2Image || "",
  serviceTtile: data?.serviceTtile || "",
  needsSection: {
    title: data?.needsSection?.title || "",
    description: data?.needsSection?.description || "",
    needslist: Array.isArray(data?.needsSection?.needslist)
      ? data.needsSection.needslist.map(
          (item: any): SubdomainNeedsItem => ({
            title: item?.title || "",
            description: item?.description || "",
          }),
        )
      : [],
  },
  processSection: {
    title: data?.processSection?.title || "",
    processData: Array.isArray(data?.processSection?.processData)
      ? data.processSection.processData.map(
          (item: any): SubdomainProcessItem => ({
            title: item?.title || "",
            description: item?.description || "",
          }),
        )
      : [],
  },
  h5: data?.h5 || "",
  p5: data?.p5 || "",
  h5Image: data?.h5Image || "",
  faq: Array.isArray(data?.faq)
    ? data.faq.map(
        (item: any): SubdomainFaqItem => ({
          ques: item?.ques || "",
          ans: item?.ans || "",
        }),
      )
    : [],
  reviews: Array.isArray(data?.reviews) ? data.reviews : [],
  neighbourhoods: data?.neighbourhoods || "",
  zipCodes: data?.zipCodes || "",
  address: data?.address || "",
});

// Transform and sanitize every entry
const subdomainData: SubdomainDataMap = Object.entries(
  rawSubdomainData || {},
).reduce((acc, [key, value]) => {
  acc[key] = sanitizeSubdomain(value) ;
  return acc;
}, {} as SubdomainDataMap);

const subdomainContent: {
  subdomainData: SubdomainDataMap;
} = {
  subdomainData,
};

export default subdomainContent;
