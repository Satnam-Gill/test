// app/robots.ts
import type { MetadataRoute } from "next";
import { headers } from "next/headers";
import subdomainMap from "@/components/Content/subDomainUrlContent.json"; // keys = allowed subdomains

export const dynamic = "force-dynamic";

export default function robots(): MetadataRoute.Robots {
  const h = headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");

  const [hostnameNoPort, port] = host.split(":");
  const firstLabel = hostnameNoPort.split(".")[0];
  const allowed = Object.keys(subdomainMap);
  const onSubdomain = allowed.includes(firstLabel);

  const makeUrl = (h: string) => `${proto}://${h}${port ? `:${port}` : ""}`;

  if (onSubdomain) {
    // Robots for subdomain (e.g., alameda-ca.example.com)
    // Dynamically block the mirrored path on this subdomain: /<subdomain>/ and /<subdomain>
    const origin = makeUrl(hostnameNoPort);
    const mirroredPathBlocks = [`/${firstLabel}/`, `/${firstLabel}`];

    return {
      rules: [
        {
          userAgent: "*",
          allow: "/",
          disallow: ["/_next/", "/static/", "/*?*", ...mirroredPathBlocks],
        },
      ],
      sitemap: `${origin}/sitemap.xml`,
      host: host,
    };
  }

  // Robots for main domain (www or apex)
  const rootNoWww = hostnameNoPort.replace(/^www\./, "");
  const subSitemaps = allowed.map((sd) => `${makeUrl(`${sd}.${rootNoWww}`)}/sitemap.xml`);

  const origin = makeUrl(hostnameNoPort);
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // Block state-prefixed mirrors to avoid dupes on the main host
        disallow: ["/_next/", "/static/", ...allowed.map((sd) => `/${sd}/`)],
      },
    ],
    // Point to main site’s sitemap AND every subdomain’s sitemap
    sitemap: `${origin}/sitemap.xml`,
    host: host,
  };
}
