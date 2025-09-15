// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// --- Helpers ---
function extractSubdomain(hostname: string): string {
  // strip port if present
  const host = (hostname || "").split(":")[0].toLowerCase();
  const parts = host.split(".");

  // No subdomain cases
  if (parts.length <= 1) return "";

  // Handle Vercel and similar multi-label dev hosts
  // example.vercel.app          -> "example"
  // foo.example.vercel.app      -> "foo"
  if (host.endsWith(".vercel.app")) {
    return parts.length >= 3 ? parts[0] : "";
  }

  // Handle localhost-style multi-tenant dev (foo.localhost)
  if (host.endsWith(".localhost")) {
    return parts.length >= 2 ? parts[0] : "";
  }

  // Handle nip.io / sslip.io style hosts (foo.127.0.0.1.nip.io)
  if (host.endsWith(".nip.io") || host.endsWith(".sslip.io")) {
    return parts.length >= 3 ? parts[0] : "";
  }

  // Generic custom domain:
  // foo.example.com -> "foo"
  // example.com     -> ""
  return parts.length >= 3 ? parts[0] : "";
}

async function getSubdomainData(request: NextRequest) {
  try {
    const proto = request.headers.get("x-forwarded-proto") ?? request.nextUrl.protocol.replace(":", "") ?? "http";
    const host  = request.headers.get("host") ?? request.nextUrl.host;
    const baseUrl = `${proto}://${host}`;

    const res = await fetch(`${baseUrl}/api/subdomains`, { cache: "no-store" });
    const data = await res.json();

    if (data && data.subdomains) {
      // Convert array to { [slug]: item }
      return data.subdomains.reduce((acc: Record<string, any>, item: any) => {
        if (item?.slug) acc[item.slug] = item;
        return acc;
      }, {});
    }
    return {};
  } catch {
    return {};
  }
}

// --- Middleware ---
export async function middleware(request: NextRequest) {
  const url = request.nextUrl.clone();
  const hostname = request.headers.get("host") || "";

  // Skip Next assets & common static files (kept)
  if (
    url.pathname.startsWith("/_next") ||
    url.pathname.startsWith("/static") ||
    /\.(jpg|jpeg|png|gif|svg|ico|webp|avif)$/i.test(url.pathname)
  ) {
    return NextResponse.next();
  }

  // Let root serve robots & sitemaps normally (kept)
  if (/^\/(robots\.txt|sitemap\.xml|blogs\/sitemap\.xml)$/.test(url.pathname)) {
    const pass = NextResponse.next();
    pass.headers.set("x-subdomain", extractSubdomain(hostname));
    return pass;
  }

  // Determine requested subdomain (now robust across dummy/prod/dev)
  const subdomain = extractSubdomain(hostname);

  // Fetch allowed / known subdomains (kept)
  const subdomainMap = await getSubdomainData(request);
  const allowedSubs = Object.keys(subdomainMap);

  // If not a known subdomain, proceed normally (kept)
  if (!subdomain || subdomain === "www" || !allowedSubs.includes(subdomain)) {
    return NextResponse.next();
  }

  // Rewrite to /:subdomain/* (kept)
  url.pathname = `/${subdomain}${url.pathname}`;

  const response = NextResponse.rewrite(url);
  response.headers.set("x-subdomain", subdomain);
  return response;
}

// --- Matcher (kept) ---
export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
