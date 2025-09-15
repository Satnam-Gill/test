// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// --- Helpers ---
function getProtoAndHost(req: NextRequest) {
  const proto = (req.headers.get("x-forwarded-proto") || req.nextUrl.protocol.replace(":", "") || "http").toLowerCase();
  const host  = (req.headers.get("host") || req.nextUrl.host || "").toLowerCase();
  return { proto, host };
}

/**
 * For Vercel:
 *   - Base host = last 3 labels (e.g., test-mauve-nu-11.vercel.app)
 *   - Subdomain exists only if there is an extra label before those 3
 * For custom domains:
 *   - Heuristic: base = last 2 labels (example.com); subdomain is any extra left label
 */
function splitHost(host: string) {
  const parts = host.split(":")[0].split(".").filter(Boolean);
  const isVercel = host.endsWith(".vercel.app");

  if (isVercel) {
    const baseParts = parts.slice(-3);                  // e.g., ["test-mauve-nu-11","vercel","app"]
    const leftParts = parts.slice(0, -3);               // e.g., ["fort-mcdowell-az"]
    const baseHost  = baseParts.join(".");
    const subdomain = leftParts.length > 0 ? leftParts.join(".") : ""; // allow nested like a.b.test-*.vercel.app
    return { isVercel: true, baseHost, subdomain };
  }

  // localhost-style (foo.localhost)
  if (host.endsWith(".localhost")) {
    const baseParts = parts.slice(-2);                  // ["localhost"]
    const leftParts = parts.slice(0, -2);
    const baseHost  = baseParts.join(".");
    const subdomain = leftParts.length > 0 ? leftParts.join(".") : "";
    return { isVercel: false, baseHost, subdomain };
  }

  // nip.io / sslip.io (foo.127.0.0.1.nip.io)
  if (host.endsWith(".nip.io") || host.endsWith(".sslip.io")) {
    const baseParts = parts.slice(-3);                  // ["nip","io"] + IP block before -> keep 3 for safety
    const leftParts = parts.slice(0, -3);
    const baseHost  = baseParts.join(".");
    const subdomain = leftParts.length > 0 ? leftParts.join(".") : "";
    return { isVercel: false, baseHost, subdomain };
  }

  // Generic custom domain (heuristic): example.com as base; foo.example.com => subdomain=foo
  const baseParts = parts.slice(-2);
  const leftParts = parts.slice(0, -2);
  const baseHost  = baseParts.join(".");
  const subdomain = leftParts.length > 0 ? leftParts.join(".") : "";
  return { isVercel: false, baseHost, subdomain };
}

async function getSubdomainData(request: NextRequest) {
  try {
    const { proto, host } = getProtoAndHost(request);
    const { baseHost } = splitHost(host);
    const baseUrl = `${proto}://${baseHost}`;

    const res = await fetch(`${baseUrl}/api/subdomains`, { cache: "no-store" });
    const data = await res.json();

    if (data?.subdomains) {
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
  const { host } = getProtoAndHost(request);
  const { subdomain } = splitHost(host); // << now supports fort-mcdowell-az.test-mauve-nu-11.vercel.app

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
    pass.headers.set("x-subdomain", subdomain || "");
    return pass;
  }

  // Fetch allowed subdomains (kept)
  const subdomainMap = await getSubdomainData(request);
  const allowedSubs = Object.keys(subdomainMap);

  // If no subdomain or not allowed (or "www"), proceed normally (kept)
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
