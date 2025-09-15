import { NextResponse } from 'next/server';
import { readFileSync } from 'fs';
import { join } from 'path';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET(request: Request) {
  try {
    const filePath = join(process.cwd(), 'components', 'Content', 'subDomainUrlContent.json');
    const fileData = readFileSync(filePath, 'utf-8');
    const subdomainsObject = JSON.parse(fileData);

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayStr = today.toISOString().split('T')[0];

    // Convert object to array and apply date filter
    const subdomainsArray = Object.keys(subdomainsObject).map((key) => {
      const item = subdomainsObject[key] || {};
      // Ensure slug present
      if (!item.slug) {
        item.slug = key;
      }
      return item;
    });

    const filteredSubdomains = subdomainsArray
      .filter((entry: any) => {
        if (!entry || !entry.publishedAt) {
          // No publish date -> show by default
          return true;
        }
        const publishDate = new Date(entry.publishedAt);
        publishDate.setHours(0, 0, 0, 0);
        return publishDate <= today;
      })
      .sort((a: any, b: any) => {
        const aDate = a?.publishedAt ? new Date(a.publishedAt).getTime() : 0;
        const bDate = b?.publishedAt ? new Date(b.publishedAt).getTime() : 0;
        return bDate - aDate;
      });

    if (filteredSubdomains.length === 0) {
      return NextResponse.json(
        { message: 'No published subdomains found for the current date', currentDate: todayStr },
        {
          status: 404,
          headers: {
            'Cache-Control': 'no-store, must-revalidate',
            'Pragma': 'no-cache',
          }
        }
      );
    }

    return new NextResponse(JSON.stringify({
      subdomains: filteredSubdomains,
      currentDate: todayStr,
      totalSubdomains: filteredSubdomains.length,
    }), {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      }
    });
  } catch (error) {
    console.error('Error in subdomains route:', error);
    return NextResponse.json(
      { message: 'Error reading subdomains', error: String(error) },
      {
        status: 500,
        headers: {
          'Cache-Control': 'no-store, must-revalidate',
          'Pragma': 'no-cache',
        }
      }
    );
  }
}


