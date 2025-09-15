/** @type {import('next').NextConfig} */
const nextConfig = {
    trailingSlash: true,
    images: {
      remotePatterns: [
        {
          protocol: 'https',
          hostname: 'ik.imagekit.io',
          pathname: '**',
        },
      ]
    }
  }
  
  module.exports = nextConfig
  