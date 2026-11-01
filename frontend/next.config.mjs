/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  webpack: (config, { dev }) => {
    if (dev) {
      // Disable persistent disk pack file cache in dev to prevent ENOENT rename races and stale chunk 404s
      config.cache = false;
    }
    return config;
  },
};

export default nextConfig;
