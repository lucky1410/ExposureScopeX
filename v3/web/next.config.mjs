/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        // The web and API services share the Docker `edge` network. This is
        // server-side only: browsers always request the current application origin.
        destination: "http://api:8000/api/:path*",
      },
    ];
  },
};

export default nextConfig;
