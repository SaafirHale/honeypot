import type { NextConfig } from "next";

/**
 * Static export. NEXT_PUBLIC_BASE_PATH lets the same build mount under a
 * sub-path (e.g. "/honeypot" on saafirhale.com) without code changes.
 */
const basePath = process.env.NEXT_PUBLIC_BASE_PATH || "";

const nextConfig: NextConfig = {
  output: "export",
  basePath: basePath || undefined,
  images: { unoptimized: true },
  poweredByHeader: false,
  reactStrictMode: true,
};

export default nextConfig;
