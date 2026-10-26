import type { Metadata } from "next";
import { Archivo, Geist_Mono } from "next/font/google";
import "./globals.css";

const archivo = Archivo({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-archivo",
  display: "swap",
});

const geistMono = Geist_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-geist-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Honeypot · Saafir Hale",
  description:
    "Live statistics from a Cowrie SSH/Telnet honeypot: where attacks come from, what credentials bots guess, and what they run.",
  robots: { index: true, follow: false },
};

// Same bootstrap and storage key as saafirhale.com: dark by default, no flash.
const themeBootstrap = `(function(){try{var t=localStorage.getItem('sh-theme')||'dark';document.documentElement.setAttribute('data-theme',t)}catch(e){document.documentElement.setAttribute('data-theme','dark')}})()`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className={`${archivo.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
