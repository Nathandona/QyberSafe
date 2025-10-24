import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
import { SessionProvider } from "@/components/providers/session-provider";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "QyberSafe - Enterprise-Grade Cybersecurity for Everyone",
  description: "Protect your digital life with military-grade security. Real-time threat protection, encryption, and comprehensive cybersecurity solutions for individuals and businesses.",
  keywords: ["cybersecurity", "security", "encryption", "malware protection", "VPN", "password manager", "online security"],
  authors: [{ name: "QyberSafe Team" }],
  creator: "QyberSafe",
  publisher: "QyberSafe",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth" suppressHydrationWarning>
      <body
        className={`${inter.variable} font-sans antialiased`}
      >
        <SessionProvider>
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            disableTransitionOnChange
          >
            {/* Hero gradient background wrapper */}
            <div className="min-h-screen relative">
              {/* Background */}
              <div className="fixed inset-0 bg-gradient-to-br from-background via-background to-muted"></div>

              {/* Subtle Grid Pattern */}
              <div
                className="fixed inset-0 opacity-20"
                style={{
                  backgroundImage: `
                    linear-gradient(to right, var(--border) 1px, transparent 1px),
                    linear-gradient(to bottom, var(--border) 1px, transparent 1px)
                  `,
                  backgroundSize: '60px 60px'
                }}
              ></div>

              {/* Floating Orb Elements */}
              <div className="fixed top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl animate-pulse"></div>
              <div className="fixed bottom-1/4 right-1/4 w-80 h-80 bg-secondary/5 rounded-full blur-3xl animate-pulse delay-1000"></div>
              <div className="fixed top-1/2 right-1/3 w-64 h-64 bg-accent/5 rounded-full blur-2xl animate-pulse delay-2000"></div>

              {/* Content */}
              <div className="relative z-10">
                {children}
              </div>
            </div>
          </ThemeProvider>
        </SessionProvider>
      </body>
    </html>
  );
}
