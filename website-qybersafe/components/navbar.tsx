"use client";

import { useState } from "react";
import { Shield, Menu, X, User, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ModeToggle } from "./mode-toggle";
import { motion, AnimatePresence } from "framer-motion";
import { useSession, signOut } from "next-auth/react";
import Link from "next/link";

export default function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const { data: session, status } = useSession();

  const handleSignOut = () => {
    signOut({ callbackUrl: "/" });
  };

  return (
    <motion.nav
      initial={{ y: -10, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="relative z-10 w-full px-6 py-6 md:py-8"
    >
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="flex items-center space-x-3"
        >
          <Link href="/" className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-foreground rounded-sm flex items-center justify-center hover:scale-105 transition-transform duration-200">
              <Shield className="h-5 w-5 text-background" />
            </div>
            <span className="text-lg font-medium text-foreground">QyberSafe</span>
          </Link>
        </motion.div>

        {/* Desktop Navigation */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="hidden md:flex items-center space-x-8"
        >
          {status === "authenticated" ? (
            <>
              <Link href="/dashboard" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Dashboard
              </Link>
              <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                <User className="h-4 w-4" />
                <span>{session.user?.email}</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleSignOut}
                className="text-sm text-foreground hover:bg-muted flex items-center space-x-2"
              >
                <LogOut className="h-4 w-4" />
                <span>Sign Out</span>
              </Button>
            </>
          ) : (
            <>
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Features
              </a>
              <a href="#testimonials" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Testimonials
              </a>
              <a href="#pricing" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Pricing
              </a>
              <ModeToggle />
              <Link href="/auth/signin">
                <Button variant="ghost" className="text-sm text-foreground hover:bg-muted">
                  Sign In
                </Button>
              </Link>
              <Link href="/auth/signup">
                <Button className="text-sm bg-foreground text-background hover:bg-foreground/90 px-6">
                  Get Started
                </Button>
              </Link>
            </>
          )}
        </motion.div>

        {/* Mobile menu button */}
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="md:hidden"
          onClick={() => setIsMenuOpen(!isMenuOpen)}
        >
          {isMenuOpen ? (
            <X className="h-5 w-5 text-foreground" />
          ) : (
            <Menu className="h-5 w-5 text-foreground" />
          )}
        </motion.button>
      </div>

      {/* Mobile Navigation */}
      <AnimatePresence>
        {isMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
            className="md:hidden absolute top-full left-0 w-full bg-card border-b border"
          >
            <div className="flex flex-col p-6 space-y-4">
              {status === "authenticated" ? (
                <>
                  <Link href="/dashboard" className="text-sm text-muted-foreground hover:text-foreground">
                    Dashboard
                  </Link>
                  <div className="flex items-center justify-between text-sm text-muted-foreground">
                    <div className="flex items-center space-x-2">
                      <User className="h-4 w-4" />
                      <span>{session.user?.email}</span>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    className="text-sm justify-start"
                    onClick={handleSignOut}
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    Sign Out
                  </Button>
                </>
              ) : (
                <>
                  <a href="#features" className="text-sm text-muted-foreground hover:text-foreground">
                    Features
                  </a>
                  <a href="#testimonials" className="text-sm text-muted-foreground hover:text-foreground">
                    Testimonials
                  </a>
                  <a href="#pricing" className="text-sm text-muted-foreground hover:text-foreground">
                    Pricing
                  </a>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Theme</span>
                    <ModeToggle />
                  </div>
                  <Link href="/auth/signin">
                    <Button variant="ghost" className="text-sm justify-start">Sign In</Button>
                  </Link>
                  <Link href="/auth/signup">
                    <Button className="text-sm bg-foreground text-background justify-start">Get Started</Button>
                  </Link>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.nav>
  );
}