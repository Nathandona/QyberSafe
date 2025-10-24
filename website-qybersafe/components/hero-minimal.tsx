"use client";

import { useState } from "react";
import { Shield, ArrowRight, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ModeToggle } from "./mode-toggle";

export default function HeroMinimal() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <section className="min-h-screen flex flex-col relative overflow-hidden">
      {/* Enhanced Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-background via-background to-muted dark:from-background dark:via-background dark:to-muted"></div>

      {/* Subtle Grid Pattern */}
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage: `
            linear-gradient(to right, var(--border) 1px, transparent 1px),
            linear-gradient(to bottom, var(--border) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px'
        }}
      ></div>

      {/* Gradient Overlay for Depth */}
      <div className="absolute inset-0 bg-gradient-to-t from-transparent via-transparent to-background/20"></div>

      {/* Floating Orb Elements */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl animate-pulse"></div>
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-secondary/5 rounded-full blur-3xl animate-pulse delay-1000"></div>
      <div className="absolute top-1/2 right-1/3 w-64 h-64 bg-accent/5 rounded-full blur-2xl animate-pulse delay-2000"></div>
      {/* Navigation */}
      <nav className="relative z-10 w-full px-6 py-6 md:py-8">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-foreground rounded-sm flex items-center justify-center">
              <Shield className="h-5 w-5 text-background" />
            </div>
            <span className="text-lg font-medium text-foreground">QyberSafe</span>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
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
            <Button variant="ghost" className="text-sm text-foreground hover:bg-muted">
              Sign In
            </Button>
            <Button className="text-sm bg-foreground text-background hover:bg-foreground/90 px-6">
              Get Started
            </Button>
          </div>

          {/* Mobile menu button */}
          <button
            className="md:hidden"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
          >
            {isMenuOpen ? (
              <X className="h-5 w-5 text-black dark:text-white" />
            ) : (
              <Menu className="h-5 w-5 text-black dark:text-white" />
            )}
          </button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden absolute top-full left-0 w-full bg-card border-b border">
            <div className="flex flex-col p-6 space-y-4">
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground">
                Features
              </a>
              <a href="#testimonials" className="text-sm text-muted-foreground hover:text-foreground">
                Testimonials
              </a>
              <a href="#pricing" className="text-sm text-muted-foreground hover:text-foreground">
                Pricing
              </a>
              <ModeToggle />
              <Button variant="ghost" className="text-sm justify-start">Sign In</Button>
              <Button className="text-sm bg-foreground text-background">Get Started</Button>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Content */}
      <div className="relative z-10 flex-1 flex items-center justify-center px-6 pb-20">
        <div className="max-w-4xl w-full">
          <div className="text-center">
            <div className="mb-8">
              <div className="inline-flex items-center px-3 py-1 bg-[#f5f5f5] dark:bg-[#1a1a1a] rounded-full text-xs font-medium text-[#666666] dark:text-[#888888]">
                <Shield className="h-3 w-3 mr-2" />
                Military-Grade Security
              </div>
            </div>

            <h1 className="text-5xl md:text-7xl font-bold text-black dark:text-white mb-6 leading-tight tracking-tight">
              Protect Your
              <br />
              Digital Life
            </h1>

            <p className="text-lg md:text-xl text-[#666666] dark:text-[#888888] mb-10 max-w-2xl mx-auto leading-relaxed">
              Enterprise-level cybersecurity designed for everyone. Real-time threat protection,
              military-grade encryption, and comprehensive security tools.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
              <Button className="text-base bg-black dark:bg-white text-white dark:text-black hover:bg-[#333333] dark:hover:bg-[#cccccc] px-8 py-3 h-12">
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
              <Button variant="outline" className="text-base border-[#e5e5e5] dark:border-[#333333] text-black dark:text-white hover:bg-[#f5f5f5] dark:hover:bg-[#1a1a1a] px-8 py-3 h-12">
                Watch Demo
              </Button>
            </div>

            <div className="flex items-center justify-center space-x-8 text-xs text-[#999999] dark:text-[#666666]">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                No Credit Card Required
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
                14-Day Free Trial
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}