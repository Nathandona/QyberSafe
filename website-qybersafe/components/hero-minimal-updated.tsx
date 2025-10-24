"use client";

import { ArrowRight, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import Navbar from "./navbar";

export default function HeroMinimalUpdated() {
  return (
    <section className="min-h-screen flex flex-col relative">
      {/* Navigation */}
      <Navbar />

      {/* Hero Content */}
      <div className="relative z-10 flex-1 flex items-center justify-center px-6 pb-20">
        <div className="max-w-4xl w-full">
          <div className="text-center">
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="mb-8"
            >
              <div className="inline-flex items-center px-3 py-1 bg-muted rounded-full text-xs font-medium text-muted-foreground">
                <Shield className="h-3 w-3 mr-2" />
                Military-Grade Security
              </div>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, delay: 0.4 }}
              className="text-5xl md:text-7xl font-bold text-foreground mb-6 leading-tight tracking-tight"
            >
              Protect Your
              <br />
              Digital Life
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.6 }}
              className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed"
            >
              Enterprise-level cybersecurity designed for everyone. Real-time threat protection,
              military-grade encryption, and comprehensive security tools.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.8 }}
              className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
            >
              <Button className="text-base bg-foreground text-background hover:bg-foreground/90 px-8 py-3 h-12">
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
              <Button variant="outline" className="text-base border text-foreground hover:bg-muted px-8 py-3 h-12">
                Watch Demo
              </Button>
            </motion.div>

            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.6, delay: 1.0 }}
              className="flex items-center justify-center space-x-8 text-xs text-muted-foreground"
            >
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                No Credit Card Required
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-primary rounded-full mr-2"></div>
                14-Day Free Trial
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}