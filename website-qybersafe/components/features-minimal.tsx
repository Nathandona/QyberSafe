"use client";

import { Shield, Lock, Eye, Zap, Globe, Smartphone } from "lucide-react";
import { motion } from "framer-motion";

const features = [
  {
    icon: Shield,
    title: "Advanced Protection",
    description: "Real-time defense against modern cyber threats using AI-powered detection systems."
  },
  {
    icon: Lock,
    title: "Military Encryption",
    description: "End-to-end AES-256 encryption ensuring complete privacy and security for all your data."
  },
  {
    icon: Eye,
    title: "24/7 Monitoring",
    description: "Continuous security monitoring with instant alerts and rapid incident response capabilities."
  },
  {
    icon: Zap,
    title: "Lightning Fast",
    description: "Optimized security protocols that provide maximum protection without slowing you down."
  },
  {
    icon: Globe,
    title: "Global Coverage",
    description: "Secure your internet connection worldwide with our distributed security infrastructure."
  },
  {
    icon: Smartphone,
    title: "Mobile Security",
    description: "Comprehensive protection for all your devices with advanced anti-theft features."
  }
];

export default function FeaturesMinimal() {
  return (
    <section id="features" className="py-24 relative">
      <div className="max-w-6xl mx-auto px-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-20"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-foreground mb-6 tracking-tight">
            Everything You Need for
            <br />
            Complete Security
          </h2>
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            viewport={{ once: true }}
            className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed"
          >
            Our comprehensive security suite provides enterprise-grade protection
            for your digital life.
          </motion.p>
        </motion.div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-12">
          {features.map((feature, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="group h-full"
            >
              <div className="mb-6">
                <div className="w-12 h-12 bg-foreground rounded-lg flex items-center justify-center mb-4 group-hover:scale-105 transition-transform duration-200">
                  <feature.icon className="h-6 w-6 text-background" />
                </div>
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-3">
                {feature.title}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {feature.description}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}