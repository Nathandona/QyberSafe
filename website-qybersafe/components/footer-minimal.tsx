"use client";

import { Shield, Mail, Twitter, Github, Linkedin } from "lucide-react";
import { motion } from "framer-motion";

const footerLinks = {
  product: {
    title: "Product",
    links: [
      { name: "Features", href: "#features" },
      { name: "Pricing", href: "#pricing" },
      { name: "Security", href: "#" }
    ]
  },
  company: {
    title: "Company",
    links: [
      { name: "About", href: "#" },
      { name: "Blog", href: "#" },
      { name: "Careers", href: "#" }
    ]
  },
  resources: {
    title: "Resources",
    links: [
      { name: "Documentation", href: "#" },
      { name: "Help Center", href: "#" },
      { name: "API", href: "#" }
    ]
  },
  legal: {
    title: "Legal",
    links: [
      { name: "Privacy", href: "#" },
      { name: "Terms", href: "#" },
      { name: "Security", href: "#" }
    ]
  }
};

const socialLinks = [
  { icon: Twitter, href: "#" },
  { icon: Github, href: "#" },
  { icon: Linkedin, href: "#" }
];

export default function FooterMinimal() {
  return (
    <footer className="relative border-t">
      <div className="max-w-6xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-8">
          {/* Brand Column */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="lg:col-span-2"
          >
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-8 h-8 bg-foreground rounded-sm flex items-center justify-center hover:scale-105 transition-transform duration-200">
                <Shield className="h-5 w-5 text-background" />
              </div>
              <span className="text-lg font-medium text-foreground">QyberSafe</span>
            </div>
            <p className="text-sm text-muted-foreground mb-6 leading-relaxed max-w-sm">
              Enterprise-grade cybersecurity solutions that protect millions of users worldwide.
            </p>

            {/* Contact Info */}
            <div className="space-y-2 mb-6">
              <div className="flex items-center text-sm text-muted-foreground">
                <Mail className="h-4 w-4 mr-2" />
                <span>support@qybersafe.com</span>
              </div>
            </div>

            {/* Social Links */}
            <div className="flex space-x-4">
              {socialLinks.map((social, index) => (
                <a
                  key={index}
                  href={social.href}
                  className="w-8 h-8 bg-muted rounded-sm flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted-foreground/10 transition-colors duration-200"
                >
                  <social.icon className="h-4 w-4" />
                </a>
              ))}
            </div>
          </motion.div>

          {/* Links Columns */}
          {Object.entries(footerLinks).map(([key, section], sectionIndex) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: sectionIndex * 0.1 }}
              viewport={{ once: true }}
              className="lg:col-span-1"
            >
              <h3 className="font-medium text-foreground mb-4 text-sm">
                {section.title}
              </h3>
              <ul className="space-y-2">
                {section.links.map((link, index) => (
                  <li key={index}>
                    <a
                      href={link.href}
                      className="text-sm text-muted-foreground hover:text-foreground transition-colors duration-200"
                    >
                      {link.name}
                    </a>
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>

        {/* Bottom Bar */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          viewport={{ once: true }}
          className="mt-12 pt-8 border-t"
        >
          <div className="flex flex-col md:flex-row items-center justify-between text-sm text-muted-foreground">
            <div className="mb-4 md:mb-0">
              © 2024 QyberSafe. All rights reserved.
            </div>
            <div className="flex items-center space-x-4 text-xs">
              <div className="flex items-center">
                <span>SSL Secured</span>
              </div>
              <div className="flex items-center">
                <span>SOC 2 Certified</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </footer>
  );
}