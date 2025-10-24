"use client";

import { Star } from "lucide-react";
import { motion } from "framer-motion";

const testimonials = [
  {
    name: "Sarah Chen",
    role: "CEO, TechStart",
    content: "QyberSafe has transformed our security infrastructure. Comprehensive protection and real-time monitoring have prevented multiple potential breaches.",
    rating: 5
  },
  {
    name: "Marcus Rodriguez",
    role: "Developer",
    content: "Enterprise-grade security without the enterprise price. The encryption features and secure backup are game-changers for my freelance work.",
    rating: 5
  },
  {
    name: "Emily Thompson",
    role: "Small Business Owner",
    content: "User-friendly interface with powerful security features. 95% reduction in security incidents since switching. Highly recommended!",
    rating: 5
  },
  {
    name: "David Park",
    role: "IT Director",
    content: "Stood out for comprehensive features and reliability. Vulnerability scanning alone has saved countless hours and prevented disasters.",
    rating: 5
  },
  {
    name: "Lisa Martinez",
    role: "Privacy Advocate",
    content: "Password management and encryption features are outstanding. Finally confident that my digital communications are truly private.",
    rating: 5
  },
  {
    name: "James Wilson",
    role: "Startup Founder",
    content: "QyberSafe gave us peace of mind from day one. Mobile security features are especially crucial for our remote team.",
    rating: 5
  }
];

const stats = [
  { number: "2M+", label: "Users Protected" },
  { number: "99.9%", label: "Uptime" },
  { number: "24/7", label: "Monitoring" },
  { number: "50K+", label: "Daily Threats Blocked" }
];

export default function TestimonialsMinimal() {
  return (
    <section id="testimonials" className="py-24 relative">
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
            Trusted by Millions
            <br />
            Worldwide
          </h2>
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            viewport={{ once: true }}
            className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed"
          >
            Join thousands of satisfied users who have secured their digital lives with QyberSafe.
          </motion.p>
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-20">
          {stats.map((stat, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <div className="text-3xl font-bold text-foreground mb-2">
                {stat.number}
              </div>
              <div className="text-sm text-muted-foreground">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Testimonials Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {testimonials.map((testimonial, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="bg-card p-8 border hover:border-foreground/20 transition-colors duration-200 h-full hover:shadow-lg"
            >
              {/* Rating */}
              <div className="flex mb-4">
                {[...Array(testimonial.rating)].map((_, i) => (
                  <Star key={i} className="h-4 w-4 text-yellow-500 fill-current" />
                ))}
              </div>

              {/* Content */}
              <p className="text-muted-foreground mb-6 leading-relaxed">
                "{testimonial.content}"
              </p>

              {/* Author */}
              <div className="flex items-center">
                <div className="w-10 h-10 bg-foreground rounded-full flex items-center justify-center mr-3">
                  <span className="text-sm font-medium text-background">
                    {testimonial.name.split(' ').map(n => n[0]).join('')}
                  </span>
                </div>
                <div>
                  <div className="font-medium text-foreground text-sm">
                    {testimonial.name}
                  </div>
                  <div className="text-xs text-muted-foreground/70">
                    {testimonial.role}
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}