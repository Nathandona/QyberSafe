"use client";

import { Check, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";

const plans = [
  {
    name: "Starter",
    description: "Perfect for individuals",
    price: "$9",
    period: "/month",
    features: [
      "Up to 5 devices",
      "Real-time threat protection",
      "Basic VPN access",
      "Password manager",
      "Email support"
    ],
    notIncluded: [
      "Priority support",
      "Dark web monitoring"
    ],
    popular: false
  },
  {
    name: "Professional",
    description: "Ideal for businesses",
    price: "$29",
    period: "/month",
    features: [
      "Up to 25 devices",
      "Advanced threat protection",
      "Premium VPN unlimited",
      "Unlimited passwords",
      "Priority support",
      "Dark web monitoring",
      "Secure cloud backup"
    ],
    notIncluded: [
      "Dedicated account manager"
    ],
    popular: true
  },
  {
    name: "Enterprise",
    description: "For organizations",
    price: "Custom",
    period: "",
    features: [
      "Unlimited devices",
      "Enterprise protection",
      "Corporate VPN",
      "Enterprise management",
      "24/7 phone support",
      "Advanced monitoring",
      "Unlimited backup",
      "Compliance reporting",
      "Custom policies",
      "Dedicated manager"
    ],
    notIncluded: [],
    popular: false
  }
];

export default function PricingMinimal() {
  return (
    <section id="pricing" className="py-24 relative border-b">
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
            Simple, Transparent
            <br />
            Pricing
          </h2>
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            viewport={{ once: true }}
            className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed"
          >
            Choose the perfect plan for your needs. All plans include core security features
            with no hidden fees.
          </motion.p>
        </motion.div>

        {/* Pricing Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
          {plans.map((plan, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className={`relative h-full flex flex-col ${
                plan.popular
                  ? "bg-foreground text-background border-2 ring-2 ring-primary/20"
                  : "bg-card text-foreground border"
              } p-8 hover:border-primary/50 transition-all duration-200 hover:shadow-lg`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                  <div className="px-3 py-1 bg-primary text-primary-foreground rounded-full text-xs font-medium">
                    Most Popular
                  </div>
                </div>
              )}

              <div className="text-center mb-8">
                <div className="text-2xl font-bold mb-2">{plan.name}</div>
                <div className="text-sm opacity-70 mb-4">{plan.description}</div>
                <div className="text-4xl font-bold mb-1">
                  {plan.price}
                  <span className="text-lg font-normal opacity-70 ml-1">
                    {plan.period}
                  </span>
                </div>
              </div>

              <div className="flex-1 space-y-3 mb-8">
                {plan.features.map((feature, featureIndex) => (
                  <div key={featureIndex} className="flex items-center">
                    <Check className="h-4 w-4 mr-3 flex-shrink-0" />
                    <span className="text-sm">{feature}</span>
                  </div>
                ))}

                {plan.notIncluded.map((feature, featureIndex) => (
                  <div key={featureIndex} className="flex items-center opacity-40">
                    <X className="h-4 w-4 mr-3 flex-shrink-0" />
                    <span className="text-sm">{feature}</span>
                  </div>
                ))}
              </div>

              <div className="mt-auto">
                <Button
                  className={`w-full h-12 ${
                    plan.popular
                      ? "bg-background text-foreground hover:bg-muted"
                      : "bg-foreground text-background hover:bg-foreground/90"
                  }`}
                >
                  {plan.popular ? "Start Free Trial" : plan.price === "Custom" ? "Contact Sales" : "Get Started"}
                </Button>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Call to Action */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          viewport={{ once: true }}
          className="text-center"
        >
          <p className="text-muted-foreground mb-6">
            Need help choosing the right plan?
          </p>
          <Button variant="outline" className="border text-foreground hover:bg-muted">
            Contact Our Team
          </Button>
        </motion.div>
      </div>
    </section>
  );
}